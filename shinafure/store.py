"""A registry that survives restarts: the same Registry, written through to SQLite.

    reg = PersistentRegistry("registry.db")     # creates or reopens

Every change is written in the same call that makes it, inside one
transaction, so a crash loses at most the call in flight. Kept in memory
only: OPRF rate-limit counters and pending ownership challenges (a restart
resets the counters and the registrant asks for a new challenge).

The OPRF key k
  is the registry's most important secret: with it and the database, the
  F values of guessable tokens (names, addresses) can be tested. Pass it in
  (key_hex, or SHINAFURE_REGISTRY_KEY) to keep it out of the database file;
  otherwise it is generated once and stored in the database, which must then
  be protected like a private key (the file is created with mode 600).
  Changing k makes every registered F useless.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from typing import Optional

from . import ec, group
from .issuance import Ticket
from .registry import Registry, Report

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS entries(f BLOB, registrant TEXT, canary_id TEXT, dataset TEXT, kind TEXT);
CREATE INDEX IF NOT EXISTS entries_f ON entries(f);
CREATE TABLE IF NOT EXISTS prefixes(p INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS escrows(f BLOB, canary_id TEXT, sealed BLOB, PRIMARY KEY(f, canary_id));
CREATE TABLE IF NOT EXISTS providers(api_key TEXT PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS domains(registrant TEXT, domain TEXT, PRIMARY KEY(registrant, domain));
CREATE TABLE IF NOT EXISTS blocks(registrant TEXT, block TEXT, PRIMARY KEY(registrant, block));
CREATE TABLE IF NOT EXISTS tickets(ticket_id TEXT PRIMARY KEY, registrant TEXT, dataset TEXT,
                                   commitment BLOB, nonce BLOB, tbl TEXT, issued_at REAL);
CREATE TABLE IF NOT EXISTS reports(registrant TEXT, canary_id TEXT, dataset TEXT, provider TEXT,
                                   kinds TEXT, status TEXT, at REAL, delivered INTEGER);
CREATE TABLE IF NOT EXISTS abuse(registrant TEXT, canary_id TEXT, why TEXT, at REAL);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, role TEXT, name TEXT, ref TEXT, webhook TEXT);
CREATE TABLE IF NOT EXISTS webhook_secrets(registrant TEXT PRIMARY KEY, secret TEXT);
CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, registrant TEXT, payload TEXT, attempts INTEGER, next_at REAL);
"""


class PersistentRegistry(Registry):
    def __init__(self, path: str, key_hex: Optional[str] = None, **kw) -> None:
        super().__init__(**kw)
        new = not os.path.exists(path)
        if new:
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        with self.db:
            self.db.executescript(SCHEMA)
        self._load_key(key_hex or os.environ.get("SHINAFURE_REGISTRY_KEY"))
        self._load()

    # ------------------------------------------------------------ load
    def _load_key(self, key_hex: Optional[str]) -> None:
        stored = self.db.execute("SELECT v FROM meta WHERE k='oprf_key'").fetchone()
        fp = self.db.execute("SELECT v FROM meta WHERE k='key_check'").fetchone()
        if key_hex:
            k = int(key_hex, 16)
        elif stored:
            k = int(stored[0], 16)
        else:
            k = self._k
            with self.db:
                self.db.execute("INSERT INTO meta VALUES('oprf_key', ?)", (format(k, "x"),))
        if not 0 < k < ec.N:
            raise ValueError("OPRF key out of range")
        check = group.backend.mul_x(k, group.backend.hash_x(b"shinafure-key-check", b"")).hex()
        if fp and fp[0] != check:
            raise ValueError("this OPRF key does not match the one the database was built with")
        if not fp:
            with self.db:
                self.db.execute("INSERT INTO meta VALUES('key_check', ?)", (check,))
        self._k, self._kkey = k, group.backend.key(k)

    def _load(self) -> None:
        q = self.db.execute
        for f, r, c, ds, kind in q("SELECT f, registrant, canary_id, dataset, kind FROM entries ORDER BY rowid"):
            self._entries[f].append((r, c, ds, kind))
            self._by_canary[c].append(f)
        self._prefixes.update(p for (p,) in q("SELECT p FROM prefixes"))
        self._escrows.update({(f, c): s for f, c, s in q("SELECT f, canary_id, sealed FROM escrows")})
        self._providers.update(dict(q("SELECT api_key, name FROM providers")))
        for r, d in q("SELECT registrant, domain FROM domains"):
            self._domains[r].add(d)
        for r, b in q("SELECT registrant, block FROM blocks"):
            self._blocks[r].add(b)
        for tid, r, ds, cm, nonce, tbl, at in q("SELECT * FROM tickets ORDER BY issued_at"):
            self._tickets[tid] = Ticket(tid, r, ds, cm, nonce, tbl)
            self._ticket_times[r].append(at)
        for r, c, ds, p, kinds, st, at, dl in q("SELECT * FROM reports ORDER BY rowid"):
            self.reports.append(Report(r, c, ds, p, tuple(kinds.split(",")) if kinds else (), st, at, bool(dl)))
        self.abuse_log.extend(q("SELECT registrant, canary_id, why, at FROM abuse ORDER BY rowid").fetchall())

    # ----------------------------------------------- write-through ops
    def verify_domain(self, registrant, domain, resolve_txt):
        with self.lock:
            ok = super().verify_domain(registrant, domain, resolve_txt)
            if ok:
                with self.db:
                    self.db.execute("INSERT OR IGNORE INTO domains VALUES(?, ?)", (registrant, domain.strip().lower()))
            return ok

    def confirm_phone_block(self, registrant, challenge_id, code):
        with self.lock:
            before = set(self._blocks[registrant])
            ok = super().confirm_phone_block(registrant, challenge_id, code)
            if ok:
                with self.db:
                    for b in self._blocks[registrant] - before:
                        self.db.execute("INSERT OR IGNORE INTO blocks VALUES(?, ?)", (registrant, b))
            return ok

    def issue_ticket(self, registrant, dataset, commitment):
        with self.lock:
            t = super().issue_ticket(registrant, dataset, commitment)
            with self.db:
                self.db.execute("INSERT INTO tickets VALUES(?, ?, ?, ?, ?, ?, ?)",
                                (t.ticket_id, t.registrant, t.dataset, t.commitment, t.nonce, t.table,
                                 self._ticket_times[registrant][-1]))
            return t

    def register(self, registrant, f_values, webhook=None, escrows=None):
        rows = list(f_values)
        with self.lock:
            n = super().register(registrant, rows, webhook, escrows)     # validates; raises before any write
            with self.db:
                self.db.executemany("INSERT INTO entries VALUES(?, ?, ?, ?, ?)",
                                    [(f, registrant, c, ds, k) for f, _, c, ds, k in rows])
                self.db.executemany("INSERT OR IGNORE INTO prefixes VALUES(?)", [(p,) for _, p, *_ in rows])
                if self.require_tickets and escrows:
                    self.db.executemany("INSERT OR REPLACE INTO escrows VALUES(?, ?, ?)",
                                        [(f, c, escrows[(f, c)]) for f, _, c, _, _ in rows])
            return n

    def add_provider(self, name):
        with self.lock:
            key = super().add_provider(name)
            with self.db:
                self.db.execute("INSERT INTO providers VALUES(?, ?)", (key, name))
            return key

    def report(self, api_key, registrant, canary_id, dataset, kinds, status, keys=None):
        with self.lock:
            n_abuse = len(self.abuse_log)
            r = super().report(api_key, registrant, canary_id, dataset, kinds, status, keys)
            with self.db:
                self.db.execute("INSERT INTO reports VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                                (r.registrant, r.canary_id, r.dataset, r.provider, ",".join(r.kinds), r.status,
                                 r.at, int(r.delivered)))
                self.db.executemany("INSERT INTO abuse VALUES(?, ?, ?, ?)", self.abuse_log[n_abuse:])
            return r

    def close(self) -> None:
        self.db.close()
