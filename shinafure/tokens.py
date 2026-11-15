"""Normalization and candidate extraction.

A canary person is turned into several *tokens* (typed strings). Text that an
AI provider receives is turned into *candidates* the same way, so that a
canary survives the reformatting an attacker's pipeline typically applies
(CSV -> JSON, spacing, full/half width, +81 phone formats, romanization, ...).

Token types
  e:  email (lowercased)                         strong
  p:  phone, digits, Japanese domestic form       strong
  n:  full name in kanji / katakana / hiragana    weak (needs a partner)
  r:  romanized full name, order-insensitive      weak (needs a partner)
  a:  address, normalized                         weak (needs a partner)
  t:  last 8 digits of a phone-like number        weak (survives a dropped or mangled prefix)

Names split into two fields (v1.4): the text side also joins a surname field
and the next field (CSV, JSON, "姓：… 名：…" forms) into n: candidates, and
pairs capitalized latin words a few words apart into r: candidates.

Registry kinds (what a matched token counts as) add one more:
  m:  an *ordinary-looking* canary's name. Ordinary names collide with real
      people, so they only ever count together with a partner (a or t).
"""
from __future__ import annotations

import re
import unicodedata
from typing import Iterator

STRONG = {"e", "p", "k", "s"}      # email, phone, secret (API key), sentence
WEAK = {"n", "r", "m", "a", "t"}
NAME_KINDS = {"n", "r", "m"}
PARTNER_KINDS = {"a", "t"}

_EMAIL = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}")
_SEP = r"[\s\-.・()]{0,2}"
_PHONE = re.compile(r"(?<![\d])(?:\+81" + _SEP + r"(?:0" + _SEP + r")?|\(?0)\d{1,4}" + _SEP + r"\d{1,4}" + _SEP + r"\d{3,4}(?![\d])")
_PHONEISH = re.compile(r"(?<![\d])\+?\(?\d[\d\s\-.()・]{6,18}\d(?![\d])")
_CJK = "぀-ヿ㐀-鿿々ー"
_CJK_RUN = re.compile(f"[{_CJK}]+")
_SPACE_IN_CJK = re.compile(f"(?<=[{_CJK}])[\\s　]+(?=[{_CJK}])")
_LATIN_WORD = re.compile(r"[a-z]{2,20}")
# v1.4: a field followed by a record separator (CSV, TSV, JSON, "姓：…／名：…"
# forms), never by Japanese punctuation (、。「」), and then another field.
# Whitespace alone is not enough: fields split only by spaces or line breaks
# are already joined for the name windows (_SPACE_IN_CJK).
_GAP = r"(?=[\s\w\-]{0,39}+[,|;:/\"'=\[\]{}()<>])[\s,|;:/\"'=\[\]{}()<>A-Za-z0-9_\-]{1,40}+"
_FIELD = re.compile(f"(?<![{_CJK}])([{_CJK}]{{1,9}}+)(?![{_CJK}]){_GAP}(?=([{_CJK}]++))")
_LABEL_MAX = 4                        # 名, 名前, 下の名前: a label between the two fields
_HONORIFICS = ("様", "さま", "さん", "殿", "氏")
# romanized parts split by a key or two, as JSON ("last":"Takanashi","first":"Hakuto")
# or YAML (last: Takanashi\nfirst: Hakuto). Each pattern starts with a literal, so it is fast.
_KEYGAP = r"[\s\"',:;=|{}\[\]_\-]+"
_KEYGAP0 = _KEYGAP[:-1] + "*"
_CAP_SPLITS = tuple(re.compile(f"{q}([A-Z][a-z]{{1,19}})(?![A-Za-z])(?:{_KEYGAP}[a-z]{{2,20}}){{1,3}}{_KEYGAP0}{q}(?=([A-Z][a-z]{{1,19}})(?![A-Za-z]))")
                    for q in ('"', ": "))
_PREFS = ("北海道|東京都|大阪府|京都府|" + "|".join(p + "県" for p in (
    "青森 岩手 宮城 秋田 山形 福島 茨城 栃木 群馬 埼玉 千葉 神奈川 新潟 富山 石川 福井 山梨 長野 岐阜 静岡 愛知 "
    "三重 滋賀 兵庫 奈良 和歌山 鳥取 島根 岡山 広島 山口 徳島 香川 愛媛 高知 福岡 佐賀 長崎 熊本 大分 宮崎 鹿児島 沖縄").split()))
_ADDRESS = re.compile(f"(?:{_PREFS})[^\\s,、|\"'<>{{}}\\[\\]]{{2,30}}?\\d+(?:-\\d+){{1,2}}")

NAME_MIN, NAME_MAX = 3, 10

# secrets: one or more short words joined by - or _, then a long random part
_SECRET = re.compile(r"(?<![A-Za-z0-9_\-])(?:[A-Za-z][A-Za-z0-9]{1,15}[-_]){1,3}[A-Za-z0-9]{24,64}(?![A-Za-z0-9_\-])")
_SENT_END = re.compile(r"[。．！？!?\n:：]+")          # colons too: "議事録：<sentence>"
_LIST_MARK = re.compile(r"^(?:[\-*#>•]+|\d{1,3}[.)）])+")
_SENT_NOISE = re.compile(r"[\s　、，,「」『』（）()・\"'“”‘’:：;；]+")
SENT_MIN, SENT_MAX = 12, 200


def norm_sentence(s: str) -> str:
    """A sentence without spaces and inner punctuation, so that reflowing,
    commas or quotes do not change it."""
    s = _SENT_NOISE.sub("", nfkc(s)).strip("。．.!！?？")
    return _LIST_MARK.sub("", s)                     # "- ", "1.", "*", "#" at the start of a line


def nfkc(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


def to_katakana(s: str) -> str:
    return "".join(chr(ord(c) + 0x60) if "ぁ" <= c <= "ゖ" else c for c in s)


def to_hiragana(s: str) -> str:
    return "".join(chr(ord(c) - 0x60) if "ァ" <= c <= "ヶ" else c for c in s)


def norm_phone(raw: str) -> str | None:
    d = re.sub(r"\D", "", nfkc(raw))
    if d.startswith("81") and nfkc(raw).lstrip().startswith("+"):
        d = "0" + d[2:].lstrip("0")
    return d if 10 <= len(d) <= 11 and d.startswith("0") else None


def norm_address(raw: str) -> str:
    s = nfkc(raw)
    s = re.sub(r"[\s　]", "", s)
    s = re.sub(r"(\d+)丁目", r"\1-", s)
    s = re.sub(r"(\d+)番地?", r"\1-", s)
    s = re.sub(r"(\d+)号", r"\1", s)
    s = re.sub(r"-+", "-", s).rstrip("-")
    m = re.match(r"^(.*?\d+(?:-\d+){1,2})", s)  # cut building names / room numbers
    return m.group(1) if m else s


def phone_tail(raw: str) -> str | None:
    d = re.sub(r"\D", "", nfkc(raw))
    return d[-8:] if 9 <= len(d) <= 13 else None


def romaji_key(a: str, b: str) -> str:
    return "r:" + "|".join(sorted((a.lower(), b.lower())))


# ------------------------------------------------------------- canary side
def person_tokens(p: dict) -> set[str]:
    """Tokens for one canary person. Expects keys: last, first (kanji),
    last_kana, first_kana (katakana), last_roma, first_roma, email, phone, address."""
    if p.get("style") == "secret":
        return {"k:" + p["secret"]}
    if p.get("style") == "sentence":
        return {"s:" + norm_sentence(p["sentence"])}
    toks = {"e:" + p["email"].lower()}
    ph = norm_phone(p["phone"])
    if ph:
        toks.add("p:" + ph)
    tail = phone_tail(p["phone"])
    if tail:
        toks.add("t:" + tail)
    kanji = nfkc(p["last"] + p["first"])
    kana = to_katakana(nfkc(p["last_kana"] + p["first_kana"]))
    toks |= {"n:" + kanji, "n:" + kana, "n:" + to_hiragana(kana)}
    toks.add(romaji_key(p["last_roma"], p["first_roma"]))
    toks.add("a:" + norm_address(p["address"]))
    return toks


# --------------------------------------------------------------- text side
def split_candidates(text: str) -> tuple[list[str], str]:
    """Candidates other than Japanese name windows, plus the text in which
    the name windows live (NFKC, spaces between kana/kanji removed). The
    detector computes those windows in bulk (fastscan.py)."""
    t = nfkc(text)
    low = t.lower()
    out = ["e:" + m.group(0) for m in _EMAIL.finditer(low)]
    out += ["k:" + m.group(0) for m in _SECRET.finditer(t)]
    for sent in _SENT_END.split(t):
        ns = norm_sentence(sent)
        if SENT_MIN <= len(ns) <= SENT_MAX:
            out.append("s:" + ns)
    for m in _PHONE.finditer(t):
        ph = norm_phone(m.group(0))
        if ph:
            out.append("p:" + ph)
    for m in _PHONEISH.finditer(t):
        tail = phone_tail(m.group(0))
        if tail:
            out.append("t:" + tail)
    t_addr = re.sub(r"(\d+)丁目", r"\1-", t)
    t_addr = re.sub(r"(\d+)番地?", r"\1-", t_addr)
    t_addr = re.sub(r"(\d+)号", r"\1", t_addr)
    t_addr = re.sub(r"-+", "-", t_addr)
    out += ["a:" + norm_address(m.group(0)) for m in _ADDRESS.finditer(t_addr)]
    # romanized names: every adjacent pair of latin words, order-insensitive,
    # and capitalized words a few words apart ("last":"Takanashi","first":"Hakuto")
    words = _LATIN_WORD.findall(low)
    pairs = list(zip(words, words[1:]))
    for rx in _CAP_SPLITS:
        pairs += [(m.group(1).lower(), m.group(2).lower()) for m in rx.finditer(t)]
    out += ["r:" + a + "|" + b if a <= b else "r:" + b + "|" + a for a, b in pairs]  # = romaji_key
    out += ["n:" + x for x in field_pairs(t)]
    return out, _SPACE_IN_CJK.sub("", t)


def field_pairs(t: str) -> list[str]:
    """Names split into two fields: the surname field followed by the given
    name field, either directly or across one short label. Each field is a
    whole kana/kanji run of the NFKC text (spaces not removed); the gap must
    look like a record separator."""
    ms = [(m.start(), m.group(1), m.start(2), m.group(2)) for m in _FIELD.finditer(t)]
    out = []
    lo, hi = NAME_MIN, NAME_MAX
    for k in range(len(ms)):
        _, a, b_at, b = ms[k]
        la = len(a)
        bs = (b, ms[k + 1][3]) if len(b) <= _LABEL_MAX and k + 1 < len(ms) and ms[k + 1][0] == b_at else (b,)
        for b in bs:                                       # a+b, and a+(label)+b
            if lo <= la + len(b) <= hi:
                out.append(a + b)
            if b[-1] in "様まん殿氏" and b.endswith(_HONORIFICS):
                bb = b[:-2] if b.endswith(("さま", "さん")) else b[:-1]
                if bb and lo <= la + len(bb) <= hi:
                    out.append(a + bb)
    return out


def name_windows(joined: str) -> Iterator[str]:
    """Japanese names: every window of 3..10 characters inside a kana/kanji run."""
    for m in _CJK_RUN.finditer(joined):
        run = m.group(0)
        n = len(run)
        for i in range(n):
            for L in range(NAME_MIN, min(NAME_MAX, n - i) + 1):
                yield "n:" + run[i:i + L]


def candidates(text: str) -> Iterator[str]:
    """Every candidate token, one at a time (the reference the detector's
    bulk path is tested against)."""
    others, joined = split_candidates(text)
    yield from others
    yield from name_windows(joined)
