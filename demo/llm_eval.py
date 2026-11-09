"""Real-LLM robustness test: does a canary survive when an AI reshapes the data?

Scenario: an attacker pre-processes stolen rows with one AI (here Gemini) and
later sends the result to an AI provider that participates in Shinafure. We
scan the *output* of the first AI. All data is synthetic (Faker + canaries),
so nothing real is sent anywhere.

Backends
  ollama     : a local model through Ollama (https://ollama.com). Free, no
               account, no quota, nothing leaves your computer. Recommended.
               Default model qwen2.5:7b (Apache-2.0).
  gemini-api : Gemini API (pip install google-genai; set GEMINI_API_KEY).
               A free-tier key from Google AI Studio is enough; no card needed.
  agy        : Antigravity CLI signed in with your Google account (Google AI
               Pro/Ultra plans). Since 2026-06-18 it replaces Gemini CLI for
               subscription users. Each call is an agent run and uses your plan's
               quota, so start small (--chunks 4).
  gemini-cli : Gemini CLI. Still works with a paid Gemini API key, but no
               longer for Google AI Pro/Ultra sign-ins.
  fake       : deterministic local transforms, to check the pipeline works.

Note: the Gemini API terms and Antigravity both require users to be 18+.

Run on your own computer:
  python -m demo.llm_eval --backend ollama --chunks 4 --rows 20
  python -m demo.llm_eval --backend agy --chunks 4 --rpm 6
  python -m demo.llm_eval --backend gemini-api --model gemini-3.1-flash-lite --rpm 10
  python -m demo.llm_eval --report-only      # re-score saved outputs, no API calls

Outputs are cached in llm_outputs.jsonl, so an interrupted run resumes and
re-scoring costs nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time

from demo.measure import faker_people, t_csv, t_english, t_family_phone, t_json, t_name_address, t_name_phone
from shinafure.canary import make_canaries
from shinafure.registry import Detector, Registry, register_canaries

TASKS = [
    ("json", "次のCSVをJSON配列に変換してください。JSONだけを出力してください。"),
    ("name_phone", "次の顧客リストから氏名と電話番号だけを抜き出して、Markdownの表にしてください。表だけを出力してください。"),
    ("name_address", "次の顧客リストから氏名と住所だけを抜き出して、1行に1人ずつ書いてください。"),
    ("english", "次の顧客リストを英語に翻訳してください。氏名はローマ字で「名 姓」の順、電話番号は+81から始まる国際形式にしてください。"),
    ("family", "次の顧客リストで、同じ名字の人を家族としてグループにまとめ、各メンバーの名前と電話番号を書いてください。"),
    ("normalize", "次の顧客リストの電話番号の書式をすべて「000-0000-0000」に統一し、重複を除いて全員分を出力してください。"),
    ("summary", "次の顧客リストの特徴を3行で要約してください。"),
    ("greeting", "次の顧客リストの全員について、案内メールの宛名（「〇〇 〇〇 様」）とメールアドレスの一覧を作ってください。"),
]


def call_gemini_api(prompt: str, model: str) -> str:
    from google import genai  # pip install google-genai

    client = genai.Client()  # reads GEMINI_API_KEY
    resp = client.models.generate_content(model=model, contents=prompt)
    return resp.text or ""


_EMPTY_DIR = None


def _empty_dir() -> str:
    """Run the agent CLI in an empty folder so it has no project files to read or edit."""
    global _EMPTY_DIR
    if _EMPTY_DIR is None:
        import tempfile
        _EMPTY_DIR = tempfile.mkdtemp(prefix="shinafure-llm-")
    return _EMPTY_DIR


def call_agy(prompt: str, model: str) -> str:
    exe = shutil.which("agy")
    if not exe:
        raise SystemExit("agy (Antigravity CLI) not found on PATH. Install it and run `agy` once to sign in.")
    full = ("ツールやファイル操作は使わず、テキストの回答だけを出力してください。\n\n" + prompt)
    args = [exe, "-p", full, "--disable-slash-commands"]
    if model:
        args += ["--model", model]
    r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=300, cwd=_empty_dir())
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout)[-500:])
    return r.stdout


def call_gemini_cli(prompt: str, model: str) -> str:
    exe = shutil.which("gemini")
    if not exe:
        raise SystemExit("gemini CLI not found on PATH")
    args = [exe, "-p", "上の入力に対する回答だけを出力してください。"]
    if model:
        args += ["-m", model]
    r = subprocess.run(args, input=prompt, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=300, cwd=_empty_dir())
    if r.returncode != 0:
        raise RuntimeError(r.stderr[-500:])
    return r.stdout


def call_ollama(prompt: str, model: str, host: str) -> str:
    import httpx

    r = httpx.post(f"{host.rstrip('/')}/api/chat", timeout=1800, json={
        "model": model, "stream": False,
        "messages": [{"role": "user", "content": prompt}],
        "options": {"num_ctx": 16384, "temperature": 0.2},
    })
    r.raise_for_status()
    return r.json()["message"]["content"]


def call_fake(task: str, rows: list[dict]) -> str:
    return {"json": t_json, "name_phone": t_name_phone, "name_address": t_name_address,
            "english": t_english, "family": t_family_phone, "normalize": t_name_phone,
            "summary": lambda rs: "顧客は全国に分布しています。", "greeting": lambda rs: "\n".join(
                f"{r['last']} {r['first']} 様 <{r['email']}>" for r in rs)}[task](rows)


def build_chunks(rows_per_chunk: int = 50, seed: int = 11, style: str = "rare"):
    """seed=11 reproduces the v0.1 / v0.2 runs exactly; other seeds give new
    canaries, new customers and new positions (for more samples)."""
    rng = random.Random(seed)
    k = rows_per_chunk
    people = faker_people(20 * k, seed=3 + (seed - 11))
    canaries = make_canaries(10, "eval-db", "kanari.example", rng, style=style)
    chunks = []
    for i in range(20):
        rows = people[i * k:(i + 1) * k]
        cid = None
        if i < 10:  # chunks 0-9 carry one canary each; 10-19 are controls
            c = canaries[i]
            rows = rows[:-1] + [{**c.person, "id": f"U{rng.randint(10**6, 10**7)}", "canary": c.canary_id}]
            rng.shuffle(rows)
            cid = c.canary_id
        chunks.append({"chunk": i, "canary": cid, "rows": rows})
    return canaries, chunks


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["ollama", "agy", "gemini-api", "gemini-cli", "fake"], default="fake")
    ap.add_argument("--model", default=None,
                    help="ollama default: qwen2.5:7b; gemini-api default: gemini-3.1-flash-lite; CLIs: their default")
    ap.add_argument("--rows", type=int, default=50, help="rows per chunk (use 20 for a local model)")
    ap.add_argument("--host", default="http://localhost:11434", help="Ollama address")
    ap.add_argument("--chunks", type=int, default=10, help="canary chunks to use (same number of control chunks); max 10")
    ap.add_argument("--rpm", type=float, default=10, help="requests per minute (free tiers are rate-limited)")
    ap.add_argument("--canary-style", choices=["rare", "ordinary", "mixed"], default="rare",
                    help="rare = v0.1 canaries (default, matches earlier runs); ordinary = common-looking names")
    ap.add_argument("--seed", type=int, default=11, help="11 = the original chunks; change it for new samples")
    ap.add_argument("--tasks", default="", help="comma-separated subset, e.g. family,summary (default: all)")
    ap.add_argument("--out", default="llm_outputs.jsonl")
    ap.add_argument("--results", default="results_llm.md")
    ap.add_argument("--report-only", action="store_true")
    a = ap.parse_args()

    if a.backend == "fake":
        a.model = "local-transforms"
    elif a.model is None and a.backend == "gemini-api":
        a.model = "gemini-3.1-flash-lite"
    elif a.model is None and a.backend == "ollama":
        a.model = "qwen2.5:7b"
    tasks = [t for t in TASKS if not a.tasks or t[0] in a.tasks.split(",")]
    if not tasks:
        raise SystemExit(f"unknown --tasks; choose from {', '.join(t for t, _ in TASKS)}")
    canaries, chunks = build_chunks(a.rows, seed=a.seed, style=a.canary_style)
    n = max(1, min(10, a.chunks))
    chunks = chunks[:n] + chunks[10:10 + n]
    done = {}
    if os.path.exists(a.out):
        for line in open(a.out, encoding="utf-8"):
            d = json.loads(line)
            if d.get("seed", 11) != a.seed or d.get("canary_style", "rare") != a.canary_style:
                raise SystemExit(f"{a.out} holds outputs for a different --seed/--canary-style; use another --out file")
            done[(d["chunk"], d["task"])] = d

    if not a.report_only:
        with open(a.out, "a", encoding="utf-8") as f:
            for ch in chunks:
                for task, instruction in tasks:
                    if (ch["chunk"], task) in done:
                        continue
                    prompt = f"{instruction}\n\n{t_csv(ch['rows'])}"
                    t = time.time()
                    try:
                        if a.backend == "ollama":
                            out = call_ollama(prompt, a.model, a.host)
                        elif a.backend == "agy":
                            out = call_agy(prompt, a.model)
                        elif a.backend == "gemini-api":
                            out = call_gemini_api(prompt, a.model)
                        elif a.backend == "gemini-cli":
                            out = call_gemini_cli(prompt, a.model)
                        else:
                            out = call_fake(task, ch["rows"])
                    except Exception as e:  # keep going; failures are retried on the next run
                        print(f"  chunk {ch['chunk']} {task}: {e}", file=sys.stderr)
                        if a.backend in ("agy", "gemini-api", "gemini-cli"):
                            time.sleep(max(0.0, 60.0 / a.rpm - (time.time() - t)))
                        continue
                    rec = {"chunk": ch["chunk"], "task": task, "backend": a.backend, "model": a.model or "default",
                           "canary": ch["canary"], "canary_style": a.canary_style, "seed": a.seed,
                           "rows": a.rows, "output": out}
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
                    done[(ch["chunk"], task)] = rec
                    print(f"  chunk {ch['chunk']:2d} {task:12s} {len(out):6d} chars {time.time() - t:5.1f}s",
                          file=sys.stderr)
                    if a.backend in ("agy", "gemini-api", "gemini-cli"):
                        time.sleep(max(0.0, 60.0 / a.rpm - (time.time() - t)))

    reg = Registry(oprf_per_hour=10**9, require_tickets=False)
    register_canaries(reg, "eval-co", canaries)
    det = Detector(reg, reg.add_provider("p"), "p")
    rows = ["| 指示 | カナリア入り：確定 | カナリア入り：疑いのみ | カナリアなし：誤検知（確定） | カナリアなし：疑い | 未実行 |",
            "|---|---:|---:|---:|---:|---:|"]
    for task, _ in tasks:
        conf = sus = fp = fsus = missing = ran_c = ran_n = 0
        for ch in chunks:
            d = done.get((ch["chunk"], task))
            if d is None:
                missing += 1
                continue
            r = det.scan(d["output"], report=False)
            if ch["canary"]:
                ran_c += 1
                conf += ch["canary"] in r.confirmed
                sus += ch["canary"] in r.suspect and ch["canary"] not in r.confirmed
            else:
                ran_n += 1
                fp += bool(r.confirmed)
                fsus += bool(r.suspect) and not r.confirmed
        rows.append(f"| {task} | {conf}/{ran_c} | {sus} | {fp}/{ran_n} | {fsus} | {missing} |")
    backends = sorted({d['backend'] + ':' + d['model'] for d in done.values()})
    rows_note = (f"1ブロック{a.rows}行、カナリア入り{n}ブロック＋カナリアなし{n}ブロック、"
                 f"カナリアの種類: {a.canary_style}、seed {a.seed}")
    md = f"使用したモデル: {', '.join(backends) or 'なし'}（{rows_note}）\n\n" + "\n".join(rows)
    print(md)
    open(a.results, "w", encoding="utf-8").write(md + "\n")


if __name__ == "__main__":
    main()
