"""Backtest: run the full offline pipeline over a corpus of real phishing emails plus synthetic legitimate ones.

    python -I tests/backtest.py [corpus_dir]

Reports crashes, slow emails, the score distribution, which checks fire most, the lowest-scoring phish (possible
misses) and any legitimate email that scores above Low (false positives). Exit code 1 if anything crashed or a
legitimate email was flagged.
"""
import collections
import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from phishcheck import analyzer, intel, parser, report  # noqa: E402
import ham  # noqa: E402

SLOW = 3.0  # seconds


def run_one(path: str):
    t0 = time.time()
    pe = parser.parse_file(path)
    r = analyzer.analyze(pe)
    report.to_html(r)  # the export path must also survive whatever the email contained
    intel.build_targets(pe)
    return r, time.time() - t0


def main():
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests" / "corpus"
    files = sorted(corpus.glob("*.eml"))
    crashes, slow, results = [], [], []
    fired = collections.Counter()
    for f in files:
        try:
            r, dt = run_one(str(f))
        except Exception as exc:
            crashes.append((f.name, f"{type(exc).__name__}: {exc}"))
            continue
        results.append((f.name, r))
        if dt > SLOW:
            slow.append((f.name, dt))
        for fi in r.findings:
            if fi.points:
                fired[fi.message.split(":")[0][:48]] += 1

    n = len(results)
    dist = collections.Counter(r.verdict for _, r in results)
    scores = sorted(r.score for _, r in results)
    print(f"\n=== PHISHING CORPUS: {len(files)} emails, {n} analysed, {len(crashes)} crashed ===")
    for v in ("High", "Medium", "Low"):
        print(f"  {v:7} {dist[v]:4}  ({100 * dist[v] / max(n, 1):.0f}%)")
    if scores:
        print(f"  score min/median/max: {scores[0]}/{scores[len(scores) // 2]}/{scores[-1]}")
    strongest = collections.Counter()
    for _, r in results:
        # ignore SPF/DKIM/DMARC: in a forwarded-email corpus they say little about the email itself
        sev = {f.severity for f in r.findings if f.points and not re.match(r"(No )?(SPF|DKIM|DMARC)", f.message)}
        strongest["high-severity content evidence" if "high" in sev else "medium content evidence" if "medium" in sev
                  else "only weak (low) signals" if "low" in sev else "nothing found"] += 1
    print("\nstrongest evidence per email (authentication results ignored):")
    for k, c in strongest.most_common():
        print(f"  {c:4}  {k}")
    print("\nmost frequent scoring checks:")
    for k, c in fired.most_common(14):
        print(f"  {c:4}  {k}")
    if slow:
        print(f"\nSLOW (> {SLOW}s): {slow}")
    if crashes:
        print("\nCRASHES:")
        for c in crashes:
            print("  ", c)

    print("\nlowest-scoring phish (potential misses):")
    for name, r in sorted(results, key=lambda x: x[1].score)[:8]:
        pe = r.email
        print(f"  {r.score:3} {name:20} from={pe.sender[:40]!r} links={len(pe.links)} subj={pe.subject[:40]!r}".encode("ascii", "replace").decode())

    # --- legitimate emails must stay Low
    print("\n=== LEGITIMATE (synthetic) emails: must be Low ===")
    false_pos = []
    with tempfile.TemporaryDirectory() as td:
        for name, raw in ham.build().items():
            p = Path(td) / f"{name}.eml"
            p.write_bytes(raw)
            r, _ = run_one(str(p))
            flag = "OK " if r.verdict == "Low" else "FALSE-POSITIVE"
            print(f"  {flag} {name:24} {r.verdict} {r.score}")
            if r.verdict != "Low":
                false_pos.append(name)
                for fi in r.findings:
                    if fi.points:
                        print(f"        +{fi.points} {fi.message[:100]}")
    sys.exit(1 if (crashes or false_pos) else 0)


if __name__ == "__main__":
    main()
