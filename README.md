# PhishCheck

A Windows desktop tool that analyses suspicious emails (`.eml` / `.msg`) for phishing and malware indicators **without ever opening or executing anything**. It combines offline heuristics, static attachment analysis and optional online threat-intel lookups into a single risk score and verdict.

<!-- Add a screenshot: docs/screenshot.png -->
<!-- ![PhishCheck](docs/screenshot.png) -->

## How it works

```
.eml / .msg  ->  parser  ->  checks (headers, links, body)  ->  analyzer  ->  score + verdict
                    |                                              ^
                    +-> static attachment analysis ----------------+
                                                                   ^
                              optional online lookups (VirusTotal, abuse.ch) add findings later
```

1. **Parse**: the email is split into headers, body text/HTML, links and attachments. Parsing is defensive. Hostile or malformed emails fall back to more lenient parsers instead of crashing, and hard limits cap file size, MIME depth, links and attachments.
2. **Check**: each header, link and body is run through heuristics, and each attachment is analysed as raw bytes. Each check produces a *finding* with a severity and points.
3. **Score**: findings are merged (duplicates collapse into one with a count) and each category is capped, so one noisy category can't push a harmless email to High. Points add up to a 0-100 score: **High** at 50+, **Medium** at 20+, otherwise **Low**.
4. **Enrich (optional)**: hashes, domains and URLs are looked up on VirusTotal and abuse.ch. The results are added to the findings and the score is recomputed.

## Features

- **Header and link heuristics** – sender/reply-to mismatches, lookalike domains, URL shorteners, suspicious TLDs, `@` URL tricks, IP-based links, unencrypted HTTP links, obfuscated text.
- **Body analysis** – urgency / credential-lure language (multi-language), fake login forms, HTML smuggling, embedded scripts.
- **Static attachment analysis** – files are only read as bytes. Checks for dangerous and double extensions, macro-enabled Office files (via `oletools`), PE inspection (`pefile`), PDFs, archives (including password-protected zips), ISO/LNK/OneNote containers, SVG scripts and entropy.
- **Threat intel (optional)** – VirusTotal (file hash + domain reputation) and abuse.ch (MalwareBazaar + URLhaus). Only hashes, domains and URLs are sent, never file contents or email bodies. Results are cached locally in SQLite.
- **Outlook integration** – pick emails straight from classic Outlook (COM).
- **Reports** – exportable HTML report with findings ranked by severity.
- **CLI mode** – `python main.py path\to\email.eml`

## Install

Requires Windows and Python 3.10+.

```
pip install -r requirements.txt
python main.py
```

Optional: `powershell -File create_shortcut.ps1` adds a Desktop / Start Menu shortcut.

### API keys (optional)

Copy `config.example.json` to `config.json` and fill in your keys, or paste them in the app under **SETTINGS / API KEYS**. Keys can also be supplied as the environment variables `VT_API_KEY` and `ABUSECH_AUTH_KEY`. Without keys, all offline analysis still works. `config.json` is git-ignored.

## Testing

The project ships with a test suite that stresses the analyser against real-world phishing and its own edge cases (see [`tests/README.md`](tests/README.md)):

- a backtest over a corpus of real phishing emails (public [`phishing_pot`](https://github.com/rf-peixoto/phishing_pot) research set) plus legitimate emails, checking for crashes, slow inputs and false positives
- 19 hand-built emails, one per phishing technique
- regression tests for every bug found
- a 7-stage fuzzer (corrupted emails, hostile attachments, malformed API replies, garbage `.msg` files, the GUI itself)

```
python -I tests/fetch_corpus.py 300
python -X utf8 -I tests/backtest.py
python -X utf8 -m unittest tests.test_regressions -v
python -X utf8 tests/fuzz.py
```

## Project layout

```
main.py               entry point (GUI, or CLI when given a file path)
phishcheck/
  parser.py           .eml / .msg parsing
  checks.py           header, link and body heuristics
  static_analysis.py  attachment analysis
  intel.py            VirusTotal / abuse.ch lookups + cache
  analyzer.py         combines findings into a score and verdict
  report.py           HTML report
  gui.py              PySide6 interface
  outlook.py          classic Outlook (COM) integration
tests/                backtest, archetypes, regression tests, fuzzer
```

## Disclaimer

PhishCheck is a triage aid, not a guarantee. Treat any email it rates Low with the same caution you would anyway.
