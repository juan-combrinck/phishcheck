# PhishCheck tests

Run everything from the `phishcheck` folder. All tests are offline except `fetch_corpus.py`; nothing is ever executed.

| Command | What it does |
|---|---|
| `python -I tests/fetch_corpus.py 300` | Downloads 300 random real phishing emails (public `phishing_pot` research corpus) into `tests/corpus` |
| `python -X utf8 -I tests/backtest.py` | Runs the whole pipeline over the corpus + 16 legitimate emails. Reports crashes, slow emails, score spread, most common checks, lowest-scoring phish, and any **false positive** on the legitimate set |
| `python -X utf8 tests/archetypes.py` | 19 hand-built emails, one per phishing technique (lookalike login, macro invoice, HTML smuggling, fake login form, SVG script, double extension, ISO / LNK-in-zip, password-protected zip, OneNote, CEO fraud, BEC reply-to spoof, delivery-fee smishing, obfuscated DocuSign, crypto airdrop, Portuguese tax lure, IP login, `@` URL trick, German account lock). Each must reach a minimum verdict |
| `python -X utf8 -m unittest tests.test_regressions -v` | 28 regression tests for every bug the backtest and fuzzer have found |
| `python -X utf8 tests/fuzz.py` | Seven fuzz stages (below) with a hang watchdog. `--cases N`, `--seed S`, `--stage NAME ...` |
| `python -X utf8 tests/fuzz.py --repro STAGE SEED` | Replays one failing case with a full traceback |

## Fuzz stages
`mutate-eml` corrupts real phishing emails (bit flips, truncation, header bombs, broken MIME, junk charsets) |
`gen-eml` builds hostile emails from scratch (nasty addresses, URLs, filenames, attachments) |
`attach` corrupted PE / PDF / zip / OOXML / OLE / RTF / HTML / SVG / OneNote blobs |
`checks` hostile strings into the link and header heuristics |
`api-shape` malformed VirusTotal / abuse.ch replies (no network used) |
`msg` garbage `.msg` files must fail cleanly |
`gui` hostile emails pushed through the real window, offscreen.

A case fails if it raises where the app must cope, or runs longer than `FUZZ_TIMEOUT` seconds (default 25).
Exit code is 1 if anything failed, so these can be wired into CI.
