import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from phishcheck import analyzer, parser, report


def cli(path):
    r = analyzer.analyze(parser.parse_file(path))
    print(f"{r.verdict} risk {r.score}/100")
    for f in r.findings:
        print(f"[{f.severity:6}] {f.category}: {f.message}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli(sys.argv[1])
    else:
        if sys.platform == "win32":  # detach the console so launching from a shortcut leaves no black window
            import ctypes

            ctypes.windll.kernel32.FreeConsole()
        from phishcheck.gui import main

        main()

