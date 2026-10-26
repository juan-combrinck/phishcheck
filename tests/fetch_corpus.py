"""Downloads a random sample of real phishing emails (public research corpus: rf-peixoto/phishing_pot) into tests/corpus.

These are plain .eml files. The tests only ever read them; nothing is opened or executed.
    python -I tests/fetch_corpus.py [count]
"""
import json
import random
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

API = "https://api.github.com/repos/rf-peixoto/phishing_pot/contents/email"
OUT = Path(__file__).resolve().parent / "corpus"


def main(count: int):
    OUT.mkdir(exist_ok=True)
    listing = json.load(urllib.request.urlopen(API, timeout=60))
    pool = [x for x in listing if 3000 < x["size"] < 700000]
    random.Random(2026).shuffle(pool)

    def get(x):
        dest = OUT / x["name"]
        if dest.exists():
            return 1
        try:
            urllib.request.urlretrieve(x["download_url"], dest)
            return 1
        except Exception as exc:
            print("skip", x["name"], exc)
            return 0

    with ThreadPoolExecutor(8) as ex:
        n = sum(ex.map(get, pool[:count]))
    print(f"{n} emails in {OUT}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 300)
