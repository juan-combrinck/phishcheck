"""Online reputation lookups. Only hashes, domains and URLs are sent, never file contents or email bodies.

Providers (keys are set in the app under SETTINGS / API KEYS, or via environment variables):
  VT_API_KEY        VirusTotal: file hash + domain reputation
  ABUSECH_AUTH_KEY  abuse.ch: MalwareBazaar (file hash) + URLhaus (URL)

Every lookup returns a dict with a "status": ok | not_found | no_key | error | cancelled.
"""
import json
import os
import sqlite3
import time
from collections import deque
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urlparse

import requests

from .checks import base_domain
from .models import Finding, ParsedEmail

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"
CACHE_DB = ROOT / "cache.sqlite"
TIMEOUT = 20
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # harmless antivirus test file
MAX_HOSTS = 8  # link domains looked up per email (8 lookups = 2 minutes on a free VirusTotal key)


# ---------------------------------------------------------------- config
def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(values: dict):
    cfg = load_config()
    cfg.update(values)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def _cfg(name: str) -> str:
    return os.environ.get(name) or load_config().get(name, "")


def have_vt() -> bool:
    return bool(_cfg("VT_API_KEY"))


def have_abuse() -> bool:
    return bool(_cfg("ABUSECH_AUTH_KEY"))


# ---------------------------------------------------------------- key tests (Settings)
def test_vt_key(key: str):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{EICAR_SHA256}", headers={"x-apikey": key}, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return False, f"network error: {exc}"
    if r.status_code in (200, 404):
        return True, "key accepted"
    if r.status_code in (401, 403):
        return False, "key rejected by VirusTotal"
    if r.status_code == 429:
        return True, "key accepted (rate limit hit right now)"
    return False, f"unexpected HTTP {r.status_code}"


def test_abusech_key(key: str):
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": EICAR_SHA256},
                          headers={"Auth-Key": key}, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return False, f"network error: {exc}"
    if r.status_code in (401, 403):
        return False, "key rejected by abuse.ch"
    if r.status_code != 200:
        return False, f"unexpected HTTP {r.status_code}"
    if r.json().get("query_status", "") in ("unauthorized", "no_auth_key", "invalid_auth_key"):
        return False, "key rejected by abuse.ch"
    return True, "key accepted"


# ---------------------------------------------------------------- cache
def _db():
    con = sqlite3.connect(CACHE_DB)
    con.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT, t REAL)")
    return con


def _cached(key: str, fetch):
    """Successful answers are cached (24h; 'not found' only 1h, since new samples get added). Errors never are."""
    con = _db()
    try:
        row = con.execute("SELECT v, t FROM c WHERE k=?", (key,)).fetchone()
        if row:
            val = json.loads(row[0])
            ttl = 3600 if val.get("status") == "not_found" else 86400
            if time.time() - row[1] < ttl:
                val["cached"] = True
                return val
        val = fetch()
        if val.get("status") in ("ok", "not_found"):
            con.execute("REPLACE INTO c VALUES (?,?,?)", (key, json.dumps(val), time.time()))
            con.commit()
        return val
    finally:
        con.close()


# ---------------------------------------------------------------- providers
class _Limiter:
    """VirusTotal free tier: 4 requests per rolling minute."""

    def __init__(self, per=4, window=60.0):
        self.per, self.window, self.times = per, window, deque()

    def wait(self, cancel, notify) -> bool:
        while True:
            now = time.time()
            while self.times and now - self.times[0] > self.window:
                self.times.popleft()
            if len(self.times) < self.per:
                self.times.append(now)
                return True
            if cancel():
                return False
            delay = self.window - (now - self.times[0])
            notify(f"waiting {int(delay) + 1}s for VirusTotal free-tier rate limit")
            time.sleep(min(delay, 1.0))


_vt_limiter = _Limiter()


# Provider replies are untrusted input: coerce every field to the type we expect instead of assuming the shape.
def _d(x) -> dict:
    return x if isinstance(x, dict) else {}


def _l(x) -> list:
    return x if isinstance(x, list) else []


def _n(x) -> int:
    return x if isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 10 ** 9 else 0


def _num(x):
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) and -10 ** 12 < x < 10 ** 12 else None


def _vt(path: str, cancel, notify) -> dict:
    key = _cfg("VT_API_KEY")
    if not key:
        return {"status": "no_key"}
    if not _vt_limiter.wait(cancel, notify):
        return {"status": "cancelled"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key}, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return {"status": "error", "msg": f"network error: {exc}"}
    if r.status_code == 404:
        return {"status": "not_found"}
    if r.status_code in (401, 403):
        return {"status": "error", "msg": "VirusTotal rejected the API key"}
    if r.status_code == 429:
        return {"status": "error", "msg": "VirusTotal quota reached (try again later)"}
    if r.status_code != 200:
        return {"status": "error", "msg": f"VirusTotal HTTP {r.status_code}"}
    try:
        a = _d(_d(_d(r.json()).get("data")).get("attributes"))
    except ValueError:
        return {"status": "error", "msg": "VirusTotal returned an unreadable reply"}
    if not a:
        return {"status": "error", "msg": "VirusTotal returned an unexpected reply"}
    stats = _d(a.get("last_analysis_stats"))
    ptc = _d(a.get("popular_threat_classification"))
    flagged = sorted((str(eng)[:40], str(_d(v).get("result") or _d(v).get("category"))[:80])
                     for eng, v in _d(a.get("last_analysis_results")).items() if _d(v).get("category") in ("malicious", "suspicious"))
    return {"status": "ok", "malicious": _n(stats.get("malicious")), "suspicious": _n(stats.get("suspicious")),
            "harmless": _n(stats.get("harmless")), "undetected": _n(stats.get("undetected")),
            "total": sum(_n(v) for v in stats.values()),
            "label": str(ptc.get("suggested_threat_label") or "")[:80],
            "threat_names": [str(x["value"])[:60] for x in _l(ptc.get("popular_threat_name"))[:3] if isinstance(x, dict) and x.get("value")],
            "threat_cats": [str(x["value"])[:60] for x in _l(ptc.get("popular_threat_category"))[:3] if isinstance(x, dict) and x.get("value")],
            "flagged": flagged[:5], "flagged_total": len(flagged),
            "reputation": _num(a.get("reputation")), "last_analysis": _num(a.get("last_analysis_date")),
            # file facts
            "name": str(a.get("meaningful_name") or "")[:100], "file_type": str(a.get("type_description") or "")[:60],
            "size": _num(a.get("size")), "first_seen": _num(a.get("first_submission_date")),
            # domain facts
            "categories": sorted({str(v)[:40] for v in _d(a.get("categories")).values()})[:4],
            "created": _num(a.get("creation_date")), "registrar": str(a.get("registrar") or "")[:60]}


def _abuse_post(url: str, data: dict) -> dict:
    key = _cfg("ABUSECH_AUTH_KEY")
    if not key:
        return {"status": "no_key"}
    try:
        r = requests.post(url, data=data, headers={"Auth-Key": key}, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return {"status": "error", "msg": f"network error: {exc}"}
    if r.status_code in (401, 403):
        return {"status": "error", "msg": "abuse.ch rejected the auth key"}
    if r.status_code != 200:
        return {"status": "error", "msg": f"abuse.ch HTTP {r.status_code}"}
    try:
        return {"status": "raw", "json": r.json()}
    except ValueError:
        return {"status": "error", "msg": "abuse.ch returned a non-JSON reply"}


def _malwarebazaar(sha256: str) -> dict:
    res = _abuse_post("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": sha256})
    if res["status"] != "raw":
        return res
    j = _d(res["json"])
    qs = str(j.get("query_status", ""))
    if qs == "ok":
        data = _l(j.get("data"))
        e = _d(data[0]) if data else {}
        tags = ", ".join(str(t) for t in _l(e.get("tags")))
        return {"status": "ok", "hit": True, "detail": str(e.get("signature") or tags or "known malware")[:80]}
    if qs in ("hash_not_found", "no_results"):
        return {"status": "ok", "hit": False}
    return {"status": "error", "msg": f"MalwareBazaar: {qs or 'unexpected reply'}"}


def _urlhaus(url: str) -> dict:
    res = _abuse_post("https://urlhaus-api.abuse.ch/v1/url/", {"url": url})
    if res["status"] != "raw":
        return res
    j = _d(res["json"])
    qs = str(j.get("query_status", ""))
    if qs == "ok":
        return {"status": "ok", "hit": True, "detail": f"{str(j.get('threat') or 'malware url')[:40]} ({str(j.get('url_status') or '?')[:20]})"}
    if qs in ("no_results", "invalid_url"):
        return {"status": "ok", "hit": False}
    return {"status": "error", "msg": f"URLhaus: {qs or 'unexpected reply'}"}


# ---------------------------------------------------------------- targets + lookup
def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def build_targets(pe: ParsedEmail) -> list:
    """What gets looked up: every attachment hash first, then link domains (links the static checks already flagged
    go first, one per registered domain, capped so the free VirusTotal quota lasts)."""
    targets, seen_hash, seen_base = [], set(), set()
    for a in pe.attachments:
        if a.data and a.sha256 not in seen_hash:
            seen_hash.add(a.sha256)
            targets.append({"kind": "file", "label": a.filename, "sha256": a.sha256})
    for l in sorted(pe.links, key=lambda x: not x.findings):  # stable: flagged links first
        host = _host(l.href)
        if host and base_domain(host) not in seen_base and len(seen_base) < MAX_HOSTS:
            seen_base.add(base_domain(host))
            targets.append({"kind": "url", "label": host, "url": l.href, "host": host})
    return targets


def _day(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") if ts else ""
    except (OverflowError, OSError, ValueError, TypeError):
        return ""


def detail_html(t: dict, res: dict) -> str:
    """The crucial facts for one target, as small HTML for the Threat Intel detail pane."""
    Y, M = "#FFD400", "#8a8a8a"
    colors = {"high": "#ff3b30", "medium": "#ff8c00", "clean": "#35e06b", "unknown": Y, "off": M, "error": "#d99a3d"}
    rows = []

    def row(k, v, color=None):
        v = f"<span style='color:{color}'>{v}</span>" if color else v
        rows.append(f"<tr><td style='color:{M};padding-right:14px' valign=top>{k}</td><td>{v}</td></tr>")

    vt, ab = res["vt"], res["abuse"]
    text, level = describe_vt(vt)
    what = "FILE" if t["kind"] == "file" else "DOMAIN"
    out = f"<div style='font-size:15px'><b style='color:{Y}'>{escape(t['label'][:80])}</b> <span style='color:{M}'>{what}</span></div>"
    if vt.get("status") == "ok":
        bad = vt["malicious"] + vt["suspicious"]
        row("VERDICT", f"<b>{text.split('  ')[0]}</b>: {bad} of {vt['total']} security engines flagged this", colors[level])
        row("BREAKDOWN", f"{vt['malicious']} malicious, {vt['suspicious']} suspicious, {vt['harmless']} harmless, "
                          f"{vt['undetected']} undetected")
        threat = ", ".join(x for x in [vt.get("label")] + vt.get("threat_names", []) if x)
        if threat:
            row("THREAT", escape(threat), colors["high"] if level == "high" else None)
        if vt.get("threat_cats"):
            row("CATEGORY", escape(", ".join(vt["threat_cats"])))
        if vt.get("flagged"):
            more = vt["flagged_total"] - len(vt["flagged"])
            names = "<br>".join(f"{escape(e)}: <span style='color:{M}'>{escape(str(r))}</span>" for e, r in vt["flagged"])
            row("FLAGGED BY", names + (f"<br><span style='color:{M}'>+ {more} more engines</span>" if more > 0 else ""))
        if t["kind"] == "file":
            facts = [x for x in (vt.get("file_type"), f"{vt['size']:,} bytes" if vt.get("size") else "",
                                 f"first seen {_day(vt.get('first_seen'))}" if vt.get("first_seen") else "") if x]
            if facts:
                row("FILE", escape("  |  ".join(facts)))
            if vt.get("name"):
                row("KNOWN AS", escape(vt["name"]))
        else:
            if vt.get("categories"):
                row("CATEGORIES", escape(", ".join(vt["categories"])))
            facts = [x for x in (f"registered {_day(vt['created'])}" if vt.get("created") else "",
                                 f"registrar {vt['registrar']}" if vt.get("registrar") else "",
                                 f"reputation {vt['reputation']}" if vt.get("reputation") is not None else "") if x]
            if facts:
                row("DOMAIN", escape("  |  ".join(facts)))
        if vt.get("last_analysis"):
            row("CHECKED", f"VirusTotal last analysed this {_day(vt['last_analysis'])}")
    elif vt.get("status") == "not_found":
        what_l = "file" if t["kind"] == "file" else "domain"
        row("VERDICT", f"<b>Unknown</b>: VirusTotal has no record of this {what_l}. A never-seen attachment is itself a warning sign.", Y)
    else:
        row("VIRUSTOTAL", escape(text), colors[level])
    if ab.get("status") != "no_key":
        atext, alevel = describe_abuse(ab)
        row("ABUSE.CH", escape(atext), colors[alevel])
    return out + "<table cellspacing=4 style='margin-top:8px'>" + "".join(rows) + "</table>"


def vt_page(t: dict) -> str:
    """Browser link to the VirusTotal page for this target (works without an API key)."""
    if t["kind"] == "file":
        return f"https://www.virustotal.com/gui/file/{t['sha256']}"
    return f"https://www.virustotal.com/gui/domain/{t['host']}"


def lookup(t: dict, cancel=lambda: False, notify=lambda m: None) -> dict:
    if t["kind"] == "file":
        sha = t["sha256"]
        return {"vt": _cached(f"vt2:file:{sha}", lambda: _vt(f"files/{sha}", cancel, notify)),
                "abuse": _cached(f"mb:{sha}", lambda: _malwarebazaar(sha))}
    host, url = t["host"], t["url"]
    return {"vt": _cached(f"vt2:domain:{host}", lambda: _vt(f"domains/{host}", cancel, notify)),
            "abuse": _cached(f"uh:{url}", lambda: _urlhaus(url))}


# ---------------------------------------------------------------- presentation
def describe_vt(r: dict):
    """-> (text, level) where level is high | medium | clean | unknown | off | error."""
    s = r.get("status")
    if s == "ok":
        bad = r["malicious"] + r["suspicious"]
        extra = f"  {r['label']}" if r.get("label") else ""
        if r["malicious"] >= 3:
            return f"MALICIOUS  {bad}/{r['total']}{extra}", "high"
        if bad:
            return f"SUSPICIOUS  {bad}/{r['total']}{extra}", "medium"
        return f"CLEAN  0/{r['total']}", "clean"
    if s == "not_found":
        return "not on VirusTotal yet", "unknown"
    if s == "no_key":
        return "no VirusTotal key (add in SETTINGS)", "off"
    if s == "cancelled":
        return "cancelled", "off"
    return r.get("msg", "error"), "error"


def describe_abuse(r: dict):
    s = r.get("status")
    if s == "ok":
        return (f"LISTED: {r.get('detail', '')}", "high") if r.get("hit") else ("not listed", "clean")
    if s == "no_key":
        return "not configured", "off"
    return r.get("msg", "error"), "error"


def to_findings(t: dict, res: dict) -> list:
    out, name = [], t["label"][:50]
    vt = res["vt"]
    if vt.get("status") == "ok":
        bad = vt["malicious"] + vt["suspicious"]
        what = "file" if t["kind"] == "file" else "domain"
        if bad:
            base = 15 if t["kind"] == "file" else 10
            sev = "high" if vt["malicious"] >= 3 else "medium"
            out.append(Finding(sev, "Intel", f"VirusTotal flags {what} {name}: {bad}/{vt['total']} engines {vt.get('label', '')}".strip(),
                               min(base + bad * 3, 50)))
        else:
            out.append(Finding("info", "Intel", f"VirusTotal: {what} {name} is clean (0/{vt['total']})", 0))
    elif vt.get("status") == "not_found":
        pts = 3 if t["kind"] == "file" else 0
        out.append(Finding("info", "Intel", f"VirusTotal has never seen {name}", pts))
    elif vt.get("status") == "error":
        out.append(Finding("info", "Intel", f"VirusTotal lookup failed for {name}: {vt.get('msg')}", 0))
    ab = res["abuse"]
    if ab.get("status") == "ok" and ab.get("hit"):
        src = "MalwareBazaar" if t["kind"] == "file" else "URLhaus"
        out.append(Finding("high", "Intel", f"{src} lists {name}: {ab.get('detail', '')}", 50))
    elif ab.get("status") == "error":
        out.append(Finding("info", "Intel", f"abuse.ch lookup failed for {name}: {ab.get('msg')}", 0))
    return out
