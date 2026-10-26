from datetime import datetime
from html import escape

from . import intel
from .models import Report

COLORS = {"High": "#c62828", "Medium": "#ef6c00", "Low": "#2e7d32"}
SEV = {"high": "#c62828", "medium": "#ef6c00", "low": "#f9a825", "info": "#607d8b"}


def to_html(r: Report) -> str:
    e = r.email
    rows = "".join(
        f"<tr><td style='color:{SEV[f.severity]};font-weight:bold'>{f.severity.upper()}</td>"
        f"<td>{escape(f.category)}</td><td>{escape(f.message)}</td><td>+{f.points}</td></tr>"
        for f in r.findings)
    atts = "".join(
        f"<tr><td>{escape(a.filename)}</td><td>{a.size}</td><td><code>{a.md5}</code></td>"
        f"<td><code>{a.sha1}</code></td><td><code>{a.sha256}</code></td></tr>" for a in e.attachments
    ) or "<tr><td colspan=5>None</td></tr>"
    links = "".join(f"<tr><td>{escape(l.text[:60])}</td><td>{escape(l.href[:120])}</td></tr>" for l in e.links) \
        or "<tr><td colspan=2>None</td></tr>"
    def flagged(res):
        vt = res["vt"]
        if vt.get("status") != "ok" or not vt.get("flagged"):
            return ""
        return "; ".join(f"{e}: {r}" for e, r in vt["flagged"])

    intel_rows = "".join(
        f"<tr><td>{t['kind']}</td><td>{escape(t['label'][:70])}</td><td>{escape(intel.describe_vt(res['vt'])[0])}</td>"
        f"<td>{escape(flagged(res))}</td><td>{escape(intel.describe_abuse(res['abuse'])[0])}</td></tr>"
        for t, res in r.intel) or "<tr><td colspan=5>No online lookups were run</td></tr>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Phishing report</title>
<style>body{{font-family:Segoe UI,sans-serif;margin:2em;max-width:1000px}}table{{border-collapse:collapse;width:100%;margin-bottom:1.5em}}
td,th{{border:1px solid #ccc;padding:6px;text-align:left;font-size:13px;word-break:break-all}}th{{background:#eee}}
.v{{display:inline-block;padding:8px 18px;color:#fff;border-radius:6px;font-size:20px;background:{COLORS[r.verdict]}}}</style></head><body>
<h1>Email Phishing Report</h1><p>Generated {datetime.now():%Y-%m-%d %H:%M}</p>
<p><span class="v">{r.verdict} risk: {r.score}/100</span></p>
<table><tr><th>Subject</th><td>{escape(e.subject)}</td></tr><tr><th>From</th><td>{escape(e.sender)}</td></tr>
<tr><th>Reply-To</th><td>{escape(e.reply_to)}</td></tr><tr><th>Return-Path</th><td>{escape(e.return_path)}</td></tr>
<tr><th>To</th><td>{escape(e.to)}</td></tr><tr><th>Date</th><td>{escape(e.date)}</td></tr></table>
<h2>Findings</h2><table><tr><th>Severity</th><th>Area</th><th>Detail</th><th>Score</th></tr>{rows}</table>
<h2>Attachments</h2><table><tr><th>Name</th><th>Bytes</th><th>MD5</th><th>SHA-1</th><th>SHA-256</th></tr>{atts}</table>
<h2>Threat intelligence</h2><table><tr><th>Type</th><th>Target</th><th>VirusTotal</th><th>Flagged by</th><th>abuse.ch</th></tr>{intel_rows}</table>
<h2>Links</h2><table><tr><th>Text</th><th>URL</th></tr>{links}</table></body></html>"""
