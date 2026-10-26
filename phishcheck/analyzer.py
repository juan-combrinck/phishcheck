from . import checks, static_analysis
from .models import Finding, ParsedEmail, Report

ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
# A single noisy category must not be able to push a harmless email to High on its own.
CATEGORY_CAP = {"Links": 45, "Body": 30, "Headers": 70}


def _tidy(findings: list) -> list:
    """Merge identical findings ('Unencrypted HTTP link: x.com' x 12 -> one, '(x12)') and cap each category's points."""
    merged, counts = {}, {}
    for f in findings:
        key = (f.severity, f.category, f.message)
        if key in merged:
            counts[key] += 1
        else:
            merged[key], counts[key] = f, 1
    out = []
    for key, f in merged.items():
        if counts[key] > 1:
            f.message = f"{f.message}  (x{counts[key]})"
        out.append(f)
    spent = {}
    for f in sorted(out, key=lambda x: -x.points):
        cap = CATEGORY_CAP.get(f.category)
        if cap is not None:
            take = min(f.points, max(cap - spent.get(f.category, 0), 0))
            f.points = take
            spent[f.category] = spent.get(f.category, 0) + take
    return out


def _finish(r: Report, findings: list):
    r.findings = sorted(findings, key=lambda f: (ORDER.get(f.severity, 9), -f.points))
    r.score = min(sum(f.points for f in r.findings), 100)
    r.verdict = "High" if r.score >= 50 else "Medium" if r.score >= 20 else "Low"


def analyze(pe: ParsedEmail, progress=lambda msg: None, **_ignored) -> Report:
    """Static analysis only: fast, offline, nothing is executed. Online lookups run separately (see intel.py)."""
    findings = []
    findings += [Finding(sev, "Headers", msg, pts) for sev, msg, pts in pe.notes]
    progress("Checking headers")
    findings += checks.check_headers(pe)
    progress("Checking links")
    for link in pe.links:
        link.findings = checks.check_link(link.href, link.text)
        findings += link.findings
    findings += checks.check_context(pe)
    progress("Checking body")
    findings += checks.check_body(pe)
    for att in pe.attachments:
        progress(f"Static analysis: {att.filename}")
        static_analysis.analyze(att)
        findings += att.findings
    findings = _tidy(findings)
    r = Report(email=pe)
    r.static_findings = list(findings)
    _finish(r, findings)
    return r


def rescore(r: Report, extra: list):
    """Recompute the score after online lookups add (or replace) their findings."""
    _finish(r, r.static_findings + extra)
