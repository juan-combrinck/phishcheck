"""Heuristic checks on headers, links and body text. No network access."""
import html as _html
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import Finding, ParsedEmail

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
              "tiny.cc", "rb.gy", "t.ly", "bl.ink", "lnkd.in", "s.id"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest",
                   "icu", "cyou", "buzz", "monster", "sbs", "cfd", "bond"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "icloud.com", "proton.me",
            "protonmail.com", "gmx.com", "gmx.net", "gmx.de", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "msn.com",
            "web.de", "mail.ru", "qq.com", "163.com", "yahoo.co.uk", "yahoo.fr", "hotmail.fr", "hotmail.co.uk",
            "outlook.com.br", "hotmail.com.br", "uol.com.br", "bol.com.br"}
# second-level public suffixes, so "shop.example.co.uk" has the registered domain "example.co.uk"
MULTI_SUFFIX = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.za", "co.jp", "co.in",
                "co.id", "ac.id", "or.id", "com.br", "net.br", "org.br", "com.ar", "com.mx", "com.tr", "com.cn", "com.hk",
                "com.sg", "com.my", "com.ph", "com.vn", "com.co", "com.pe", "com.ua", "co.kr", "co.il", "com.pk", "com.ng",
                "com.eg", "com.sa", "com.tw", "gob.mx"}

# brand -> registered domains that genuinely belong to it (any <brand>.<tld> also counts as genuine)
BRANDS = {
    "microsoft": {"microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "hotmail.com", "msn.com",
                  "microsoftonline.com", "onmicrosoft.com", "sharepoint.com", "windows.com", "azure.com", "skype.com",
                  "bing.com", "xbox.com", "microsoft365.com", "office.net", "outlook.office365.com"},
    "outlook": {"outlook.com", "office365.com", "office.com", "microsoft.com", "live.com"},
    "google": {"google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "gmail.com", "goo.gl", "g.page",
               "youtube.com", "withgoogle.com", "google.org", "googlemail.com", "googlegroups.com", "appspot.com"},
    "apple": {"apple.com", "icloud.com", "mzstatic.com", "me.com"},
    "amazon": {"amazon.com", "amazonaws.com", "amazonses.com", "awsapps.com", "amazon.jobs", "a2z.com", "amzn.to", "amzn.com"},
    "paypal": {"paypal.com", "paypalobjects.com", "paypal.me", "paypal-communication.com"},
    "netflix": {"netflix.com", "nflxso.net", "nflximg.net"},
    "dhl": {"dhl.com", "dhl.de", "dpdhl.com"},
    "fedex": {"fedex.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com", "dropboxusercontent.com"},
    "facebook": {"facebook.com", "fb.com", "facebookmail.com", "fbcdn.net", "meta.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "linkedin": {"linkedin.com", "licdn.com", "lnkd.in"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "binance": {"binance.com", "binance.us"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "ledger": {"ledger.com"},
    "adobe": {"adobe.com", "adobesign.com", "adobelogin.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "chase": {"chase.com", "jpmorgan.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "americanexpress": {"americanexpress.com", "aexp.com"},
    "usps": {"usps.com", "usps.gov"},
    "ups": {"ups.com"},
}
SHORT_BRANDS = {b for b in BRANDS if len(b) <= 5}  # must match a whole word, so 'purchase' never matches 'chase'
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})

GENERIC_NAME_WORDS = {"team", "support", "service", "services", "security", "account", "accounts", "noreply", "newsletter",
                      "billing", "alerts", "alert", "notifications", "notification", "update", "updates", "customer",
                      "online", "official", "department", "center", "centre", "mail", "email", "sales", "marketing",
                      "store", "admin", "manager", "helpdesk", "desk", "message", "messages", "reply", "invoice"}

LURES = {
    "Credential/urgency language": (3, [
        "urgent", "immediately", "verify your account", "verify your identity", "account suspended", "suspended",
        "confirm your password", "confirm your identity", "unusual activity", "unusual sign", "action required",
        "within 24 hours", "click here", "update your payment", "security alert", "wire transfer", "password expires",
        "reset your password", "login to continue", "sign in to continue", "restore access", "account will be closed",
        "avoid suspension", "final notice", "last warning", "act now", "limited access", "expires today",
        "blocked", "locked"]),
    "Prize/survey bait": (3, [
        "you have won", "you've won", "you won", "congratulations", "claim your prize", "winner", "lottery", "gift card",
        "free iphone", "survey", "reward", "gewonnen", "gratis", "winactie", "kans op", "je prijs", "ganhou", "prêmio",
        "premio", "sorteio", "gagné", "cadeau", "gewinn", "umfrage", "ganaste", "felicidades"]),
    "Crypto lure": (3, [
        "seed phrase", "recovery phrase", "airdrop", "wallet", "connect your wallet", "claim your tokens", "metamask",
        "private key", "staking", "device verification", "allocation program", "token distribution"]),
    "Delivery/payment lure": (3, [
        "package could not be delivered", "customs fee", "delivery fee", "unpaid toll", "pedágio", "pedagio",
        "parcel", "redelivery", "tracking number", "pakket", "paket", "colis", "encomenda", "outstanding payment",
        "overdue", "unpaid", "refund"]),
    "Account-takeover wording (non-English)": (3, [
        "su cuenta", "tu cuenta", "cuenta suspendida", "verifica tu", "conta bloqueada", "conta suspensa", "regularize",
        "vérifiez votre compte", "votre compte", "compte suspendu", "ihr konto", "konto gesperrt", "bestätigen sie",
        "bevestig je", "je account", "geblokkeerd", "bloqueamos", "acesso suspeito", "acceso sospechoso"]),
}
BODY_LURE_CAP = 20
FINANCE_WORDS = ("invoice", "payment", "remittance", "purchase order", "wire", "bank details", "overdue", "statement",
                 "receipt", "refund", "factura", "fatura", "rechnung", "facture")

ADDR_RE = re.compile(r"[\w.+'-]+@([\w-]+(?:\.[\w-]+)+)")
IPV4_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u2060\ufeff]")
TAGNAME_RE = re.compile(r"/?([a-z][a-z0-9]*)")
HEADER_CAP = 2000  # characters of any single header we inspect (RFC 5322 lines are 998 max)
LINK_TEXT_CAP = 300


# ---------------------------------------------------------------- helpers
def _domain(addr: str) -> str:
    addr = (addr or "")[:HEADER_CAP]
    a = parseaddr(addr)[1]
    if "@" in a:
        return a.rsplit("@", 1)[-1].lower().strip(".")
    m = ADDR_RE.search(addr or "")  # malformed header: fall back to a regex
    return m.group(1).lower() if m else ""


def _netloc(url: str) -> str:
    try:
        return urlparse(url).netloc or ""
    except ValueError:  # e.g. "http://[bad-ipv6"
        return ""


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def base_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    if not host or IPV4_RE.fullmatch(host) or ":" in host:
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def reg_label(host: str) -> str:
    return base_domain(host).split(".")[0]


def _norm(s: str) -> str:
    """Undo font/combining-mark disguises: NFKD maps fancy letters to plain ones, then marks/format chars are dropped."""
    return "".join(c for c in unicodedata.normalize("NFKD", s or "") if unicodedata.category(c) not in ("Mn", "Me", "Cf"))


def _obfuscated(s: str) -> bool:
    """Display names built from combining marks, invisible characters or math-alphabet letters to dodge brand filters."""
    marks = sum(1 for c in s if unicodedata.category(c) in ("Mn", "Me", "Cf"))
    fancy = sum(1 for c in s if 0x1D400 <= ord(c) <= 0x1D7FF)
    return marks >= 3 or fancy >= 3


def _tokens(s: str) -> list:
    return [t for t in re.split(r"[^a-z0-9]+", _norm(s).lower()) if t]


def _brand_hits(tokens: list) -> set:
    hits = set()
    for cand in (tokens, [t.translate(LEET) for t in tokens]):  # also catches micros0ft, paypa1, g00gle
        joined = "".join(cand)
        for b in BRANDS:
            if (b in cand) if b in SHORT_BRANDS else (b in joined):
                hits.add(b)
    return hits


def _is_genuine(host: str, brand: str) -> bool:
    return base_domain(host) in BRANDS[brand] or reg_label(host) == brand


def scan_html(html: str):
    """One linear pass over HTML -> (visible text, set of tag names, has meta-refresh). Never backtracks, so a hostile
    page of a few hundred KB of '<<<<' or unclosed tags cannot stall the scan."""
    html = html[:400_000]
    low = html.lower()
    text, tags, refresh = [], set(), False
    i, n = 0, len(html)
    while i < n:
        j = html.find("<", i)
        if j < 0:
            text.append(html[i:])
            break
        text.append(html[i:j])
        k = html.find(">", j + 1)
        if k < 0:
            break  # unclosed tag: ignore the rest
        m = TAGNAME_RE.match(low, j + 1)
        name = m.group(1) if m else ""
        i = k + 1
        text.append(" ")
        if not name:
            continue
        tags.add(name)
        if name == "meta" and "refresh" in low[j:k]:
            refresh = True
        if name in ("script", "style"):
            end = low.find("</" + name, k)
            if end < 0:
                break
            close = low.find(">", end)
            i = close + 1 if close >= 0 else n
    return _html.unescape("".join(text)), tags, refresh


def _visible_text(pe: ParsedEmail, plain_html: str) -> str:
    return "\n".join(((pe.subject or "")[:HEADER_CAP], pe.body_text or "", plain_html))[:400_000]


# ---------------------------------------------------------------- headers
def check_headers(pe: ParsedEmail) -> list:
    out = []
    hdr = {k.lower(): v for k, v in pe.headers}
    auth = " ".join(v for k, v in pe.headers if k.lower() in ("authentication-results", "received-spf", "arc-authentication-results")).lower()

    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if not m:
            out.append(Finding("low", "Headers", f"No {mech.upper()} result found in headers", 3))
            continue
        res = m.group(1)
        if res == "fail":
            out.append(Finding("high", "Headers", f"{mech.upper()} result: fail", 15))
        elif res == "softfail":
            out.append(Finding("medium", "Headers", f"{mech.upper()} result: softfail", 8))
        elif res in ("none", "temperror", "permerror", "neutral", "policy"):
            out.append(Finding("low", "Headers", f"{mech.upper()} result: {res} (sender not verified)", 3))
        else:
            out.append(Finding("info", "Headers", f"{mech.upper()} result: {res}", 0))

    sender = (pe.sender or "")[:HEADER_CAP]
    from_d = _domain(sender)
    if sender and not parseaddr(sender)[1]:
        out.append(Finding("medium", "Headers", f"Malformed From header: {sender[:60]}", 8))
    if pe.reply_to and from_d and _domain(pe.reply_to) and base_domain(_domain(pe.reply_to)) != base_domain(from_d):
        out.append(Finding("high", "Headers", f"Reply-To domain ({_domain(pe.reply_to)}) differs from From domain ({from_d})", 15))
    rp = _domain(pe.return_path)
    if rp and "." in rp and from_d and base_domain(rp) != base_domain(from_d):
        out.append(Finding("low", "Headers", f"Return-Path domain ({rp}) differs from From domain ({from_d})", 4))

    name = (parseaddr(sender)[0] or sender.split("<")[0])[:200]
    toks = _tokens(name)
    if _obfuscated(name):
        out.append(Finding("medium", "Headers", f"Display name is disguised with odd Unicode characters: {_norm(name)[:40]}", 8))
    if from_d:
        for b in sorted(_brand_hits(toks)):
            if not _is_genuine(from_d, b):
                out.append(Finding("high", "Headers", f"Display name claims '{b}' but sender domain is {from_d}", 15))
                break
        else:
            out += _lookalike_sender(toks, from_d)
    if from_d and not from_d.isascii():
        out.append(Finding("high", "Headers", f"Sender domain uses non-ASCII lookalike characters: {from_d}", 20))
    if "xn--" in from_d:
        out.append(Finding("high", "Headers", f"Sender domain uses punycode: {from_d}", 15))
    if "x-mailer" in hdr and any(t in hdr["x-mailer"].lower() for t in ("phpmailer", "swiftmailer")):
        out.append(Finding("low", "Headers", f"Bulk-mailer library in X-Mailer: {hdr['x-mailer']}", 3))
    return out


def _signature_words(toks: list) -> list:
    return [t for t in toks if len(t) >= 5 and t.isalpha() and t not in GENERIC_NAME_WORDS]


def _joins(toks: list) -> set:
    return {"".join(toks[i:j]) for i in range(len(toks)) for j in range(i + 1, len(toks) + 1)}


def _lookalike_sender(toks: list, from_d: str) -> list:
    """'COLDCARD <info@coldcardpressrelease.com>': the domain embeds the display name plus extra words."""
    label = reg_label(from_d).replace("-", "")
    joins = _joins(toks)
    for t in _signature_words(toks):
        if t in label and label not in joins and label != t:
            return [Finding("medium", "Headers", f"Sender domain {from_d} embeds '{t}' plus extra words (possible look-alike)", 8)]
    return []


# ---------------------------------------------------------------- links
def check_link(href: str, text: str) -> list:
    out = []
    host = _host(href)
    if not host:
        if href.strip().lower().startswith(("javascript:", "data:", "vbscript:")):
            out.append(Finding("high", "Links", f"Link uses a script/data URL: {href[:60]}", 15))
        return out
    if IPV4_RE.fullmatch(host):
        out.append(Finding("high", "Links", f"URL uses a raw IP address: {href[:80]}", 15))
    if host in SHORTENERS:
        out.append(Finding("medium", "Links", f"URL shortener hides destination: {host}", 8))
    if "xn--" in host:
        out.append(Finding("high", "Links", f"Punycode (lookalike) domain: {host}", 15))
    elif not host.isascii():
        out.append(Finding("high", "Links", f"Non-ASCII lookalike domain: {host}", 15))
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        out.append(Finding("medium", "Links", f"Suspicious TLD: {host}", 6))
    if href.lower().startswith("http://"):
        out.append(Finding("low", "Links", f"Unencrypted HTTP link: {host}", 3))
    if host.count(".") >= 4:
        out.append(Finding("low", "Links", f"Unusually deep subdomain chain: {host}", 3))
    if "@" in _netloc(href):
        out.append(Finding("high", "Links", f"Credentials-style '@' in URL hides real host: {href[:80]}", 15))
    for b in sorted(_brand_hits(_tokens(host))):
        if not _is_genuine(host, b):
            out.append(Finding("medium", "Links", f"Domain {host} uses the name '{b}' but is not {b}'s domain", 8))
            break
    t = text.strip().lower()[:LINK_TEXT_CAP]
    m = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", t)
    if m and t.startswith(("http", "www.")) and base_domain(m.group(1)) != base_domain(host):
        out.append(Finding("high", "Links", f"Link text shows {m.group(1)} but goes to {host}", 20))
    return out


def check_context(pe: ParsedEmail) -> list:
    """Checks that need both the sender and the links."""
    out = []
    sender = (pe.sender or "")[:HEADER_CAP]
    from_d = _domain(sender)
    name = (parseaddr(sender)[0] or sender.split("<")[0])[:200]
    toks = _tokens(name)
    # 4-letter names ('Lido') count too, but only as a whole word of the link's domain, never as part of a longer one
    sig = _signature_words(toks) + [t for t in toks if len(t) == 4 and t.isalpha() and t not in GENERIC_NAME_WORDS]
    if not (from_d and sig):
        return out
    joins, sender_base = _joins(toks), base_domain(from_d)
    seen = set()
    for l in pe.links[:200]:
        host = _host(l.href)
        if not host or host in seen or base_domain(host) == sender_base:
            continue
        seen.add(host)
        label = reg_label(host).replace("-", "")
        flat = host.replace("-", "").replace(".", "")
        words = set(re.split(r"[^a-z0-9]+", host))
        for t in sig:
            if (t in words if len(t) < 5 else t in flat) and label not in joins and label != t:
                out.append(Finding("medium", "Links", f"Link domain {host} borrows the sender's name '{t}' but is a different domain", 8))
                break
    return out


# ---------------------------------------------------------------- body
def check_body(pe: ParsedEmail) -> list:
    plain, tags, refresh = scan_html(pe.body_html or "")
    text = _visible_text(pe, plain).lower()
    out, budget = [], BODY_LURE_CAP
    for group, (per_hit, phrases) in LURES.items():
        hits = [w for w in phrases if w in text]
        if hits:
            pts = min(len(hits) * per_hit, 9, budget)
            budget -= pts
            out.append(Finding("medium" if len(hits) > 2 else "low", "Body", f"{group}: {', '.join(hits[:5])}", pts))

    from_base = base_domain(_domain(pe.sender))
    if from_base in FREEMAIL and any(w in text for w in FINANCE_WORDS):
        out.append(Finding("medium", "Body", f"Money/invoice wording from a free email address ({from_base})", 10))

    if tags & {"form", "input"}:
        out.append(Finding("high", "Body", "HTML body contains a form/input (possible credential harvesting)", 15))
    if "script" in tags:
        out.append(Finding("medium", "Body", "HTML body contains <script>", 8))
    if refresh:
        out.append(Finding("medium", "Body", "HTML body auto-redirects (meta refresh)", 8))
    if len(ZERO_WIDTH_RE.findall(f"{(pe.subject or '')[:HEADER_CAP]}{(pe.body_text or '')[:200_000]}{plain[:200_000]}")) > 20:
        out.append(Finding("medium", "Body", "Many invisible characters (a trick to dodge spam filters)", 6))
    return out
