import email
import hashlib
import re
from email import policy
from html.parser import HTMLParser
from pathlib import Path

from .models import Attachment, Link, ParsedEmail

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']{1,2000})""", re.I)
MAX_FILE = 80_000_000  # bytes read from one email
MAX_PARTS = 2000  # MIME parts walked
MAX_ATTACHMENTS = 200
MAX_LINKS = 500
MAX_TEXT = 2_000_000
HTML_FOR_LINKS = 600_000


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _hash(att: Attachment):
    att.size = len(att.data)
    att.md5 = hashlib.md5(att.data).hexdigest()
    att.sha1 = hashlib.sha1(att.data).hexdigest()
    att.sha256 = hashlib.sha256(att.data).hexdigest()


def _safe(fn, default=None):
    """Hostile emails make Python's own header parser raise in odd places; one bad header must never stop a scan."""
    try:
        return fn()
    except Exception:
        return default


def _extract_links(pe: ParsedEmail):
    seen, known = set(), set()
    html = (pe.body_html or "")[:HTML_FOR_LINKS]
    if html:
        found = None
        try:
            ex = _LinkExtractor()
            ex.feed(html)
            ex.close()
            found = ex.links
        except Exception:  # HTMLParser can choke on deliberately broken markup: fall back to a simple regex
            found = [(m, "") for m in HREF_RE.findall(html)]
        for href, text in found:
            href = (href or "").strip()
            if href.lower().startswith(("http://", "https://")) and (href, text) not in seen and len(pe.links) < MAX_LINKS:
                seen.add((href, text))
                pe.links.append(Link(href=href[:4000], text=text[:300]))
    known = {l.href for l in pe.links}
    for url in URL_RE.findall((pe.body_text or "")[:HTML_FOR_LINKS]):
        if url not in known and len(pe.links) < MAX_LINKS:
            known.add(url)
            pe.links.append(Link(href=url[:4000]))


def _hdr(msg, name: str) -> str:
    try:
        v = msg.get(name, "")
        return str(v) if v is not None else ""
    except Exception:  # the policy-decoded value blew up (a stdlib bug on some malformed headers): use the raw one
        for k, raw in _safe(lambda: list(msg.raw_items()), []):
            if str(k).lower() == name.lower():
                return str(raw)
        return ""


def _all_headers(msg) -> list:
    out = []
    for k, raw in _safe(lambda: list(msg.raw_items()), []):
        value = _safe(lambda: str(msg.policy.header_fetch_parse(k, raw)))
        out.append((str(k), value if value is not None else str(raw)))
    return out


def _decode_text(part) -> str:
    payload = _safe(lambda: part.get_payload(decode=True), b"") or b""
    if not isinstance(payload, (bytes, bytearray)):
        return ""
    charset = _safe(part.get_content_charset) or "utf-8"
    try:
        return bytes(payload).decode(charset, "replace")
    except (LookupError, TypeError):  # e.g. charset="nonsense"
        return bytes(payload).decode("utf-8", "replace")


def _build(path: str, msg) -> ParsedEmail:
    pe = ParsedEmail(source=path)
    pe.subject = _hdr(msg, "Subject")
    pe.sender = _hdr(msg, "From")
    pe.reply_to = _hdr(msg, "Reply-To")
    pe.return_path = _hdr(msg, "Return-Path")
    pe.to = _hdr(msg, "To")
    pe.date = _hdr(msg, "Date")
    pe.headers = _all_headers(msg)
    texts, htmls, walked = [], [], 0
    for part in msg.walk():
        walked += 1
        if walked > MAX_PARTS:
            pe.notes.append(("medium", f"Unusually many MIME parts (stopped reading at {MAX_PARTS})", 5))
            break
        if _safe(part.is_multipart, False):
            continue
        ctype = _safe(part.get_content_type, "text/plain") or "text/plain"
        disposition = _safe(part.get_content_disposition) or ""
        filename = _safe(part.get_filename)
        if disposition == "attachment" or filename or not ctype.startswith("text/"):
            if len(pe.attachments) >= MAX_ATTACHMENTS:
                continue
            data = _safe(lambda: part.get_payload(decode=True), b"") or b""
            att = Attachment(filename=str(filename or "unnamed")[:300], data=bytes(data) if isinstance(data, (bytes, bytearray)) else b"")
            _hash(att)
            pe.attachments.append(att)
        elif ctype == "text/html":
            htmls.append(_decode_text(part))
        else:
            texts.append(_decode_text(part))
    pe.body_text = "\n".join(texts)[:MAX_TEXT]
    pe.body_html = "\n".join(htmls)[:MAX_TEXT]
    _extract_links(pe)
    return pe


def parse_eml(path: str) -> ParsedEmail:
    raw = Path(path).read_bytes()[:MAX_FILE]
    for i, pol in enumerate((policy.default, policy.compat32)):  # strict-ish first, then the most forgiving policy
        try:
            pe = _build(path, email.message_from_bytes(raw, policy=pol))
            if i:
                pe.notes.append(("low", "Email headers are malformed (read with the lenient fallback parser)", 4))
            return pe
        except Exception:  # includes RecursionError from absurdly nested MIME
            continue
    pe = ParsedEmail(source=path, subject=Path(path).stem, body_text=raw[:MAX_TEXT].decode("utf-8", "replace"))
    pe.notes.append(("medium", "Email structure could not be parsed at all (scanned as plain text)", 8))
    _extract_links(pe)
    return pe


def parse_msg(path: str) -> ParsedEmail:
    try:
        import extract_msg

        m = extract_msg.Message(path)
    except Exception as exc:
        raise ValueError(f"Could not read this .msg file: {exc}") from exc
    try:
        pe = ParsedEmail(source=path)
        pe.subject = _safe(lambda: m.subject) or ""
        pe.sender = _safe(lambda: m.sender) or ""
        pe.to = _safe(lambda: m.to) or ""
        pe.date = str(_safe(lambda: m.date) or "")
        raw = _safe(lambda: m.header)
        if raw:
            pe.headers = [(str(k), str(v)) for k, v in _safe(lambda: list(raw.items()), [])]
            pe.reply_to = str(_safe(lambda: raw.get("Reply-To")) or "")
            pe.return_path = str(_safe(lambda: raw.get("Return-Path")) or "")
        pe.body_text = str(_safe(lambda: m.body) or "")[:MAX_TEXT]
        html = _safe(lambda: m.htmlBody)
        if isinstance(html, bytes):
            html = html.decode("utf-8", "replace")
        pe.body_html = str(html or "")[:MAX_TEXT]
        for a in _safe(lambda: list(m.attachments), [])[:MAX_ATTACHMENTS]:
            data = _safe(lambda: a.data)
            name = _safe(lambda: a.longFilename) or _safe(lambda: a.shortFilename) or "unnamed"
            att = Attachment(filename=str(name)[:300], data=bytes(data) if isinstance(data, (bytes, bytearray)) else b"")
            _hash(att)
            pe.attachments.append(att)
        _extract_links(pe)
        return pe
    finally:
        _safe(m.close)


def parse_file(path: str) -> ParsedEmail:
    ext = Path(path).suffix.lower()
    if ext == ".eml":
        return parse_eml(path)
    if ext == ".msg":
        return parse_msg(path)
    raise ValueError(f"Unsupported file type: {ext} (use .eml or .msg)")
