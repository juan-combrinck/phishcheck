"""The single 'Email Check' folder every email lives in."""
import re
import shutil
from datetime import datetime
from email import policy
from email.parser import BytesHeaderParser
from email.utils import parsedate_to_datetime
from pathlib import Path

from . import intel

EXTS = {".eml", ".msg"}


def mail_folder() -> Path:
    custom = intel.load_config().get("MAIL_FOLDER")
    p = Path(custom) if custom else Path.home() / "Desktop" / "Email Check"
    p.mkdir(parents=True, exist_ok=True)
    return p


def list_mail(folder: Path) -> list:
    files = [f for f in folder.iterdir() if f.is_file() and f.suffix.lower() in EXTS]
    return sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)


_peek_cache = {}


def _short_date(raw) -> str:
    try:
        return parsedate_to_datetime(str(raw)).strftime("%d %b %Y")
    except (TypeError, ValueError):
        return ""


def peek(path: Path) -> dict:
    """Cheap subject/sender/date for the mailbox list (headers only, cached by mtime)."""
    key = (str(path), path.stat().st_mtime)
    if key in _peek_cache:
        return _peek_cache[key]
    info = {"subject": path.stem, "sender": "", "date": ""}
    try:
        if path.suffix.lower() == ".eml":
            with open(path, "rb") as f:
                msg = BytesHeaderParser(policy=policy.default).parse(f)
            info = {"subject": str(msg.get("Subject", "")) or path.stem, "sender": str(msg.get("From", "")),
                    "date": _short_date(msg.get("Date"))}
        else:
            import extract_msg

            m = extract_msg.Message(str(path))
            info = {"subject": m.subject or path.stem, "sender": m.sender or "", "date": str(m.date or "")[:10]}
            m.close()
    except Exception:
        pass
    _peek_cache[key] = info
    return info


def add_to_folder(src: str, folder: Path) -> Path:
    """Copy an email into the Email Check folder (if it isn't already there) and return its new path."""
    src = Path(src)
    if src.parent.resolve() == folder.resolve():
        return src
    dest = folder / src.name
    n = 1
    while dest.exists():
        dest = folder / f"{src.stem} ({n}){src.suffix}"
        n += 1
    shutil.copy2(src, dest)
    return dest


def safe_name(text: str, limit=60) -> str:
    return re.sub(r'[\/:*?"<>|\r\n\t]+', " ", text or "").strip()[:limit] or "no subject"


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")
