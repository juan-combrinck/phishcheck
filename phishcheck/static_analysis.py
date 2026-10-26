"""Static analysis of attachments. Files are only read as bytes, never executed or opened."""
import io
import math
import re
import zipfile
from pathlib import Path

from collections import Counter

from .checks import scan_html
from .models import Attachment, Finding

DANGEROUS_EXT = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
                 ".hta", ".jar", ".msi", ".dll", ".lnk", ".iso", ".img", ".reg", ".cpl", ".chm", ".appx",
                 ".url", ".xll", ".wll", ".vhd", ".vhdx", ".gadget", ".msc", ".scf", ".inf", ".ocx", ".diagcab", ".msix",
                 ".appxbundle", ".application", ".settingcontent-ms", ".sct", ".ws", ".psc1"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xlsb", ".ppam", ".sldm"}
OFFICE_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".dot", ".xlt"} | MACRO_EXT
DOC_LURE_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
HTML_EXT = {".html", ".htm", ".xhtml", ".shtml", ".svg", ".mht", ".mhtml"}
ONENOTE_MAGIC = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
HTML_STARTS = (b"<!doctype html", b"<html", b"<svg", b"<head", b"<body", b"<script", b"<?xml", b"<meta", b"<form")

MAGIC = [
    (ONENOTE_MAGIC, "OneNote"),
    (b"MZ", "Windows executable (PE)"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP/OOXML container"),
    (b"\xd0\xcf\x11\xe0", "OLE2 (legacy Office)"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf", "7-Zip archive"),
    (b"{\\rtf", "RTF"),
    (b"L\x00\x00\x00\x01\x14\x02", "Windows shortcut (LNK)"),
]


def entropy(data: bytes) -> float:
    data = data[:1_000_000]  # a sample is plenty, and keeps huge attachments fast
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def sniff(data: bytes) -> str:
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    head = data[:300].lstrip(b"\xef\xbb\xbf \t\r\n").lower()  # skip a BOM / leading whitespace
    if head.startswith(HTML_STARTS):
        return "HTML/SVG"
    return "unknown"


def analyze(att: Attachment):
    f = att.findings
    name = att.filename
    ext = Path(name).suffix.lower()
    kind = sniff(att.data)

    f.append(Finding("info", "Attachment", f"{name}: {att.size} bytes, detected type: {kind}", 0))

    if ext in DANGEROUS_EXT:
        f.append(Finding("high", "Attachment", f"{name}: executable/script file type ({ext})", 25))
    if ext in MACRO_EXT:
        f.append(Finding("high", "Attachment", f"{name}: macro-enabled Office file ({ext})", 20))
    parts = name.lower().split(".")
    if len(parts) >= 3 and "." + parts[-1] in DANGEROUS_EXT and "." + parts[-2] in DOC_LURE_EXT | OFFICE_EXT:
        f.append(Finding("high", "Attachment", f"{name}: double extension disguises an executable", 25))
    if re.search(r"[‮‭]", name):
        f.append(Finding("high", "Attachment", f"{name}: right-to-left override character in filename", 25))
    if kind.startswith("Windows executable") and ext != ".exe" and ext not in DANGEROUS_EXT:
        f.append(Finding("high", "Attachment", f"{name}: contains a Windows executable but extension is {ext or 'none'}", 25))
    if ext == ".pdf" and kind != "PDF" and att.data:
        f.append(Finding("medium", "Attachment", f"{name}: extension says PDF but content is {kind}", 12))

    e = entropy(att.data)
    if e > 7.5 and att.size > 4096 and kind not in ("ZIP/OOXML container", "RAR archive", "7-Zip archive"):
        f.append(Finding("medium", "Attachment", f"{name}: very high entropy ({e:.2f}), possibly packed/encrypted", 8))

    try:
        if kind == "Windows executable (PE)":
            _pe(att)
        elif kind == "HTML/SVG" or ext in HTML_EXT:
            _html(att, ext)
        elif kind == "OneNote" or ext in (".one", ".onepkg"):
            _onenote(att)
        elif kind == "PDF":
            _pdf(att)
        elif kind.startswith("OLE2") or kind.startswith("ZIP") or kind == "RTF":
            if kind.startswith("ZIP") and ext not in OFFICE_EXT:
                _zip(att)
            else:
                _office(att)
    except Exception as exc:  # analysis must never crash the app
        f.append(Finding("info", "Attachment", f"{name}: static analysis error: {exc}", 0))


def _html(att: Attachment, ext: str):
    """HTML / SVG attachments: the favourite carrier for fake login pages and 'HTML smuggling' (JavaScript that builds
    a malware file in the victim's browser). Read as text only, never rendered."""
    f, name = att.findings, att.filename
    text = att.data[:2_000_000].decode("utf-8", "replace")
    low = text.lower()
    _, tags, refresh = scan_html(text)
    f.append(Finding("medium", "Attachment", f"{name}: HTML attachment (opens in the browser; a common phishing/malware carrier)", 8))
    if "form" in tags and ("type=\"password\"" in low or "type='password'" in low or "type=password" in low):
        f.append(Finding("high", "Attachment", f"{name}: contains a password/login form (credential harvesting page)", 20))
    elif tags & {"form", "input"}:
        f.append(Finding("medium", "Attachment", f"{name}: contains a form", 8))
    if re.search(r"action\s*=\s*[\"']?https?://", low):
        f.append(Finding("medium", "Attachment", f"{name}: form posts data to an external site", 8))
    has_blob = "new blob" in low or "createobjecturl" in low or "msssaveblob" in low
    has_decode = "atob(" in low or "fromcharcode" in low or "unescape(" in low
    if has_blob and (has_decode or "download" in low):
        f.append(Finding("high", "Attachment", f"{name}: HTML smuggling (JavaScript builds and drops a file on the victim's PC)", 25))
    elif has_decode and ("eval(" in low or "document.write(" in low):
        f.append(Finding("high", "Attachment", f"{name}: obfuscated JavaScript (decode + eval)", 15))
    if ext == ".svg" and "script" in tags:
        f.append(Finding("high", "Attachment", f"{name}: SVG image contains a script (can redirect or run code)", 15))
    if re.search(r"(window\.|document\.)?location(\.href|\.replace|\.assign)?\s*=\s*[\"']https?://", low):
        f.append(Finding("medium", "Attachment", f"{name}: script redirects the browser to another site", 8))
    if refresh:
        f.append(Finding("medium", "Attachment", f"{name}: auto-redirects (meta refresh)", 6))
    if "data:text/html" in low:
        f.append(Finding("medium", "Attachment", f"{name}: embeds a data:text/html page", 8))


def _onenote(att: Attachment):
    """OneNote files can carry embedded scripts/executables that run when the victim double-clicks a fake button."""
    f, name = att.findings, att.filename
    f.append(Finding("medium", "Attachment", f"{name}: OneNote attachment (used to deliver malware through embedded files)", 12))
    low = att.data[:5_000_000].lower()
    if b"this program cannot be run in dos mode" in low:
        f.append(Finding("high", "Attachment", f"{name}: OneNote file contains an embedded Windows executable", 25))
    elif any(t in low for t in (b"powershell", b"cmd.exe", b"wscript", b"mshta", b"<hta:application", b".vbs", b".bat")):
        f.append(Finding("high", "Attachment", f"{name}: OneNote file references script launchers (powershell/cmd/wscript/mshta)", 20))


def _pe(att: Attachment):
    import pefile

    pe = pefile.PE(data=att.data, fast_load=False)
    f = att.findings
    suspicious_apis = {b"VirtualAlloc", b"VirtualProtect", b"WriteProcessMemory", b"CreateRemoteThread",
                       b"URLDownloadToFile", b"WinExec", b"ShellExecute", b"IsDebuggerPresent",
                       b"LoadLibraryA", b"GetProcAddress", b"InternetOpenUrl", b"RegSetValueEx", b"CryptEncrypt"}
    found = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name and imp.name.rstrip(b"AW") in {s.rstrip(b"AW") for s in suspicious_apis}:
                found.add(imp.name.decode(errors="replace"))
    if found:
        f.append(Finding("medium", "Attachment", f"{att.filename}: suspicious imports: {', '.join(sorted(found)[:10])}", 10))
    for s in pe.sections:
        sname = s.Name.rstrip(b"\x00").decode(errors="replace")
        if s.get_entropy() > 7.2:
            f.append(Finding("medium", "Attachment", f"{att.filename}: high-entropy section {sname} (packed?)", 8))
        if sname.lower().startswith((".upx", "upx")):
            f.append(Finding("medium", "Attachment", f"{att.filename}: UPX-packed", 8))
    if not pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size:
        f.append(Finding("low", "Attachment", f"{att.filename}: not digitally signed", 3))


def _pdf(att: Attachment):
    raw = att.data
    f = att.findings
    for tag, label, pts in [(b"/JavaScript", "embedded JavaScript", 15), (b"/JS", "embedded JavaScript", 15),
                            (b"/OpenAction", "auto-run action on open", 10), (b"/Launch", "launch-program action", 20),
                            (b"/EmbeddedFile", "embedded file", 10), (b"/URI", "URI action", 3)]:
        if tag in raw:
            f.append(Finding("high" if pts >= 15 else "medium" if pts >= 10 else "low", "Attachment",
                             f"{att.filename}: PDF contains {label} ({tag.decode()})", pts))


def _office(att: Attachment):
    import warnings

    with warnings.catch_warnings():  # oletools' own pyparsing deprecation noise
        warnings.simplefilter("ignore")
        from oletools.olevba import VBA_Parser

    f = att.findings
    if att.data.startswith(b"{\\rtf") and b"\\objdata" in att.data:
        f.append(Finding("high", "Attachment", f"{att.filename}: RTF with embedded OLE object (exploit vector)", 20))
    vp = VBA_Parser(att.filename, data=att.data)
    try:
        if vp.detect_vba_macros():
            f.append(Finding("high", "Attachment", f"{att.filename}: contains VBA macros", 20))
            for kind, kw, desc in vp.analyze_macros():
                if kind in ("AutoExec", "Suspicious"):
                    f.append(Finding("high" if kind == "AutoExec" else "medium", "Attachment",
                                     f"{att.filename}: macro {kind}: {kw} ({desc[:80]})", 8))
        if vp.type == "OpenXML":
            with zipfile.ZipFile(io.BytesIO(att.data)) as z:
                names = z.namelist()
                if any("externalLinks" in n or "oleObject" in n or "embeddings/" in n for n in names):
                    f.append(Finding("medium", "Attachment", f"{att.filename}: embedded/external OLE objects", 10))
                for n in names:
                    if n.endswith(".rels"):
                        rels = z.read(n).decode("utf-8", "ignore")
                        if 'TargetMode="External"' in rels and re.search(r'Target="https?://', rels):
                            f.append(Finding("high", "Attachment", f"{att.filename}: remote template/resource link in {n} (template injection)", 20))
                            break
    finally:
        vp.close()


def _zip(att: Attachment):
    f = att.findings
    with zipfile.ZipFile(io.BytesIO(att.data)) as z:
        infos = z.infolist()
        if any(i.flag_bits & 0x1 for i in infos):
            f.append(Finding("high", "Attachment", f"{att.filename}: password-protected archive (evades scanners)", 15))
        bad = [i.filename for i in infos if Path(i.filename).suffix.lower() in DANGEROUS_EXT]
        if bad:
            f.append(Finding("high", "Attachment", f"{att.filename}: archive contains executables/scripts: {', '.join(bad[:5])}", 25))
        f.append(Finding("info", "Attachment", f"{att.filename}: archive holds {len(infos)} file(s)", 0))
