from dataclasses import dataclass, field


@dataclass
class Finding:
    severity: str  # info | low | medium | high
    category: str
    message: str
    points: int = 0


@dataclass
class Attachment:
    filename: str
    data: bytes
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    size: int = 0
    findings: list = field(default_factory=list)
    intel: dict = field(default_factory=dict)


@dataclass
class Link:
    href: str
    text: str = ""
    findings: list = field(default_factory=list)
    intel: dict = field(default_factory=dict)


@dataclass
class ParsedEmail:
    source: str
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    headers: list = field(default_factory=list)  # [(name, value)]
    body_text: str = ""
    body_html: str = ""
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    notes: list = field(default_factory=list)  # [(severity, message, points)] parser observations


@dataclass
class Report:
    email: ParsedEmail
    findings: list = field(default_factory=list)
    static_findings: list = field(default_factory=list)  # findings before online lookups
    intel: list = field(default_factory=list)  # [(target, results)] from online lookups
    score: int = 0
    verdict: str = "Low"
