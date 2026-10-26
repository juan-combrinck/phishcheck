"""Synthetic LEGITIMATE emails used to check for false positives. Each should score Low (< 20)."""
from email.message import EmailMessage

AUTH_PASS = "mx.example.com; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; dmarc=pass header.from={d}"


def _mail(sender, subject, text, html=None, reply_to=None, domain=None, auth=True, attach=None):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "me@example.org"
    m["Subject"] = subject
    m["Date"] = "Mon, 12 Oct 2026 09:30:00 +0000"
    if reply_to:
        m["Reply-To"] = reply_to
    if auth:
        d = domain or sender.split("@")[-1].strip(">")
        m["Authentication-Results"] = AUTH_PASS.format(d=d)
        m["Return-Path"] = f"<bounce@{d}>"
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    if attach:
        name, data, mt, st = attach
        m.add_attachment(data, maintype=mt, subtype=st, filename=name)
    return bytes(m)


def build() -> dict:
    out = {}
    out["github_notification"] = _mail(
        "GitHub <notifications@github.com>", "[repo] Pull request #42: fix typo",
        "A new comment was posted. View it on GitHub: https://github.com/acme/repo/pull/42",
        '<p>New comment. <a href="https://github.com/acme/repo/pull/42">View it on GitHub</a></p>')
    out["microsoft_receipt"] = _mail(
        "Microsoft <microsoft-noreply@microsoft.com>", "Your Microsoft 365 receipt",
        "Thanks for your purchase. Manage your subscription at https://account.microsoft.com/services",
        '<p>Thanks! <a href="https://account.microsoft.com/services">Manage subscription</a></p>')
    out["colleague_plain"] = _mail(
        "Sam Rivera <sam@example.org>", "Lunch tomorrow?", "Hey, are we still on for lunch tomorrow at 12? - Sam",
        domain="example.org")
    out["meeting_invite"] = _mail(
        "Priya Shah <priya@example.org>", "Invitation: Q4 planning @ Tue 14:00",
        "Join: https://teams.microsoft.com/l/meetup-join/abc123\nAgenda attached.", domain="example.org",
        attach=("agenda.pdf", b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF", "application", "pdf"))
    out["newsletter"] = _mail(
        "The Weekly <news@theweekly.com>", "This week: 5 reads worth your time",
        "Read online: https://www.theweekly.com/issue/412\nUnsubscribe: https://www.theweekly.com/unsub",
        '<p><a href="https://www.theweekly.com/issue/412">Read online</a> | '
        '<a href="https://www.theweekly.com/unsub">Unsubscribe</a></p>')
    out["bank_statement_real"] = _mail(
        "Acme Bank <statements@acmebank.com>", "Your October statement is ready",
        "Your statement is available in online banking: https://www.acmebank.com/login",
        '<p>Your statement is ready. <a href="https://www.acmebank.com/login">Sign in</a></p>')
    out["invoice_docx_clean"] = _mail(
        "Accounts <billing@vendor-co.com>", "Invoice 2026-118", "Please find invoice 2026-118 attached. Thank you.",
        attach=("invoice-2026-118.docx", b"PK\x03\x04" + b"\x00" * 60, "application",
                "vnd.openxmlformats-officedocument.wordprocessingml.document"))
    out["amazon_shipping"] = _mail(
        "Amazon <shipment-tracking@amazon.com>", "Your package has shipped",
        "Track it: https://www.amazon.com/progress-tracker/package/ref=abc",
        '<p><a href="https://www.amazon.com/progress-tracker/package/ref=abc">Track package</a></p>')
    out["google_security_alert"] = _mail(
        "Google <no-reply@accounts.google.com>", "Security alert",
        "Your Google Account was just signed in to from a new Windows device. If this was you, you don't need to do "
        "anything. If not, check activity: https://myaccount.google.com/notifications",
        '<p>Security alert. <a href="https://myaccount.google.com/notifications">Check activity</a></p>')
    out["dhl_dutch_parcel"] = _mail(
        "DHL Express <noreply@dhl.com>", "Uw pakket is onderweg",
        "Uw pakket wordt morgen bezorgd. Volg uw zending: https://www.dhl.com/nl-nl/home/tracking.html",
        '<p>Volg uw zending: <a href="https://www.dhl.com/nl-nl/home/tracking.html">tracking</a></p>')
    out["paypal_receipt"] = _mail(
        "PayPal <service@paypal.com>", "Receipt for your payment to Acme Store",
        "You sent a payment of 24.00 EUR. View details: https://www.paypal.com/activity/payment/1AB",
        '<p><a href="https://www.paypal.com/activity/payment/1AB">View details</a></p>')
    out["zoom_invite"] = _mail(
        "Zoom <no-reply@zoom.us>", "Reminder: Standup starts in 15 minutes",
        "Join: https://us02web.zoom.us/j/123456789", '<p><a href="https://us02web.zoom.us/j/123456789">Join</a></p>')
    out["mercadolivre_pt"] = _mail(
        "Mercado Livre <noreply@mercadolivre.com.br>", "Seu pedido foi enviado",
        "Seu pedido chegara em 3 dias. Acompanhe: https://www.mercadolivre.com.br/compras",
        '<p><a href="https://www.mercadolivre.com.br/compras">Acompanhar</a></p>')
    out["linkedin_digest"] = _mail(
        "LinkedIn <jobs-listings@linkedin.com>", "5 new jobs for you",
        "See jobs: https://www.linkedin.com/jobs/view/123", '<p><a href="https://www.linkedin.com/jobs/view/123">See jobs</a></p>')
    out["personal_gmail_friend"] = _mail(
        "Alex Moreno <alex.moreno@gmail.com>", "photos from the weekend", "Hey! Here are the photos, ping me when you've seen them.",
        domain="gmail.com")
    out["company_invoice_reminder"] = _mail(
        "Finance <finance@vendor-co.com>", "Reminder: invoice 2026-118 due Friday",
        "A friendly reminder that invoice 2026-118 is due on Friday. Pay via your usual portal: https://portal.vendor-co.com/pay",
        '<p><a href="https://portal.vendor-co.com/pay">Pay</a></p>')
    return out
