"""Regression tests for problems found by the backtest and the fuzzer.   python -X utf8 -m unittest discover -s tests -v"""
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import ham  # noqa: E402
from phishcheck import analyzer, checks, intel, parser, static_analysis  # noqa: E402
from phishcheck.models import Attachment, Link, ParsedEmail  # noqa: E402


def msgs(findings):
    return " | ".join(f.message for f in findings)


class LinkChecks(unittest.TestCase):
    def test_genuine_brand_infrastructure_is_not_flagged(self):
        for url in ("https://storage.googleapis.com/x", "https://tenant.onmicrosoft.com/a", "https://www.google.com.br/",
                    "https://www.amazon.co.uk/x", "https://us02web.zoom.us/j/1", "https://login.microsoftonline.com/"):
            self.assertEqual([f for f in checks.check_link(url, "") if "uses the name" in f.message], [], url)

    def test_lookalike_brand_domains_are_flagged(self):
        for url in ("http://paypal.com.evil.ru/login", "http://micros0ft-login.top/a", "https://secure-paypa1.com/",
                    "https://www.google.com.br-1234convites@x.run.app", "http://login-dhl.xyz/"):
            self.assertTrue(checks.check_link(url, ""), url)

    def test_short_brand_words_match_whole_words_only(self):
        # 'purchase' contains 'chase', 'pineapple' contains 'apple': neither is a brand impersonation
        for url in ("https://purchase-orders.example.com/", "https://pineapple-farm.example.org/"):
            self.assertEqual([f for f in checks.check_link(url, "") if "uses the name" in f.message], [], url)

    def test_text_vs_destination_mismatch(self):
        f = checks.check_link("http://evil.example.net/x", "https://www.microsoft.com/verify")
        self.assertTrue(any("Link text shows" in x.message for x in f))

    def test_hostile_urls_never_raise(self):
        for url in ("http://[::1", "http://[v1.fe]/", "http://\x00/", "http://" + "a" * 100000, "javascript:alert(1)",
                    "http://a@b@c/", "", " ", "//x"):
            checks.check_link(url, "t" * 100000)

    def test_registered_domain_handles_two_part_suffixes(self):
        self.assertEqual(checks.base_domain("lido-airdrop.tcgprices.co.uk"), "tcgprices.co.uk")
        self.assertEqual(checks.base_domain("a.b.example.com"), "example.com")
        self.assertEqual(checks.base_domain("1.2.3.4"), "1.2.3.4")


class HeaderChecks(unittest.TestCase):
    def _pe(self, sender, **kw):
        return ParsedEmail(source="x", sender=sender, **kw)

    def test_obfuscated_display_name_still_matches_brand(self):
        sender = "D̲o̲c̲u̲S̲i̲g̲n̲ Notification <ib@avrahamprime.com>"
        self.assertIn("docusign", msgs(checks.check_headers(self._pe(sender))).lower())

    def test_math_font_domain_is_flagged(self):
        sender = "x <a@\U0001d5f2\U0001d5ff.nl>"
        self.assertIn("non-ASCII", msgs(checks.check_headers(self._pe(sender))))

    def test_genuine_sender_is_not_flagged(self):
        for s in ("Microsoft <no-reply@accounts.microsoft.com>", "Google <noreply@google.com>", "PayPal <service@paypal.com>"):
            self.assertEqual([f for f in checks.check_headers(self._pe(s)) if f.severity == "high"], [], s)

    def test_sender_domain_that_embeds_the_name(self):
        f = checks.check_headers(self._pe("COLDCARD <info@coldcardpressrelease.com>"))
        self.assertIn("look-alike", msgs(f))

    def test_company_domain_made_of_the_name_is_fine(self):
        f = checks.check_headers(self._pe("Acme Bank <statements@acmebank.com>"))
        self.assertNotIn("look-alike", msgs(f))

    def test_malformed_from_is_handled(self):
        f = checks.check_headers(self._pe('Microsoft account team ,_<no-reply@access-accsecurity.com>'))
        self.assertIn("microsoft", msgs(f).lower())

    def test_huge_headers_are_fast(self):
        t = time.time()
        checks.check_headers(self._pe("a" * 70000, reply_to="b" * 70000, return_path="@" * 70000))
        self.assertLess(time.time() - t, 2)


class BodyChecks(unittest.TestCase):
    def test_pathological_html_is_linear(self):
        for html in ("<" * 400000, "<meta " * 60000, "<script" * 60000, "<a href=" * 50000, "<!--" * 100000):
            t = time.time()
            checks.check_body(ParsedEmail(source="x", body_html=html))
            self.assertLess(time.time() - t, 3, html[:12])

    def test_html_tags_detected_case_insensitively(self):
        f = checks.check_body(ParsedEmail(source="x", body_html="<FORM><INPUT name=p></FORM><SCRIPT>x</SCRIPT>"))
        self.assertIn("form/input", msgs(f))
        self.assertIn("<script>", msgs(f))

    def test_freemail_invoice_lure(self):
        f = checks.check_body(ParsedEmail(source="x", sender="x <a@gmail.com>", subject="Payment Details for Invoice #1"))
        self.assertIn("free email address", msgs(f))

    def test_non_english_lure_phrases(self):
        f = checks.check_body(ParsedEmail(source="x", subject="Bloqueamos um acesso suspeito", body_text="regularize agora"))
        self.assertIn("non-English", msgs(f))


class Scoring(unittest.TestCase):
    def test_repeated_findings_are_merged_and_capped(self):
        pe = ParsedEmail(source="x", sender="a <a@example.org>")
        pe.links = [Link(href=f"http://same-host.example.org/{i}") for i in range(60)]
        pe.links += [Link(href=f"http://host{i}.example.net/") for i in range(60)]
        r = analyzer.analyze(pe)
        http = [f for f in r.findings if "Unencrypted HTTP" in f.message]
        self.assertTrue(any("(x60)" in f.message for f in http))
        self.assertLessEqual(sum(f.points for f in r.findings if f.category == "Links"), 45)

    def test_legitimate_emails_stay_low(self):
        with tempfile.TemporaryDirectory() as td:
            for name, raw in ham.build().items():
                p = Path(td) / f"{name}.eml"
                p.write_bytes(raw)
                self.assertEqual(analyzer.analyze(parser.parse_file(str(p))).verdict, "Low", name)


class Archetypes(unittest.TestCase):
    def test_every_phishing_archetype_reaches_its_minimum_verdict(self):
        import archetypes

        self.assertEqual(archetypes.run(verbose=False), [])


class Attachments(unittest.TestCase):
    def test_html_attachment_findings(self):
        out = self._an("page.html", b"<form><input type=password></form><script>var b=new Blob([atob('AA')]);</script>")
        self.assertIn("login form", out)
        self.assertIn("HTML smuggling", out)
        self.assertIn("SVG image contains a script", self._an("a.svg", b"<svg><script>x</script></svg>"))

    def test_plain_html_receipt_is_not_alarming(self):
        a = Attachment(filename="receipt.html", data=b"<html><body><p>Thanks for your order</p></body></html>")
        static_analysis.analyze(a)
        self.assertLess(sum(f.points for f in a.findings), 20)

    def test_onenote_with_launcher(self):
        out = self._an("Instructions.one", static_analysis.ONENOTE_MAGIC + b"...powershell -enc AAAA...")
        self.assertIn("script launchers", out)

    def test_huge_attachment_is_fast(self):
        t = time.time()
        self._an("big.bin", bytes(40_000_000))
        self.assertLess(time.time() - t, 5)

    def _an(self, name, data):
        a = Attachment(filename=name, data=data, size=len(data))
        static_analysis.analyze(a)
        return msgs(a.findings)

    def test_double_extension_and_disguised_exe(self):
        out = self._an("invoice.pdf.exe", b"MZ" + b"\x00" * 100)
        self.assertIn("double extension", out)
        self.assertIn("contains a Windows executable", self._an("report.pdf", b"MZ" + b"\x00" * 100))

    def test_corrupt_containers_do_not_raise(self):
        for name, data in (("a.docx", b"PK\x03\x04" + b"\xff" * 500), ("a.doc", b"\xd0\xcf\x11\xe0" + b"\x00" * 500),
                           ("a.exe", b"MZ" + b"\xff" * 4000), ("a.pdf", b"%PDF-1.4 \x00\x00"), ("a.rtf", b"{\\rtf1\\objdata"),
                           ("a.zip", b"PK\x03\x04"), ("", b""), ("‮gpj.exe", b"x")):
            self._an(name, data)


class IntelParsing(unittest.TestCase):
    def test_describe_functions_cope_with_every_status(self):
        for r in ({"status": "ok", "malicious": 0, "suspicious": 0, "total": 0}, {"status": "not_found"}, {"status": "no_key"},
                  {"status": "error"}, {"status": "cancelled"}):
            intel.describe_vt(r)
        for r in ({"status": "ok", "hit": True}, {"status": "ok", "hit": False}, {"status": "no_key"}, {"status": "error"}):
            intel.describe_abuse(r)

    def test_unknown_domains_without_keys_render(self):
        t = {"kind": "url", "label": "x.com", "url": "http://x.com", "host": "x.com"}
        res = {"vt": {"status": "no_key"}, "abuse": {"status": "no_key"}}
        self.assertIn("x.com", intel.detail_html(t, res))
        self.assertEqual(intel.to_findings(t, res), [])


if __name__ == "__main__":
    unittest.main()
