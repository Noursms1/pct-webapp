# -*- coding: utf-8 -*-
import struct
import unittest
from unittest import mock

from engine import osint_dns


class TestMatchSan(unittest.TestCase):
    def test_exact_and_normalization(self):
        self.assertEqual(osint_dns._match_san("INFO.CERN.CH.", ["info.cern.ch"]), (True, "exact"))
        self.assertEqual(osint_dns._match_san("info.cern.ch", ["INFO.CERN.CH."]), (True, "exact"))

    def test_wildcard_single_level(self):
        self.assertEqual(osint_dns._match_san("info.cern.ch", ["*.cern.ch"]), (True, "wildcard"))
        self.assertEqual(osint_dns._match_san("api.app.cern.ch", ["*.app.cern.ch"]), (True, "wildcard"))
        self.assertEqual(osint_dns._match_san("a.b.cern.ch", ["*.cern.ch"]), (False, None))
        self.assertEqual(osint_dns._match_san("cern.ch", ["*.cern.ch"]), (False, None))

    def test_exact_and_invalid_inputs(self):
        self.assertEqual(osint_dns._match_san("www.cern.ch", ["www.cern.ch", "*.cern.ch"]), (True, "exact"))
        for host, sans in (("", ["*.cern.ch"]), (None, ["*.cern.ch"]), ("x.com", None), ("x.com", ["*." ])):
            self.assertEqual(osint_dns._match_san(host, sans), (False, None))


class TestLooksLikeIp(unittest.TestCase):
    def test_valid_values(self):
        for value in ("192.168.1.1", "0.0.0.0", "2001:db8::1", "::1"):
            self.assertTrue(osint_dns._looks_like_ip(value), value)

    def test_invalid_values(self):
        for value in ("example.com", "", None, "not-an-ip", "1.2.3"):
            self.assertFalse(osint_dns._looks_like_ip(value), repr(value))


class TestEncodeName(unittest.TestCase):
    def test_encoding(self):
        self.assertEqual(osint_dns._encode_name("example.com"), b"\x07example\x03com\x00")
        self.assertEqual(osint_dns._encode_name("example.com."), b"\x07example\x03com\x00")
        self.assertEqual(osint_dns._encode_name(""), b"\x00")


class TestParseDns(unittest.TestCase):
    @staticmethod
    def build_response(qname, qtype, answers, rcode=0):
        flags = 0x8180 | rcode
        header = struct.pack(">HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
        question = osint_dns._encode_name(qname) + struct.pack(">HH", qtype, 1)
        answer_data = b"".join(
            b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
            for rtype, rdata in answers
        )
        return header + question + answer_data

    def test_a_and_aaaa(self):
        data = self.build_response("example.com", 1, [(1, bytes([192, 168, 1, 1]))])
        records = osint_dns._parse_dns(data, expected_qtype="A")
        self.assertEqual(records[0]["value"], "192.168.1.1")
        rdata = bytes.fromhex("20010db8000000000000000000000001")
        data = self.build_response("example.com", 28, [(28, rdata)])
        self.assertIn(":", osint_dns._parse_dns(data, expected_qtype="AAAA")[0]["value"])

    def test_cname_separation(self):
        cname = osint_dns._encode_name("target.example.com")
        data = self.build_response("example.com", 1, [(5, cname)])
        self.assertEqual(osint_dns._parse_dns(data, expected_qtype="A"), [])
        data = self.build_response("example.com", 5, [(5, cname)])
        self.assertEqual(osint_dns._parse_dns(data, expected_qtype="CNAME")[0]["value"], "target.example.com")

    def test_mx_nxdomain_and_short_data(self):
        rdata = struct.pack(">H", 10) + osint_dns._encode_name("mail.example.com")
        data = self.build_response("example.com", 15, [(15, rdata)])
        self.assertTrue(osint_dns._parse_dns(data, expected_qtype="MX")[0]["value"].startswith("10 "))
        header = struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)
        question = osint_dns._encode_name("nx.local") + struct.pack(">HH", 1, 1)
        self.assertEqual(osint_dns._parse_dns(header + question, expected_qtype="A"), [{"error": "NXDOMAIN"}])
        self.assertEqual(osint_dns._parse_dns(b"\x00" * 5), [])


class TestDnsFallback(unittest.TestCase):
    def test_filters_non_ip_for_a(self):
        fake = [{"value": "192.168.1.1"}, {"value": "not-an-ip"}, {"value": ""}]
        with mock.patch.object(osint_dns, "dns_query_raw", return_value=fake):
            result = osint_dns._dns_query_with_cname_separation("example.com", "A")
        self.assertEqual(result, [fake[0]])

    def test_preserves_errors_and_other_types(self):
        fake = [{"error": "timeout"}]
        with mock.patch.object(osint_dns, "dns_query_raw", return_value=fake):
            self.assertEqual(osint_dns._dns_query_with_cname_separation("example.com", "A"), fake)
            self.assertEqual(osint_dns._dns_query_with_cname_separation("example.com", "TXT"), fake)


class TestHeadersAndNormalize(unittest.TestCase):
    def test_security_headers(self):
        headers = {name: "x" for name in osint_dns.SECURITY_HEADERS}
        result = osint_dns.audit_security_headers(headers)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["missing"], [])
        self.assertEqual(osint_dns.audit_security_headers({})["grade"], "F")

    def test_normalize_host(self):
        self.assertEqual(osint_dns.normalize_host("https://example.com:443/path"), "example.com")
        self.assertEqual(osint_dns.normalize_host(None), "")


class TestSslFailure(unittest.TestCase):
    def test_unreachable_test_net(self):
        result = osint_dns.check_ssl("192.0.2.1", port=443, timeout=1)
        self.assertFalse(result["enabled"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
