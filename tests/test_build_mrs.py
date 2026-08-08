import tempfile
import unittest
from pathlib import Path

from scripts.build_mrs import (
    BuildError,
    _auto_outputs,
    _custom_output_key,
    _manifest_output,
    _safe_relative,
    _single_output,
    _validate_https_url,
    load_manifest,
    parse_rules,
)


class ParseRulesTests(unittest.TestCase):
    def test_auto_splits_supported_rules_and_drops_only_unsupported_entries(self):
        rules = parse_rules(
            """
            # comment
            DOMAIN,exact.example
            DOMAIN-SUFFIX,example.com
            DOMAIN-WILDCARD,*.wild.example
            DOMAIN-WILDCARD,cdn-*.example.com
            DOMAIN-KEYWORD,google
            IP-CIDR,192.0.2.7/24,no-resolve
            IP-CIDR6,2001:db8::1/32,no-resolve
            IP-CIDR,203.0.113.0/24,src
            SRC-IP-CIDR,198.51.100.0/24
            PROCESS-NAME,example
            """,
            "auto",
        )

        self.assertEqual(
            rules.domain,
            ["exact.example", "+.example.com", ".wild.example"],
        )
        self.assertEqual(rules.ipcidr, ["192.0.2.0/24", "2001:db8::/32"])
        self.assertEqual(rules.dropped["unsupported_domain_wildcard"], 1)
        self.assertEqual(rules.dropped["unsupported_rule_type:DOMAIN-KEYWORD"], 1)
        self.assertEqual(rules.dropped["unsupported_rule_type:SRC-IP-CIDR"], 1)
        self.assertEqual(rules.dropped["unsupported_source_ipcidr"], 1)
        self.assertEqual(rules.dropped["unsupported_rule_type:PROCESS-NAME"], 1)

    def test_domain_text_preserves_mihomo_suffix_and_wildcard_syntax(self):
        rules = parse_rules(
            """
            exact.example
            +.suffix.example
            .subdomains-only.example
            *.one-label.example
            """,
            "domain",
        )
        self.assertEqual(
            rules.domain,
            [
                "exact.example",
                "+.suffix.example",
                ".subdomains-only.example",
                "*.one-label.example",
            ],
        )

    def test_skk_markers_and_duplicates_are_removed(self):
        rules = parse_rules(
            """
            7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe
            DOMAIN,this_ruleset_is_made_by_sukkaw.ruleset.skk.moe
            DOMAIN,ruleset.skk.moe
            DOMAIN,example.com
            DOMAIN,EXAMPLE.COM
            """,
            "auto",
        )
        self.assertEqual(rules.domain, ["ruleset.skk.moe", "example.com"])
        self.assertEqual(rules.dropped["skk_marker"], 2)
        self.assertEqual(rules.dropped["duplicate_domain"], 1)

    def test_simple_yaml_payload_lines_are_accepted(self):
        rules = parse_rules(
            """
            payload:
              - 'DOMAIN,one.example'
              - "DOMAIN-SUFFIX,two.example"
            """,
            "domain",
        )
        self.assertEqual(rules.domain, ["one.example", "+.two.example"])

    def test_behavior_filter_does_not_change_rule_semantics(self):
        domain = parse_rules("SRC-IP-CIDR,192.0.2.0/24\nDOMAIN,a.example\n", "domain")
        ipcidr = parse_rules("DOMAIN,a.example\nIP-CIDR,192.0.2.0/24\n", "ipcidr")
        self.assertEqual(domain.domain, ["a.example"])
        self.assertFalse(domain.ipcidr)
        self.assertEqual(ipcidr.ipcidr, ["192.0.2.0/24"])
        self.assertFalse(ipcidr.domain)


class ManifestTests(unittest.TestCase):
    def test_safe_paths_and_output_names(self):
        self.assertEqual(_safe_relative("folder\\rules.txt", "test").as_posix(), "folder/rules.txt")
        self.assertEqual(_single_output("folder/rules.txt").as_posix(), "folder/rules.mrs")
        domain, ipcidr = _auto_outputs("folder/rules.mrs")
        self.assertEqual(domain.as_posix(), "folder/rules_domain.mrs")
        self.assertEqual(ipcidr.as_posix(), "folder/rules_ipcidr.mrs")
        for unsafe in (
            ".",
            "../rules",
            "/rules",
            "C:/rules",
            "folder/../../rules",
            "NUL.txt",
            "bad?.mrs",
            ".git/rules.mrs",
            "folder/.GIT/rules.mrs",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(BuildError):
                _safe_relative(unsafe, "test")
        with self.assertRaises(BuildError):
            _custom_output_key(_safe_relative("README.md/child.mrs", "test"))

    def test_custom_urls_must_be_public_https_urls(self):
        parsed = _validate_https_url("https://example.com/rules.txt")
        self.assertEqual(parsed.hostname, "example.com")
        for unsafe in (
            "http://example.com/rules.txt",
            "https://localhost/rules.txt",
            "https://127.0.0.1/rules.txt",
            "https://user:secret@example.com/rules.txt",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(BuildError):
                _validate_https_url(unsafe)

    def test_manifest_accepts_object_or_array(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            object_manifest = root / "object.json"
            array_manifest = root / "array.json"
            object_manifest.write_text('{"rules": [{"source": "a.txt"}]}', encoding="utf-8")
            array_manifest.write_text('[{"source": "b.txt"}]', encoding="utf-8")
            self.assertEqual(load_manifest(object_manifest)[0]["source"], "a.txt")
            self.assertEqual(load_manifest(array_manifest)[0]["source"], "b.txt")

    def test_explicit_output_does_not_require_a_source_filename(self):
        source = "https://example.com/"
        self.assertEqual(_manifest_output({"output": "named.mrs"}, source), "named.mrs")
        with self.assertRaises(BuildError):
            _manifest_output({}, source)


if __name__ == "__main__":
    unittest.main()
