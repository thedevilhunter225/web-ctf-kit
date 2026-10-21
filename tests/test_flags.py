"""Flag recognition engine tests."""
import base64
import unittest

from webctf.flags.engine import (
    compile_pattern, compile_patterns, find_flags, find_flags_deep, looks_like_placeholder,
)


class FlagEngineTests(unittest.TestCase):
    def test_default_formats(self):
        text = "flag{abc} FLAG{X} CTF{y} HTB{z} picoCTF{p} myctf{q}"
        found = find_flags(text)
        for expect in ("flag{abc}", "FLAG{X}", "CTF{y}", "HTB{z}", "picoCTF{p}"):
            self.assertIn(expect, found)

    def test_custom_regex_added(self):
        pat = compile_pattern(r"SPECIAL\{[^}]+\}")
        self.assertEqual(find_flags("SPECIAL{hi} flag{also}", pat),
                         {"SPECIAL{hi}", "flag{also}"})

    def test_flag_only_ignores_defaults(self):
        pat = compile_pattern(r"ONLY\{[^}]+\}", flag_only=True)
        self.assertEqual(find_flags("ONLY{x} flag{nope}", pat), {"ONLY{x}"})

    def test_base64_single_layer(self):
        blob = "prefix " + base64.b64encode(b"flag{base64_me}").decode()
        matches = find_flags_deep(blob, compile_patterns())
        values = {m.value: m for m in matches}
        self.assertIn("flag{base64_me}", values)
        self.assertTrue(values["flag{base64_me}"].decoded)
        self.assertEqual(values["flag{base64_me}"].method, "decode:base64")

    def test_hex_layer(self):
        blob = b"flag{hex_me}".hex()
        self.assertTrue(any(m.value == "flag{hex_me}" for m in
                            find_flags_deep(blob, compile_patterns())))

    def test_decoded_noise_rejected(self):
        # base64 of 'flag{decoded_me}' then rot13 would create a Word{...} string;
        # decoded layers must require a known prefix, so only the real flag is kept.
        blob = "x " + base64.b64encode(b"flag{decoded_me}").decode()
        values = {m.value for m in find_flags_deep(blob, compile_patterns())}
        self.assertEqual(values, {"flag{decoded_me}"})

    def test_placeholder_detection(self):
        self.assertTrue(looks_like_placeholder("flag{...}"))
        self.assertTrue(looks_like_placeholder("flag{FLAG}"))
        self.assertTrue(looks_like_placeholder("flag{xxxxxx}"))
        self.assertFalse(looks_like_placeholder("flag{real_s3cret_123}"))


if __name__ == "__main__":
    unittest.main()
