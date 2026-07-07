import unittest

from KerberosToHash import (
    asn1_read_len,
    build_parser,
    clean_hex,
    find_first_octet_string_value,
    unwrap_cipher_from_blob,
)


class ParsingTests(unittest.TestCase):
    def test_clean_hex_removes_separators(self):
        self.assertEqual(clean_hex("aa:BB 01-ff"), "aaBB01ff")

    def test_asn1_read_len_reads_short_length(self):
        self.assertEqual(asn1_read_len(bytes([3]), 0), (3, 1))

    def test_asn1_read_len_reads_long_length(self):
        self.assertEqual(asn1_read_len(bytes([0x82, 0x01, 0x00]), 0), (256, 3))

    def test_find_octet_string_descends_into_sequence(self):
        payload = bytes.fromhex("30060404deadbeef")
        self.assertEqual(
            find_first_octet_string_value(payload),
            bytes.fromhex("deadbeef"),
        )

    def test_unwrap_direct_octet_string(self):
        payload = bytes.fromhex("0404deadbeef")
        self.assertEqual(
            unwrap_cipher_from_blob(payload),
            bytes.fromhex("deadbeef"),
        )

    def test_unwrap_rejects_non_asn1_blob(self):
        self.assertIsNone(unwrap_cipher_from_blob(bytes.fromhex("deadbeef")))

    def test_parser_rejects_unknown_mode(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["capture.pcapng", "unknown"])


if __name__ == "__main__":
    unittest.main()
