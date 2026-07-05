# PWN_Kerberos Project Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a documented and tested offline Kerberos PCAP extraction utility without overstating its capabilities.

**Architecture:** Keep the single-file utility and its current positional interface. Isolate verification around the pure hexadecimal and ASN.1 helpers, then document the `tshark` boundary and Hashcat-oriented output honestly.

**Tech Stack:** Python 3.10+, standard library `unittest`, Wireshark `tshark`, Git, GitHub CLI.

---

### Task 1: Establish repository hygiene

**Files:**
- Create: `.gitignore`
- Create: `LICENSE`

- [ ] **Step 1: Create `.gitignore`**

```gitignore
__pycache__/
*.py[cod]
.venv/
venv/
.pytest_cache/
.coverage
htmlcov/
.idea/
.vscode/
*.log
```

- [ ] **Step 2: Add the MIT license**

Use the standard MIT license text with:

```text
Copyright (c) 2026 FRTDev
```

- [ ] **Step 3: Verify tracked candidates**

Run: `git status --short`

Expected: only the source, sample capture, README, license, ignore file, tests, and project documentation are candidates.

### Task 2: Test the pure parsing helpers

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/test_kerberos_to_hash.py`
- Modify: `KerberosToHash.py`

- [ ] **Step 1: Write helper tests**

```python
import unittest

from KerberosToHash import (
    asn1_read_len,
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
        self.assertEqual(find_first_octet_string_value(payload), bytes.fromhex("deadbeef"))

    def test_unwrap_direct_octet_string(self):
        payload = bytes.fromhex("0404deadbeef")
        self.assertEqual(unwrap_cipher_from_blob(payload), bytes.fromhex("deadbeef"))

    def test_unwrap_rejects_non_asn1_blob(self):
        self.assertIsNone(unwrap_cipher_from_blob(bytes.fromhex("deadbeef")))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests before source cleanup**

Run: `python -m unittest discover -v`

Expected: helper behavior passes; any import or encoding failure is recorded before correction.

- [ ] **Step 3: Repair source text and add `argparse`**

Replace mojibake in comments, docstrings, and messages. Implement:

```python
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract Hashcat-compatible Kerberos material from a PCAP file."
    )
    parser.add_argument("pcap_file", help="Path to a PCAP or PCAPNG capture")
    parser.add_argument("mode", choices=("as_req", "as_rep", "tgs_rep"))
    parser.add_argument("--debug", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    extract_records(args.pcap_file, args.mode, debug=args.debug)
```

- [ ] **Step 4: Run unit and CLI checks**

Run: `python -m unittest discover -v`

Expected: six tests pass.

Run: `python KerberosToHash.py --help`

Expected: exit code 0 and help for `pcap_file`, mode choices, and `--debug`.

### Task 3: Replace the README

**Files:**
- Delete: `README.MD`
- Create: `README.md`

- [ ] **Step 1: Document verified behavior**

Write an English README containing:

- concise purpose and explicit offline/authorized-use scope;
- supported modes and the actual `$krb5pa$...` output shape;
- Python and `tshark` prerequisites for Windows, Debian/Ubuntu, and macOS;
- clone and invocation commands;
- a mode table;
- sample-capture attribution to Root-Me without claiming endorsement;
- limitations covering Wireshark field-version sensitivity, heuristic ASN.1 unwrapping, and lack of active capture or cracking;
- troubleshooting for missing `tshark`, unmatched packets, and missing fields;
- test command and MIT license link.

- [ ] **Step 2: Check commands and claims**

Run: `rg -n "production.ready|guaranteed|all Kerberos|undetectable|automatic cracking" README.md`

Expected: no matches.

Run: `python -m unittest discover -v`

Expected: six tests pass.

### Task 4: Verify and publish

**Files:**
- Modify: all files introduced by Tasks 1–3

- [ ] **Step 1: Run full verification**

Run: `python -m compileall -q KerberosToHash.py tests`

Expected: exit code 0.

Run: `python -m unittest discover -v`

Expected: six tests pass.

Run: `python KerberosToHash.py KerberosTest.pcapng as_req`

Expected in the current environment: exit code 1 with the documented `tshark` missing message, unless `tshark` has been installed.

- [ ] **Step 2: Review the exact publication diff**

Run: `git status --short`

Run: `git diff --check`

Expected: no whitespace errors; no unrelated files.

- [ ] **Step 3: Commit the project**

```powershell
git add -- .gitignore LICENSE README.md README.MD KerberosToHash.py KerberosTest.pcapng tests docs
git commit -m "chore: prepare Kerberos parser for publication"
```

- [ ] **Step 4: Create and push the public repository**

Run:

```powershell
gh repo create FRTDev/PWN_Kerberos --public --source . --remote origin --push
```

Expected: `origin` targets `FRTDev/PWN_Kerberos` and `main` is pushed.

