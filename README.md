# PWN_Kerberos

Offline extraction of Kerberos authentication material from PCAP/PCAPNG
captures using Wireshark's `tshark`.

This is a small research utility, not a general Kerberos exploitation
framework. It reads an existing capture, searches selected Kerberos message
types, unwraps the first ASN.1 OCTET STRING it finds, and emits
Hashcat-oriented output. It does not capture traffic, attack a domain
controller, crack passwords, or validate extracted material.

## Supported modes

| Mode | Message | Wireshark filter |
| --- | --- | --- |
| `as_req` | AS-REQ | `kerberos.msg_type == 10` |
| `as_rep` | AS-REP | `kerberos.msg_type == 11` |
| `tgs_rep` | TGS-REP | `kerberos.msg_type == 13` |

Output uses this structure:

```text
$krb5pa$<etype>$<username>$<realm>$<cipher>
```

The implementation labels every extracted mode with the same `$krb5pa$`
structure. Do not assume every line maps directly to the correct Hashcat mode
without validating the packet type, encryption type, and expected format.

## Requirements

- Python 3.10 or newer
- Wireshark `tshark` in `PATH`

On Windows, common Wireshark installation paths are also detected.

```powershell
winget install WiresharkFoundation.Wireshark
```

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install tshark

# macOS
brew install wireshark
```

## Usage

```bash
git clone https://github.com/FRTDev/PWN_Kerberos.git
cd PWN_Kerberos
python KerberosToHash.py KerberosTest.pcapng as_req
```

Enable diagnostics or show the full CLI:

```bash
python KerberosToHash.py capture.pcapng as_req --debug
python KerberosToHash.py --help
```

## Extraction process

1. Locate `tshark`.
2. Filter the capture by Kerberos message type.
3. Try several Wireshark field names to accommodate dissector differences.
4. Select rows containing a username, realm, and encrypted blob.
5. Recursively locate the first ASN.1 OCTET STRING.
6. Keep the longest candidate per username, realm, and encryption type.
7. Print candidates to standard output.

## Sample capture

`KerberosTest.pcapng` is included as a test fixture. The repository owner
states that it originates from a Root-Me training exercise and contains no
sensitive production data. Root-Me is not affiliated with or endorsing this
repository.

Verify that redistribution and use comply with the exercise terms and
applicable law.

## Tests

```bash
python -m unittest discover -v
```

The test suite covers pure hexadecimal, ASN.1, and CLI parsing behavior.
End-to-end extraction additionally requires `tshark`.

## Known limitations

- ASN.1 parsing is minimal and not a complete DER/BER implementation.
- The first-OCTET-STRING heuristic can select the wrong nested value.
- Wireshark field names and dissector output can change between versions.
- A missing encryption type defaults to `18`.
- Output is not verified against a specific Hashcat mode.
- TCP reassembly, malformed ASN.1, and uncommon Kerberos extensions are not
  handled explicitly.
- The project performs no live capture, domain discovery, credential use, or
  password cracking.

## Troubleshooting

- **`tshark` not found:** install Wireshark/tshark and add it to `PATH`.
- **No packets match:** inspect the capture with
  `tshark -r capture.pcapng -Y kerberos`.
- **Expected fields are empty:** inspect available names with
  `tshark -G fields` and compare them with the candidate lists in the script.
- **No usable material after unwrapping:** rerun with `--debug` and inspect the
  ASN.1 structure independently.

## Legal and ethical use

Use this project only on captures and systems you own or are explicitly
authorized to assess. Kerberos material can represent real credentials; treat
generated output as sensitive data.

## License

[MIT](LICENSE)
