#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import re
import platform
from typing import Optional, Tuple, List, Dict, Any

def clean_hex(value: str) -> str:
    """Garde uniquement l'hex, sans séparateurs."""
    if value is None:
        return ""
    return re.sub(r"[^0-9a-fA-F]", "", str(value))

# --------- ASN.1 helpers (récursif) ---------

def asn1_read_len(data: bytes, i: int) -> Tuple[int, int]:
    """Lit une longueur ASN.1 (DER/BER) et retourne (length, new_index)."""
    if i >= len(data):
        raise ValueError("Index hors limites (lecture longueur).")
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    if n == 0 or i + n > len(data):
        raise ValueError("Longueur ASN.1 invalide.")
    length = int.from_bytes(data[i:i+n], "big")
    i += n
    return length, i

def find_first_octet_string_value(data: bytes) -> Optional[bytes]:
    """
    Parse TLV ASN.1 et retourne la *valeur* du premier OCTET STRING trouvé.
    Descend récursivement dans les tags "constructed" (ex: A2).
    """
    i = 0
    n = len(data)

    while i < n:
        tag = data[i]
        i += 1
        if i >= n:
            break

        try:
            l, i2 = asn1_read_len(data, i)
        except Exception:
            break

        val_start = i2
        val_end = val_start + l
        if val_end > n:
            break

        value = data[val_start:val_end]

        # OCTET STRING (tag universel 0x04)
        if tag == 0x04:
            return value

        # Si tag "constructed" => on descend dans la value
        # (bit 0x20 dans le tag)
        if tag & 0x20:
            inner = find_first_octet_string_value(value)
            if inner is not None:
                return inner

        i = val_end

    return None

def unwrap_cipher_from_blob(blob_bytes: bytes) -> Optional[bytes]:
    """
    Retourne le cipher attendu pour hashcat 19900:
    - si on trouve un OCTET STRING (même imbriqué), on retourne sa valeur
    - sinon None
    """
    if not blob_bytes:
        return None

    # Si c'est déjà un OCTET STRING direct
    if blob_bytes[0] == 0x04:
        try:
            l, j = asn1_read_len(blob_bytes, 1)
            if j + l <= len(blob_bytes):
                return blob_bytes[j:j+l]
        except Exception:
            pass

    # Si c'est une SEQUENCE, on parse dedans
    if blob_bytes[0] == 0x30:
        # On peut chercher directement sur tout le blob: le parseur TLV gère ça
        return find_first_octet_string_value(blob_bytes)

    # Sinon, on tente quand même de chercher un OCTET STRING dans ce blob
    return find_first_octet_string_value(blob_bytes)

# --------- tshark helpers ---------

def find_tshark() -> Optional[str]:
    system = platform.system().lower()

    if system == "windows":
        common_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"C:\Program Files\Wireshark\bin\tshark.exe",
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p

        try:
            r = subprocess.run(["where", "tshark"], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().splitlines()[0].strip()
        except Exception:
            pass
    else:
        try:
            r = subprocess.run(["which", "tshark"], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().strip()
        except Exception:
            pass

    return None

def run_tshark(
    tshark_path: str,
    pcap_file: str,
    display_filter: str,
    fields: List[str],
) -> Tuple[int, str, str, List[str]]:
    cmd = [tshark_path, "-r", pcap_file, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd.extend(["-e", f])
    cmd.extend(["-E", "separator=$", "-E", "occurrence=f"])
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr, cmd

def any_packets_match(tshark_path: str, pcap_file: str, display_filter: str) -> bool:
    _, out, _, _ = run_tshark(tshark_path, pcap_file, display_filter, ["frame.number"])
    return bool(out.strip())

def pick_first_nonempty_column(lines: List[str], col_idx: int) -> bool:
    for line in lines:
        if not line.strip():
            continue
        parts = line.split("$")
        if len(parts) > col_idx and parts[col_idx].strip():
            return True
    return False

# --------- main extraction ---------

def extract_records(pcap_file: str, mode: str, debug: bool = False) -> None:
    tshark_path = find_tshark()
    if not tshark_path:
        print("Erreur: tshark introuvable. Installe Wireshark/tshark et assure-toi qu'il est dans PATH.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(pcap_file):
        print(f"Erreur: fichier introuvable: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    if mode == "as_req":
        display_filter = "kerberos.msg_type == 10"
        user_fields  = ["kerberos.CNameString", "kerberos.cname_string", "kerberos.cname"]
        realm_fields = ["kerberos.realm", "kerberos.crealm"]
        etype_fields = ["kerberos.etype", "kerberos.padata_etype", "kerberos.enc_part_etype"]
        blob_fields  = ["kerberos.cipher", "kerberos.padata_value", "kerberos.padata"]
    elif mode == "as_rep":
        display_filter = "kerberos.msg_type == 11"
        user_fields  = ["kerberos.CNameString", "kerberos.cname_string", "kerberos.cname"]
        realm_fields = ["kerberos.realm", "kerberos.crealm"]
        etype_fields = ["kerberos.etype", "kerberos.enc_part_etype"]
        blob_fields  = ["kerberos.cipher", "kerberos.enc_part_cipher"]
    elif mode == "tgs_rep":
        display_filter = "kerberos.msg_type == 13"
        user_fields  = ["kerberos.CNameString", "kerberos.cname_string", "kerberos.cname"]
        realm_fields = ["kerberos.realm", "kerberos.crealm"]
        etype_fields = ["kerberos.etype", "kerberos.enc_part_etype"]
        blob_fields  = ["kerberos.cipher", "kerberos.enc_part_cipher"]
    else:
        print("Erreur: mode doit être as_req, as_rep, ou tgs_rep", file=sys.stderr)
        sys.exit(1)

    if not any_packets_match(tshark_path, pcap_file, display_filter):
        print(f"Aucun paquet ne matche le filtre: {display_filter}", file=sys.stderr)
        sys.exit(2)

    chosen = None
    tested = 0

    for uf in user_fields:
        for rf in realm_fields:
            for bf in blob_fields:
                tested += 1
                _, out, _, _ = run_tshark(tshark_path, pcap_file, display_filter, [uf, rf, bf])
                lines = [l for l in out.splitlines() if l.strip()]
                if not lines:
                    continue
                if (pick_first_nonempty_column(lines, 0)
                    and pick_first_nonempty_column(lines, 1)
                    and pick_first_nonempty_column(lines, 2)):
                    chosen = (uf, rf, bf)
                    break
            if chosen:
                break
        if chosen:
            break

    if not chosen:
        print(f"Des paquets {mode} existent, mais aucun des champs attendus ne sort (testés: {tested}).", file=sys.stderr)
        sys.exit(3)

    uf, rf, bf = chosen

    chosen_etype = None
    for ef in etype_fields:
        _, out, _, _ = run_tshark(tshark_path, pcap_file, display_filter, [ef])
        if any(l.strip() for l in out.splitlines()):
            chosen_etype = ef
            break

    fields = [uf, rf, bf] + ([chosen_etype] if chosen_etype else [])
    _, out, err, cmd = run_tshark(tshark_path, pcap_file, display_filter, fields)

    records: List[Dict[str, Any]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("$")
        while len(parts) < len(fields):
            parts.append("")

        username = parts[0].strip()
        realm = parts[1].strip()
        blob_raw = parts[2].strip()
        etype = parts[3].strip() if chosen_etype else ""

        if not username or not realm or not blob_raw:
            continue

        blob_hex = clean_hex(blob_raw)
        if not blob_hex:
            continue

        records.append({
            "username": username,
            "realm": realm,
            "etype": etype or "18",
            "blob_hex": blob_hex,
        })

    if not records:
        print(f"Des paquets {mode} matchent, mais aucune ligne exploitable n'a été extraite.", file=sys.stderr)
        sys.exit(4)

    # ---- Sortie hashcat 19900: garder SEULEMENT le cipher (OCTET STRING interne) ----
    # On garde la meilleure (la plus longue) par user/realm/etype.
    MIN_CIPHER_BYTES = 32
    best: Dict[Tuple[str, str, str], str] = {}

    for r in records:
        username = r["username"]
        realm = r["realm"]
        etype = r["etype"] or "18"
        blob_hex = r["blob_hex"]

        try:
            blob_bytes = bytes.fromhex(blob_hex)
        except Exception:
            continue

        cipher = unwrap_cipher_from_blob(blob_bytes)
        if cipher is None:
            continue

        if len(cipher) < MIN_CIPHER_BYTES:
            if debug:
                print(f"[debug] skip short cipher: {username}@{realm} bytes={len(cipher)} head={cipher.hex()[:40]}", file=sys.stderr)
            continue

        cipher_hex = cipher.hex()
        key = (username, realm, etype)
        if key not in best or len(cipher_hex) > len(best[key]):
            best[key] = cipher_hex

        if debug:
            print(f"[debug] ok: {username}@{realm} etype={etype} cipher_bytes={len(cipher)} head={cipher_hex[:40]}", file=sys.stderr)

    if not best:
        print("Aucun hash 19900 exploitable trouvé (après unwrap). Essaie --debug.", file=sys.stderr)
        sys.exit(5)

    for (username, realm, etype), cipher_hex in best.items():
        print(f"$krb5pa${etype}${username}${realm}${cipher_hex}")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract Hashcat-compatible Kerberos material from a PCAP file."
        )
    )
    parser.add_argument("pcap_file", help="path to a PCAP or PCAPNG capture")
    parser.add_argument("mode", choices=("as_req", "as_rep", "tgs_rep"))
    parser.add_argument(
        "--debug",
        action="store_true",
        help="print extraction diagnostics to stderr",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    extract_records(args.pcap_file, args.mode, debug=args.debug)

if __name__ == "__main__":
    main()
