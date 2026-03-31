"""1-round DES encryption oracle."""

from __future__ import annotations

import sys

from des_utils import (
    DEBUG,
    bits_to_hex,
    encrypt_one_round_block,
    hex_to_bits,
    key56_to_key64_with_odd_parity,
    validate_hex,
)

MAIN_KEY_EFFECTIVE_56_HEX = "00000000023450"


def compute_main_key_hex() -> str:
    """Rebuild the 64-bit DES key by inserting standard odd parity bits."""
    effective_key_bits = hex_to_bits(validate_hex(MAIN_KEY_EFFECTIVE_56_HEX, 56, "Effective main key"), 56)
    return bits_to_hex(key56_to_key64_with_odd_parity(effective_key_bits))


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python code1.py <PLAINTEXT_HEX>", file=sys.stderr)
        return 1

    try:
        plaintext_hex = validate_hex(sys.argv[1], 64, "Plaintext")
        main_key_hex = compute_main_key_hex()
        result = encrypt_one_round_block(plaintext_hex, main_key_hex)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if DEBUG:
        print(f"EFFECTIVE_MAIN_KEY_56: {MAIN_KEY_EFFECTIVE_56_HEX}", file=sys.stderr)
        print(f"MAIN_KEY_64: {main_key_hex}", file=sys.stderr)
        print(f"ROUND_KEY: {result['ROUND_KEY']}", file=sys.stderr)
    print(f"CIPHERTEXT: {result['CIPHERTEXT']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
