"""Recover all DES main key candidates from the round-1 subkey."""

from __future__ import annotations

import sys

from des_utils import (
    DEBUG,
    bits_to_hex,
    fill_unknown_bits,
    hex_to_bits,
    int_to_bits,
    inverse_pc2_template,
    key56_to_key64_with_odd_parity,
    right_rotate,
    validate_hex,
)
from des_tables import SHIFT_SCHEDULE
from des_utils import encrypt_one_round_block


def iter_main_key_candidates(round_key_hex: str):
    round_key_bits = hex_to_bits(validate_hex(round_key_hex, 48, "Round key"), 48)
    partial_c1d1 = inverse_pc2_template(round_key_bits)
    unknown_positions = [index for index, value in enumerate(partial_c1d1) if value == "?"]

    for guess in range(1 << len(unknown_positions)):
        guessed_bits = int_to_bits(guess, len(unknown_positions))
        c1d1 = fill_unknown_bits(partial_c1d1, guessed_bits)
        c1, d1 = c1d1[:28], c1d1[28:]
        c0 = right_rotate(c1, SHIFT_SCHEDULE[0])
        d0 = right_rotate(d1, SHIFT_SCHEDULE[0])
        main_key_bits = key56_to_key64_with_odd_parity(c0 + d0)
        yield bits_to_hex(main_key_bits)


def recover_main_keys(round_key_hex: str, plaintext_hex: str, ciphertext_hex: str) -> list[str]:
    plaintext_hex = validate_hex(plaintext_hex, 64, "Plaintext")
    ciphertext_hex = validate_hex(ciphertext_hex, 64, "Ciphertext")
    matched_candidates = set()

    for candidate_key in iter_main_key_candidates(round_key_hex):
        result = encrypt_one_round_block(plaintext_hex, candidate_key)
        if result["CIPHERTEXT"] == ciphertext_hex:
            if DEBUG:
                print(f"MATCHED_MAIN_KEY: {candidate_key}", file=sys.stderr)
            matched_candidates.add(candidate_key)

    return sorted(matched_candidates)


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage: python code3.py <ROUND_KEY_HEX> <PLAINTEXT_HEX> <CIPHERTEXT_HEX>", file=sys.stderr)
        return 1

    try:
        recovered_main_keys = recover_main_keys(sys.argv[1], sys.argv[2], sys.argv[3])
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"MAIN_KEY_CANDIDATE_COUNT: {len(recovered_main_keys)}")
    print("MAIN_KEY_CANDIDATES:")
    for recovered_main_key in recovered_main_keys:
        print(recovered_main_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
