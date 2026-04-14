"""Liệt kê toàn bộ ứng viên khóa chính DES từ subkey vòng 1."""

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


def iter_main_key_candidates(round_key_hex: str):
    round_key_bits = hex_to_bits(validate_hex(round_key_hex, 48, "Khóa vòng"), 48)
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
    # Giữ các tham số này để tương thích CLI với phần còn lại của pipeline demo.
    validate_hex(plaintext_hex, 64, "Bản rõ")
    validate_hex(ciphertext_hex, 64, "Bản mã")

    main_key_candidates = sorted(set(iter_main_key_candidates(round_key_hex)))
    if DEBUG:
        print(f"SO_LUONG_UNG_VIEN_KHOA_CHINH_DA_TAO: {len(main_key_candidates)}", file=sys.stderr)
    return main_key_candidates


def main() -> int:
    if len(sys.argv) != 4:
        print("Cách dùng: python main_key.py <ROUND_KEY_HEX> <PLAINTEXT_HEX> <CIPHERTEXT_HEX>", file=sys.stderr)
        return 1

    try:
        recovered_main_keys = recover_main_keys(sys.argv[1], sys.argv[2], sys.argv[3])
    except ValueError as exc:
        print(f"LỖI: {exc}", file=sys.stderr)
        return 1

    print(f"SO_LUONG_UNG_VIEN_KHOA_CHINH: {len(recovered_main_keys)}")
    print("CAC_UNG_VIEN_KHOA_CHINH:")
    for recovered_main_key in recovered_main_keys:
        print(recovered_main_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
