"""Oracle mã hóa DES 1 vòng."""

from __future__ import annotations

import sys

from des_tables import IP
from des_utils import (
    DEBUG,
    bits_to_hex,
    derive_round_key_round1,
    encrypt_one_round_from_ip_state,
    hex_to_bits,
    key56_to_key64_with_odd_parity,
    permute,
    validate_hex,
)

MAIN_KEY_EFFECTIVE_56_HEX = "00000000023450"
BATCH_ORACLE_CALL_COUNT = 0


def compute_main_key_hex() -> str:
    """Dựng lại khóa DES 64 bit bằng cách chèn các bit parity lẻ chuẩn."""
    effective_key_bits = hex_to_bits(validate_hex(MAIN_KEY_EFFECTIVE_56_HEX, 56, "Khóa chính hiệu dụng"), 56)
    return bits_to_hex(key56_to_key64_with_odd_parity(effective_key_bits))


def _build_oracle_context() -> tuple[str, str, str]:
    main_key_hex = compute_main_key_hex()
    round_key_bits = derive_round_key_round1(main_key_hex)
    round_key_hex = bits_to_hex(round_key_bits)
    return main_key_hex, round_key_bits, round_key_hex


def _encrypt_validated_block(plaintext_hex: str, round_key_bits: str) -> str:
    plaintext_bits = hex_to_bits(plaintext_hex, 64)
    ip_state = permute(plaintext_bits, IP)
    return encrypt_one_round_from_ip_state(ip_state, round_key_bits)["CIPHERTEXT"]


def encrypt_one_block(plaintext_hex: str) -> str:
    validated_plaintext = validate_hex(plaintext_hex, 64, "Bản rõ")
    _, round_key_bits, _ = _build_oracle_context()
    return _encrypt_validated_block(validated_plaintext, round_key_bits)


def encrypt_many_blocks(plaintext_hex_list: list[str]) -> list[str]:
    global BATCH_ORACLE_CALL_COUNT

    validated_plaintexts = [
        validate_hex(plaintext_hex, 64, "Bản rõ")
        for plaintext_hex in plaintext_hex_list
    ]
    if not validated_plaintexts:
        return []

    _, round_key_bits, _ = _build_oracle_context()
    ciphertexts = [
        _encrypt_validated_block(plaintext_hex, round_key_bits)
        for plaintext_hex in validated_plaintexts
    ]

    BATCH_ORACLE_CALL_COUNT += 1
    if DEBUG:
        print(
            f"SO_LAN_GOI_BATCH_ORACLE={BATCH_ORACLE_CALL_COUNT} "
            f"SO_LUONG_BAN_RO={len(validated_plaintexts)}",
            file=sys.stderr,
        )

    return ciphertexts


def main() -> int:
    if len(sys.argv) != 2:
        print("Cách dùng: python des_1_round_oracle.py <PLAINTEXT_HEX>", file=sys.stderr)
        return 1

    try:
        plaintext_hex = validate_hex(sys.argv[1], 64, "Bản rõ")
        main_key_hex, round_key_bits, round_key_hex = _build_oracle_context()
        ciphertext_hex = _encrypt_validated_block(plaintext_hex, round_key_bits)
    except ValueError as exc:
        print(f"LỖI: {exc}", file=sys.stderr)
        return 1

    if DEBUG:
        print(f"KHOA_CHINH_HIEU_DUNG_56: {MAIN_KEY_EFFECTIVE_56_HEX}", file=sys.stderr)
        print(f"KHOA_CHINH_64: {main_key_hex}", file=sys.stderr)
        print(f"KHOA_VONG: {round_key_hex}", file=sys.stderr)
    print(f"BAN_MA: {ciphertext_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
