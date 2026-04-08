"""Lõi DES rút gọn được dùng xuyên suốt trong bản demo."""

from __future__ import annotations

from typing import List, Tuple

from bit_utils import (
    apply_odd_parity,
    extract_sbox_chunk,
    int_to_hex,
    join_halves,
    left_rotate,
    mask_bits,
    permute,
    right_rotate,
    split_block,
)
from des_tables import E, FP, IP, P, PC1, PC2, ROUND_SHIFTS, S_BOXES


def sbox_lookup(sbox_id: int, six_bits: int) -> int:
    """Áp dụng một S-box của DES."""
    row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b1)
    column = (six_bits >> 1) & 0b1111
    return S_BOXES[sbox_id - 1][row][column]


def sbox_substitution(expanded_48: int) -> int:
    """Áp dụng cả 8 S-box của DES lên một đầu vào 48 bit."""
    output = 0
    for sbox_id in range(1, 9):
        chunk = extract_sbox_chunk(expanded_48, sbox_id)
        output = (output << 4) | sbox_lookup(sbox_id, chunk)
    return output


def round_function(right32: int, round_key48: int) -> int:
    """Hàm vòng F của DES."""
    expanded = permute(right32, E, 32)
    mixed = expanded ^ round_key48
    sbox_out = sbox_substitution(mixed)
    return permute(sbox_out, P, 32)


def generate_round_keys(key64: int, rounds: int = 3) -> List[int]:
    """Sinh các khoá vòng đầu tiên của DES."""
    permuted_key = permute(key64, PC1, 64)
    c = (permuted_key >> 28) & ((1 << 28) - 1)
    d = permuted_key & ((1 << 28) - 1)
    round_keys: List[int] = []
    for round_index in range(rounds):
        shift = ROUND_SHIFTS[round_index]
        c = left_rotate(c, shift, 28)
        d = left_rotate(d, shift, 28)
        cd = join_halves(c, d, 28)
        round_keys.append(permute(cd, PC2, 56))
    return round_keys


def encrypt_3round_block(block64: int, key64: int) -> int:
    """Mã hoá một khối 64 bit bằng 3 vòng DES."""
    ip_block = permute(block64, IP, 64)
    left, right = split_block(ip_block, 32, 64)
    for round_key in generate_round_keys(key64, rounds=3):
        left, right = right, left ^ round_function(right, round_key)
        right &= 0xFFFFFFFF
    preoutput = join_halves(right, left, 32)
    return permute(preoutput, FP, 64)


def encrypt_3round(block64_hex: str, key64_hex: str) -> str:
    """Mã hoá một khối hexa bằng một khoá DES hexa."""
    return int_to_hex(encrypt_3round_block(int(block64_hex, 16), int(key64_hex, 16)))


def plaintext_to_round0_state(block64: int) -> Tuple[int, int]:
    """Trả về trạng thái (L0, R0) sau IP."""
    return split_block(permute(block64, IP, 64), 32, 64)


def round0_state_to_plaintext(left0: int, right0: int) -> int:
    """Ánh xạ một trạng thái sau IP về khối bản rõ bên ngoài."""
    return permute(join_halves(left0, right0, 32), FP, 64)


def ciphertext_to_round3_state(block64: int) -> Tuple[int, int]:
    """Trả về trạng thái (L3, R3) trước bước hoán đổi cuối và FP."""
    preoutput = permute(block64, IP, 64)
    right3, left3 = split_block(preoutput, 32, 64)
    return left3, right3


def normalize_des_key(key64: int) -> int:
    """Áp dụng chuẩn hoá bit parity của DES cho một ứng viên khoá 64 bit."""
    return apply_odd_parity(mask_bits(key64, 64))


def reverse_key_schedule_state(c_or_d: int, rounds: int = 3) -> int:
    """Hoàn tác tổng các phép xoay trái đến số vòng được yêu cầu."""
    total_shift = sum(ROUND_SHIFTS[:rounds])
    return right_rotate(c_or_d, total_shift, 28)