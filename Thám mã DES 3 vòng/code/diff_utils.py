"""Các hàm hỗ trợ vi sai cho bản demo DES 3 vòng."""

from __future__ import annotations

from typing import Dict, List

from bit_utils import extract_sbox_output_chunk, invert_permutation_table, permute
from des_core import ciphertext_to_round3_state
from des_tables import P

P_INV = invert_permutation_table(P)


def sbox_input_positions_in_expansion(sbox_id: int) -> List[int]:
    """Trả về các vị trí bit của R đi vào Sbox mục tiêu thông qua E."""
    from des_tables import E

    start = (sbox_id - 1) * 6
    return E[start:start + 6]


def sbox_output_positions_after_p(sbox_id: int) -> List[int]:
    """Trả về 4 vị trí bit trong đầu ra F sau P của một Sbox mục tiêu."""
    source_positions = list(range((sbox_id - 1) * 4 + 1, (sbox_id - 1) * 4 + 5))
    return [P_INV[source_position - 1] for source_position in source_positions]


def project_after_p_diff_to_sbox_output(diff32_after_p: int, sbox_id: int) -> int:
    """Chiếu một hiệu 32 bit sau P về đoạn đầu ra 4 bit của một Sbox."""
    diff_before_p = permute(diff32_after_p, P_INV, 32)
    return extract_sbox_output_chunk(diff_before_p, sbox_id)


def derive_target_sbox_diff_from_ciphertexts(cipher1: int, cipher2: int, sbox_id: int) -> Dict[str, int]:
    """Suy ra hiệu đầu ra có thể quan sát của Sbox mục tiêu ở vòng 3 từ hai bản mã."""
    left3_a, right3_a = ciphertext_to_round3_state(cipher1)
    left3_b, right3_b = ciphertext_to_round3_state(cipher2)
    delta_right3 = right3_a ^ right3_b
    known_positions = sbox_output_positions_after_p(sbox_id)
    partial_diff = 0
    known_bits = {}
    for position in known_positions:
        bit = (delta_right3 >> (32 - position)) & 1
        partial_diff |= bit << (32 - position)
        known_bits[str(position)] = bit
    observed_sbox_diff = project_after_p_diff_to_sbox_output(partial_diff, sbox_id)
    return {
        "left3_a": left3_a,
        "left3_b": left3_b,
        "right3_a": right3_a,
        "right3_b": right3_b,
        "delta_right3": delta_right3,
        "partial_diff": partial_diff,
        "observed_sbox_diff": observed_sbox_diff,
        "known_positions": known_positions,
        "known_bits": known_bits,
    }