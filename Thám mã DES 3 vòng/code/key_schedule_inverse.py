"""Invert the DES key schedule from a round-3 subkey candidate."""

from __future__ import annotations

from typing import Dict, List

from bit_utils import apply_odd_parity, join_halves
from des_core import reverse_key_schedule_state
from des_tables import PC1, PC2

PC2_MISSING_POSITIONS = [position for position in range(1, 57) if position not in PC2]


def invert_pc2(round_key48: int) -> List[int]:
    """Enumerate all 56-bit round-state candidates that map to a PC-2 output."""
    known_bits = [None for _ in range(56)]
    for output_index, source_position in enumerate(PC2, start=1):
        bit = (round_key48 >> (48 - output_index)) & 1
        known_bits[source_position - 1] = bit
    candidates: List[int] = []
    for fill_mask in range(1 << len(PC2_MISSING_POSITIONS)):
        bits = known_bits[:]
        for fill_index, source_position in enumerate(PC2_MISSING_POSITIONS):
            bits[source_position - 1] = (fill_mask >> (len(PC2_MISSING_POSITIONS) - 1 - fill_index)) & 1
        value = 0
        for bit in bits:
            value = (value << 1) | int(bit)
        candidates.append(value)
    return candidates


def invert_pc1(cd0: int) -> int:
    """Place a 56-bit PC-1 output back into a 64-bit DES key with zero parity bits."""
    key_bits = [0 for _ in range(64)]
    for output_index, source_position in enumerate(PC1, start=1):
        bit = (cd0 >> (56 - output_index)) & 1
        key_bits[source_position - 1] = bit
    key64 = 0
    for bit in key_bits:
        key64 = (key64 << 1) | bit
    return key64


def invert_round3_subkey(round_key48: int) -> List[int]:
    """Recover all 64-bit main-key candidates consistent with K3."""
    recovered = set()
    for cd3 in invert_pc2(round_key48):
        c3 = (cd3 >> 28) & ((1 << 28) - 1)
        d3 = cd3 & ((1 << 28) - 1)
        c0 = reverse_key_schedule_state(c3, rounds=3)
        d0 = reverse_key_schedule_state(d3, rounds=3)
        cd0 = join_halves(c0, d0, 28)
        recovered.add(apply_odd_parity(invert_pc1(cd0)))
    return sorted(recovered)
