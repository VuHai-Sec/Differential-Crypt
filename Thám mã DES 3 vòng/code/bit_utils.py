"""Bit helpers for DES-style permutations and formatting."""

from __future__ import annotations

from typing import Iterable, List


def mask_bits(value: int, width: int) -> int:
    """Mask an integer to the requested width."""
    return value & ((1 << width) - 1)


def hex_to_int(block_hex: str, width_bits: int = 64) -> int:
    """Parse a fixed-width hexadecimal block."""
    cleaned = block_hex.lower().replace("0x", "")
    value = int(cleaned, 16)
    return mask_bits(value, width_bits)


def int_to_hex(value: int, width_bits: int = 64) -> str:
    """Format a block as fixed-width hexadecimal."""
    width_hex = width_bits // 4
    return f"{mask_bits(value, width_bits):0{width_hex}X}"


def permute(block: int, table: Iterable[int], input_size: int) -> int:
    """Apply a DES-style permutation table."""
    output = 0
    for position in table:
        bit = (block >> (input_size - position)) & 1
        output = (output << 1) | bit
    return output


def invert_permutation_table(table: List[int]) -> List[int]:
    """Build the inverse mapping of a permutation table."""
    inverse = [0] * len(table)
    for output_index, input_position in enumerate(table, start=1):
        inverse[input_position - 1] = output_index
    return inverse


def left_rotate(value: int, shift: int, width: int) -> int:
    """Rotate a fixed-width integer left."""
    shift %= width
    mask = (1 << width) - 1
    return ((value << shift) & mask) | ((value & mask) >> (width - shift))


def right_rotate(value: int, shift: int, width: int) -> int:
    """Rotate a fixed-width integer right."""
    shift %= width
    mask = (1 << width) - 1
    return ((value & mask) >> shift) | ((value << (width - shift)) & mask)


def split_block(block: int, left_width: int, total_width: int) -> tuple[int, int]:
    """Split a block into left/right halves."""
    right_width = total_width - left_width
    left = (block >> right_width) & ((1 << left_width) - 1)
    right = block & ((1 << right_width) - 1)
    return left, right


def join_halves(left: int, right: int, right_width: int) -> int:
    """Join two halves into a single integer."""
    return (left << right_width) | right


def extract_sbox_chunk(expanded_48: int, sbox_id: int) -> int:
    """Extract the 6-bit chunk entering a target DES S-box."""
    shift = (8 - sbox_id) * 6
    return (expanded_48 >> shift) & 0x3F


def extract_sbox_output_chunk(value_32: int, sbox_id: int) -> int:
    """Extract a 4-bit chunk associated with a DES S-box before P."""
    shift = (8 - sbox_id) * 4
    return (value_32 >> shift) & 0xF


def hamming_weight(value: int) -> int:
    """Count the number of set bits."""
    return value.bit_count()


def bit_positions_to_mask(positions: Iterable[int], width: int) -> int:
    """Convert 1-based bit positions from the MSB side into a mask."""
    mask = 0
    for position in positions:
        mask |= 1 << (width - position)
    return mask


def chunks_to_bin_list(value: int, chunk_width: int, count: int) -> list[str]:
    """Format a value as multiple fixed-width binary chunks."""
    return [
        format((value >> ((count - 1 - index) * chunk_width)) & ((1 << chunk_width) - 1), f"0{chunk_width}b")
        for index in range(count)
    ]


def apply_odd_parity(key64: int) -> int:
    """Set DES odd parity bits on each byte."""
    result = 0
    for byte_index in range(8):
        shift = (7 - byte_index) * 8
        byte_value = (key64 >> shift) & 0xFF
        upper_seven = byte_value & 0xFE
        ones = (upper_seven >> 1).bit_count()
        parity_bit = 0 if ones % 2 == 1 else 1
        result = (result << 8) | (upper_seven | parity_bit)
    return result
