"""Shared DES helpers for the 1-round demo programs."""

from __future__ import annotations

from typing import Iterable, List, Sequence

from des_tables import E, FP, IP, P, PC1, PC2, S_BOXES, SHIFT_SCHEDULE

DEBUG = True


def validate_hex(value: str, bit_length: int, name: str) -> str:
    """Return an upper-case hex string after validating length and digits."""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hex string.")
    normalized = value.strip().upper()
    expected_length = bit_length // 4
    if len(normalized) != expected_length:
        raise ValueError(f"{name} must be exactly {expected_length} hex characters.")
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must contain only hexadecimal characters.") from exc
    return normalized


def hex_to_bits(value: str, bit_length: int) -> str:
    normalized = validate_hex(value, bit_length, "HEX")
    return format(int(normalized, 16), f"0{bit_length}b")


def bits_to_hex(bits: str) -> str:
    if len(bits) % 4 != 0:
        raise ValueError("Bit length must be a multiple of 4.")
    return format(int(bits, 2), f"0{len(bits) // 4}X")


def int_to_bits(value: int, width: int) -> str:
    return format(value, f"0{width}b")


def permute(bits: str, table: Sequence[int]) -> str:
    return "".join(bits[index - 1] for index in table)


def inverse_permutation(table: Sequence[int], input_size: int) -> tuple[int, ...]:
    inverse = [0] * input_size
    for output_index, input_index in enumerate(table, start=1):
        inverse[input_index - 1] = output_index
    return tuple(inverse)


P_INV = inverse_permutation(P, 32)


def xor_bits(left: str, right: str) -> str:
    if len(left) != len(right):
        raise ValueError("Bit strings must have the same length for XOR.")
    return "".join("1" if bit_l != bit_r else "0" for bit_l, bit_r in zip(left, right))


def left_rotate(bits: str, shift: int) -> str:
    shift %= len(bits)
    return bits[shift:] + bits[:shift]


def right_rotate(bits: str, shift: int) -> str:
    shift %= len(bits)
    return bits[-shift:] + bits[:-shift]


def chunk_bits(bits: str, size: int) -> List[str]:
    return [bits[offset: offset + size] for offset in range(0, len(bits), size)]


def sbox_lookup(box_index: int, six_bits: str) -> str:
    row = int(six_bits[0] + six_bits[5], 2)
    column = int(six_bits[1:5], 2)
    return int_to_bits(S_BOXES[box_index][row][column], 4)


def apply_sboxes(bits48: str) -> str:
    return "".join(
        sbox_lookup(box_index, bits48[box_index * 6:(box_index + 1) * 6])
        for box_index in range(8)
    )


def f_function(right32: str, round_key48: str) -> str:
    expanded = permute(right32, E)
    mixed = xor_bits(expanded, round_key48)
    sbox_output = apply_sboxes(mixed)
    return permute(sbox_output, P)


def derive_round_key_round1(main_key_hex: str) -> str:
    key_bits = hex_to_bits(validate_hex(main_key_hex, 64, "Main key"), 64)
    key56 = permute(key_bits, PC1)
    c0, d0 = key56[:28], key56[28:]
    shift = SHIFT_SCHEDULE[0]
    c1 = left_rotate(c0, shift)
    d1 = left_rotate(d0, shift)
    return permute(c1 + d1, PC2)


def encrypt_one_round_from_ip_state(ip_state64: str, round_key48: str) -> dict[str, str]:
    l0, r0 = ip_state64[:32], ip_state64[32:]
    f_output = f_function(r0, round_key48)
    l1 = r0
    r1 = xor_bits(l0, f_output)
    # swap l1 and r1
    preoutput = r1 + l1
    return {
        "L0": l0,
        "R0": r0,
        "F": f_output,
        "L1": l1,
        "R1": r1,
        "PREOUTPUT": preoutput,
        "CIPHERTEXT": bits_to_hex(permute(preoutput, FP)),
    }


def encrypt_one_round_block(plaintext_hex: str, main_key_hex: str) -> dict[str, str]:
    plaintext_bits = hex_to_bits(validate_hex(plaintext_hex, 64, "Plaintext"), 64)
    ip_state = permute(plaintext_bits, IP)
    round_key = derive_round_key_round1(main_key_hex)
    result = encrypt_one_round_from_ip_state(ip_state, round_key)
    result["ROUND_KEY"] = bits_to_hex(round_key)
    result["IP_STATE"] = ip_state
    return result


def preoutput_from_ciphertext(ciphertext_hex: str) -> str:
    ciphertext_bits = hex_to_bits(validate_hex(ciphertext_hex, 64, "Ciphertext"), 64)
    return permute(ciphertext_bits, IP)


def plaintext_from_ip_state(ip_state64: str) -> str:
    if len(ip_state64) != 64:
        raise ValueError("IP state must be 64 bits.")
    return bits_to_hex(permute(ip_state64, FP))


def inverse_pc2_template(round_key48: str) -> List[str]:
    template = ["?"] * 56
    for index, pc2_position in enumerate(PC2):
        template[pc2_position - 1] = round_key48[index]
    return template


def fill_unknown_bits(template: Sequence[str], fill_bits: Iterable[str]) -> str:
    filled = list(template)
    fill_iter = iter(fill_bits)
    for index, value in enumerate(filled):
        if value == "?":
            filled[index] = next(fill_iter)
    return "".join(filled)


def key56_to_key64_with_odd_parity(key56_bits: str) -> str:
    if len(key56_bits) != 56:
        raise ValueError("56-bit DES key material is required.")
    key64 = ["0"] * 64
    for output_index, input_index in enumerate(PC1):
        key64[input_index - 1] = key56_bits[output_index]

    for byte_index in range(8):
        start = byte_index * 8
        data_bits = key64[start:start + 7]
        parity_bit = "1" if data_bits.count("1") % 2 == 0 else "0"
        key64[start:start + 8] = data_bits + [parity_bit]

    return "".join(key64)
