"""Chosen-plaintext oracle for the hidden DES 3-round key."""

from __future__ import annotations

from typing import Iterable, List, Optional

from bit_utils import int_to_hex
from des_core import encrypt_3round_block, normalize_des_key

PREDEFINED_KEY56_HEX = "FFFFF6789ABCDE"
PREDEFINED_KEY56 = int(PREDEFINED_KEY56_HEX, 16)


def expand_des_key56_to_key64(key56: int) -> int:
    """Expand a user-chosen 56-bit DES key into 64 bits with odd parity."""
    if key56 < 0 or key56 >= (1 << 56):
        raise ValueError("key56 must fit in exactly 56 bits")
    key64 = 0
    for chunk_index in range(8):
        shift = (7 - chunk_index) * 7
        seven_bits = (key56 >> shift) & 0x7F
        parity_bit = 0 if seven_bits.bit_count() % 2 == 1 else 1
        key64 = (key64 << 8) | ((seven_bits << 1) | parity_bit)
        
    print(f"Main key: {hex(key64)}")
    return key64


class DES3RoundOracle:
    """Encryption-only oracle that keeps the main DES key secret."""

    def __init__(
        self,
        key64: Optional[int] = None,
        key56: Optional[int] = None,
        seed: Optional[int] = None,
    ) -> None:
        if key64 is not None and key56 is not None:
            raise ValueError("Pass either key64 or key56, not both")
        _ = seed
        if key56 is not None:
            secret64 = expand_des_key56_to_key64(key56)
        elif key64 is not None:
            secret64 = normalize_des_key(key64)
        else:
            secret64 = expand_des_key56_to_key64(PREDEFINED_KEY56)
        self._secret_key = secret64

    @staticmethod
    def key64_from_key56(key56: int) -> int:
        """Public helper for callers that want to build a DES key from 56 bits."""
        return expand_des_key56_to_key64(key56)

    @staticmethod
    def predefined_key56_hex() -> str:
        """Return the built-in 56-bit key as a hexadecimal string."""
        return PREDEFINED_KEY56_HEX

    def encrypt(self, block64_hex: str) -> str:
        """Encrypt one 64-bit plaintext block represented as hex."""
        plaintext = int(block64_hex, 16)
        return int_to_hex(encrypt_3round_block(plaintext, self._secret_key))

    def encrypt_many(self, blocks64_hex: Iterable[str]) -> List[str]:
        """Encrypt many 64-bit plaintext blocks."""
        return [self.encrypt(block_hex) for block_hex in blocks64_hex]
