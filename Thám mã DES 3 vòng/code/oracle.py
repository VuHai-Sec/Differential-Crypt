"""Oracle bản rõ được chọn cho khoá bí mật DES 3 vòng."""

from __future__ import annotations

from typing import Iterable, List, Optional

from bit_utils import int_to_hex
from des_core import encrypt_3round_block, normalize_des_key

PREDEFINED_KEY56_HEX = "FFFFF6789ABCDE"
PREDEFINED_KEY56 = int(PREDEFINED_KEY56_HEX, 16)


def expand_des_key56_to_key64(key56: int) -> int:
    """Mở rộng khoá DES 56 bit do người dùng chọn thành 64 bit với parity lẻ."""
    if key56 < 0 or key56 >= (1 << 56):
        raise ValueError("key56 phải nằm gọn trong đúng 56 bit")
    key64 = 0
    for chunk_index in range(8):
        shift = (7 - chunk_index) * 7
        seven_bits = (key56 >> shift) & 0x7F
        parity_bit = 0 if seven_bits.bit_count() % 2 == 1 else 1
        key64 = (key64 << 8) | ((seven_bits << 1) | parity_bit)
        
    print(f"Khoá chính: {hex(key64)}")
    return key64


class DES3RoundOracle:
    """Oracle chỉ cho phép mã hoá và giữ bí mật khoá chính của DES."""

    def __init__(
        self,
        key64: Optional[int] = None,
        key56: Optional[int] = None,
        seed: Optional[int] = None,
    ) -> None:
        if key64 is not None and key56 is not None:
            raise ValueError("Chỉ truyền key64 hoặc key56, không truyền đồng thời cả hai")
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
        """Hàm hỗ trợ công khai cho bên gọi khi muốn tạo khoá DES từ 56 bit."""
        return expand_des_key56_to_key64(key56)

    @staticmethod
    def predefined_key56_hex() -> str:
        """Trả về khoá 56 bit dựng sẵn dưới dạng chuỗi hexa."""
        return PREDEFINED_KEY56_HEX

    def encrypt(self, block64_hex: str) -> str:
        """Mã hoá một khối bản rõ 64 bit được biểu diễn ở dạng hexa."""
        plaintext = int(block64_hex, 16)
        return int_to_hex(encrypt_3round_block(plaintext, self._secret_key))

    def encrypt_many(self, blocks64_hex: Iterable[str]) -> List[str]:
        """Mã hoá nhiều khối bản rõ 64 bit."""
        return [self.encrypt(block_hex) for block_hex in blocks64_hex]