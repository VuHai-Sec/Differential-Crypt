"""Xây dựng và lưu bộ nhớ đệm các bảng phân bố XOR cho các S-box của DES."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from des_core import sbox_lookup


def compute_sbox_ddt(sbox_id: int) -> List[List[int]]:
    """Tính bảng phân bố XOR 64x16 của một S-box."""
    table = [[0 for _ in range(16)] for _ in range(64)]
    for input_a in range(64):
        output_a = sbox_lookup(sbox_id, input_a)
        for input_b in range(64):
            input_diff = input_a ^ input_b
            output_diff = output_a ^ sbox_lookup(sbox_id, input_b)
            table[input_diff][output_diff] += 1
    return table


def build_all_ddts() -> Dict[str, List[List[int]]]:
    """Tính DDT cho cả 8 S-box của DES."""
    return {str(sbox_id): compute_sbox_ddt(sbox_id) for sbox_id in range(1, 9)}


def load_or_build_ddt(cache_path: str = "artifacts/cache/ddt_cache.json") -> Dict[str, List[List[int]]]:
    """Tải dữ liệu DDT đã lưu trong bộ nhớ đệm hoặc tự xây dựng từ đầu."""
    cache_file = Path(cache_path)
    if cache_file.exists():
        with cache_file.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    ddt_data = build_all_ddts()
    with cache_file.open("w", encoding="utf-8") as handle:
        json.dump(ddt_data, handle, indent=2)
    return ddt_data