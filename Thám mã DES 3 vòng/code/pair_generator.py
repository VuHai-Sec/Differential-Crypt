"""Sinh các cặp bản rõ được chọn thỏa mãn ràng buộc của DES ở vòng 1."""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from bit_utils import bit_positions_to_mask, extract_sbox_chunk, hamming_weight, int_to_hex, permute
from des_core import plaintext_to_round0_state, round0_state_to_plaintext
from des_tables import E
from diff_utils import sbox_input_positions_in_expansion


@dataclass
class PairRecord:
    """Cặp bản rõ được chọn kèm theo siêu dữ liệu."""

    m1: str
    m2: str
    delta_m: str
    sbox_id: int
    constraint_ok: bool
    l0_equal: bool
    e_target_1: str
    e_target_2: str
    delta_r0: str
    notes: List[str]

    def to_dict(self) -> Dict[str, object]:
        """Chuyển bản ghi sang dữ liệu phù hợp với JSON."""
        return asdict(self)


def validate_pair_constraint(m1: int | str, m2: int | str, sbox_id: int, require_equal_l0: bool = True) -> Dict[str, object]:
    """Kiểm tra ràng buộc của cặp trên Sbox mục tiêu sau IP."""
    block1 = int(m1, 16) if isinstance(m1, str) else m1
    block2 = int(m2, 16) if isinstance(m2, str) else m2
    left0_a, right0_a = plaintext_to_round0_state(block1)
    left0_b, right0_b = plaintext_to_round0_state(block2)
    expanded_a = permute(right0_a, E, 32)
    expanded_b = permute(right0_b, E, 32)
    chunk_a = extract_sbox_chunk(expanded_a, sbox_id)
    chunk_b = extract_sbox_chunk(expanded_b, sbox_id)
    l0_equal = left0_a == left0_b
    constraint_ok = (chunk_a ^ chunk_b) == 0 and (l0_equal if require_equal_l0 else True)
    notes = []
    if (chunk_a ^ chunk_b) == 0:
        notes.append("target_sbox_input_diff_round1=0")
    if l0_equal:
        notes.append("demo_assumption_l0_equal")
    return {
        "constraint_ok": constraint_ok,
        "l0_equal": l0_equal,
        "e_target_1": format(chunk_a, "06b"),
        "e_target_2": format(chunk_b, "06b"),
        "delta_r0": int_to_hex(right0_a ^ right0_b, 32),
        "notes": notes,
    }


def _allowed_r0_positions_for_sbox(sbox_id: int) -> List[int]:
    '''xác định các bit KHÔNG đi vào Sbox mục tiêu'''
    blocked = set(sbox_input_positions_in_expansion(sbox_id))
    return [position for position in range(1, 33) if position not in blocked]


def _predefined_masks_for_sbox(sbox_id: int) -> List[int]:
    '''Sửa random những vị trí bit KHÔNG đi vào Sbox mục tiêu (để đa dạng dữ liệu)'''
    allowed = _allowed_r0_positions_for_sbox(sbox_id)
    patterns = [
        allowed[:6],
        allowed[-6:],
        allowed[::2][:6],
        allowed[1::2][:6],
        allowed[::3][:6],
        allowed[1::3][:6],
        allowed[2::3][:6],
        allowed[:3] + allowed[-3:],
    ]
    masks: List[int] = []
    for pattern in patterns:
        cleaned = sorted(set(pattern))
        if not cleaned:
            continue
        mask = bit_positions_to_mask(cleaned, 32)
        if mask not in masks:
            masks.append(mask)
    return masks


def _random_allowed_mask(sbox_id: int, rng: random.Random) -> int:
    allowed = _allowed_r0_positions_for_sbox(sbox_id)
    while True:
        picked = [position for position in allowed if rng.random() < 0.35]
        if picked:
            return bit_positions_to_mask(picked, 32)


def generate_pair_for_sbox(
    sbox_id: int,
    mode: str = "predefined",
    seed: Optional[int] = None,
    pair_index: int = 0,
    require_equal_l0: bool = True,
) -> PairRecord:
    """Sinh một cặp bản rõ được chọn cho một Sbox mục tiêu."""
    rng = random.Random((seed or 0) + sbox_id * 1009 + pair_index * 7919)
    left0 = rng.getrandbits(32)
    right0_a = rng.getrandbits(32)
    if mode == "predefined":
        # xác định nhưungx bit được sửa
        masks = _predefined_masks_for_sbox(sbox_id)
        delta_r0 = masks[pair_index % len(masks)]
    elif mode == "random":
        delta_r0 = _random_allowed_mask(sbox_id, rng)
    else:
        raise ValueError(f"Không hỗ trợ chế độ sinh cặp: {mode}")
    right0_b = right0_a ^ delta_r0
    left0_b = left0 if require_equal_l0 else rng.getrandbits(32)
    # tạo cặp bản rõ
    plaintext1 = round0_state_to_plaintext(left0, right0_a)
    plaintext2 = round0_state_to_plaintext(left0_b, right0_b)
    # kiểm tra xem cặp đã gen có phù hợp không?
    validation = validate_pair_constraint(plaintext1, plaintext2, sbox_id, require_equal_l0=require_equal_l0)
    if not validation["constraint_ok"]:
        raise RuntimeError(f"Cặp được sinh ra không thỏa mãn ràng buộc cho Sbox {sbox_id}")
    notes = list(validation["notes"])
    notes.append("delta_r0_only_touches_non_target_expansion_bits")
    if mode == "predefined":
        notes.append("predefined_demo_pattern")
    return PairRecord(
        m1=int_to_hex(plaintext1, 64),
        m2=int_to_hex(plaintext2, 64),
        delta_m=int_to_hex(plaintext1 ^ plaintext2, 64),
        sbox_id=sbox_id,
        constraint_ok=bool(validation["constraint_ok"]),
        l0_equal=bool(validation["l0_equal"]),
        e_target_1=str(validation["e_target_1"]),
        e_target_2=str(validation["e_target_2"]),
        delta_r0=str(validation["delta_r0"]),
        notes=notes,
    )


def generate_many_pairs(
    sbox_id: int,
    count: int,
    mode: str = "predefined",
    seed: Optional[int] = None,
    require_equal_l0: bool = True,
) -> List[PairRecord]:
    """Sinh nhiều cặp bản rõ được chọn cho một Sbox mục tiêu."""
    # output: Các cặp bản rõ
    return [
        generate_pair_for_sbox(
            sbox_id=sbox_id,
            mode=mode,
            seed=seed,
            pair_index=index,
            require_equal_l0=require_equal_l0,
        )
        for index in range(count)
    ]