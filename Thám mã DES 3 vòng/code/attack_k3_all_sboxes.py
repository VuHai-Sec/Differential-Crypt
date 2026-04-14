"""Chạy tấn công vi sai để tìm K3 trên cả 8 S-box của DES."""

from __future__ import annotations

from typing import Dict, List

from attack_k3_sbox import SBoxAttackResult, attack_k3_for_sbox
from pair_generator import PairRecord, generate_many_pairs


def attack_all_sboxes(oracle, config: Dict[str, object], ddt_data: Dict[str, List[List[int]]]) -> Dict[str, object]:
    """Sinh các cặp và tấn công độc lập trên tất cả các S-box."""
    # đặt chế độ sinh khoá = định trước
    pair_mode = str(config.get("pair_mode", "predefined"))
    # số cặp cho mỗi Sbox = 16
    pairs_per_sbox = int(config.get("pairs_per_sbox", 12))
    # randomseed: không dùng
    seed = int(config.get("random_seed", 0))
    # đặt l0 = 0
    require_equal_l0 = bool(config.get("require_equal_l0_demo", True))
    candidate_policy = dict(config.get("candidate_policy", {}))
    # chứa các cặp dùng cho mỗi Sbox
    pairs_by_sbox: Dict[str, List[Dict[str, object]]] = {}
    # chứa kết quả của mỗi Sbox
    results_by_sbox: Dict[str, Dict[str, object]] = {}

    for sbox_id in range(1, 9):
        # sinh các cặp bản rõ
        pairs: List[PairRecord] = generate_many_pairs(
            sbox_id=sbox_id,
            count=pairs_per_sbox,
            mode=pair_mode,
            seed=seed,
            require_equal_l0=require_equal_l0,
        )
        # lấy các khoá vòng của Sbox
        result: SBoxAttackResult = attack_k3_for_sbox(
            sbox_id=sbox_id,
            pairs=pairs,
            oracle=oracle,
            candidate_policy=candidate_policy,
            ddt_data=ddt_data,
        )
        pairs_by_sbox[str(sbox_id)] = [pair.to_dict() for pair in pairs]
        results_by_sbox[str(sbox_id)] = result.to_dict()
    # đưa ra các khoá tương ứng mỗi Sbox
    return {
        "pairs_by_sbox": pairs_by_sbox,
        "results_by_sbox": results_by_sbox,
    }