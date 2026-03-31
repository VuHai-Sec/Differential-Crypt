"""Recover main-key candidates from assembled K3 candidates."""

from __future__ import annotations

from typing import Dict, List

from bit_utils import int_to_hex
from key_schedule_inverse import invert_round3_subkey


def recover_main_keys_from_k3_candidates(k3_candidates: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Invert the round-3 subkeys into deduplicated main-key candidates."""
    recovered: Dict[int, Dict[str, object]] = {}
    for candidate in k3_candidates:
        round_key = int(candidate["k3"])
        source_hex = str(candidate["k3_hex"])
        source_score = int(candidate["score"])
        for main_key in invert_round3_subkey(round_key):
            record = recovered.setdefault(
                main_key,
                {
                    "key64": main_key,
                    "key_hex": int_to_hex(main_key, 64),
                    "source_k3_hexes": [],
                    "best_source_score": source_score,
                },
            )
            if source_hex not in record["source_k3_hexes"]:
                record["source_k3_hexes"].append(source_hex)
            record["best_source_score"] = max(int(record["best_source_score"]), source_score)
    results = list(recovered.values())
    results.sort(key=lambda item: (-int(item["best_source_score"]), int(item["key64"])))
    return results
