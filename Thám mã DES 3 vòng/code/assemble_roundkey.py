"""Assemble 48-bit K3 candidates from per-S-box candidate sets."""

from __future__ import annotations

from typing import Dict, List

from bit_utils import int_to_hex


def assemble_k3_candidates(results_by_sbox: Dict[str, Dict[str, object]], prune_limit: int) -> List[Dict[str, object]]:
    """Beam-assemble round-key candidates from eight 6-bit candidate lists."""
    partials: List[Dict[str, object]] = [{"k3": 0, "score": 0, "parts": []}]
    for sbox_id in range(1, 9):
        candidates = list(results_by_sbox[str(sbox_id)]["top_candidates"])
        expanded: List[Dict[str, object]] = []
        for partial in partials:
            for candidate in candidates:
                expanded.append(
                    {
                        "k3": (int(partial["k3"]) << 6) | int(candidate["key6"]),
                        "score": int(partial["score"]) + int(candidate["score"]),
                        "parts": [*partial["parts"], {"sbox_id": sbox_id, **candidate}],
                    }
                )
        expanded.sort(key=lambda item: (-int(item["score"]), int(item["k3"])))
        deduped: List[Dict[str, object]] = []
        seen = set()
        for item in expanded:
            if item["k3"] in seen:
                continue
            seen.add(item["k3"])
            deduped.append(item)
            if len(deduped) >= prune_limit:
                break
        partials = deduped

    for candidate in partials:
        candidate["k3_hex"] = int_to_hex(int(candidate["k3"]), 48)
        candidate["k3_bin"] = format(int(candidate["k3"]), "048b")
    return partials
