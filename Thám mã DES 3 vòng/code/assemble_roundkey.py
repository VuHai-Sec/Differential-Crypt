"""Ghép các ứng viên K3 48 bit từ các tập ứng viên theo từng Sbox."""

from __future__ import annotations

from typing import Dict, List

from bit_utils import int_to_hex


def assemble_k3_candidates(results_by_sbox: Dict[str, Dict[str, object]], prune_limit: int) -> List[Dict[str, object]]:
    """Ghép khoá vòng từ tám danh sách khoá ứng viên từ 8 Sbox."""
    partials: List[Dict[str, object]] = [{"k3": 0, "score": 0, "parts": []}]
    for sbox_id in range(1, 9):
        candidates = list(results_by_sbox[str(sbox_id)]["top_candidates"])
        expanded: List[Dict[str, object]] = []
        # phần ghép khoá
        for partial in partials:
            for candidate in candidates:
                expanded.append(
                    {
                        # ghép 6 bit key mới vào
                        "k3": (int(partial["k3"]) << 6) | int(candidate["key6"]),
                        # tính điểm cho tổ hợp mới ghép ( = tổng số phiếu của tất cả khoá 6 bit)
                        "score": int(partial["score"]) + int(candidate["score"]),
                        # lưu lịch sử ghép
                        "parts": [*partial["parts"], {"sbox_id": sbox_id, **candidate}],
                    }
                )
        expanded.sort(key=lambda item: (-int(item["score"]), int(item["k3"])))
        deduped: List[Dict[str, object]] = []
        seen = set()
        # xoá trg hợp trùng key 
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