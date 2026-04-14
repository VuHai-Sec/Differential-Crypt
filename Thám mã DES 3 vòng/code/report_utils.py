"""Các hàm hỗ trợ ghi artifact và báo cáo trên màn hình."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def save_json(path: str, data: Any) -> None:
    """Ghi một artifact JSON với mã hoá UTF-8."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def debug_print(enabled: bool, title: str, payload: Any) -> None:
    """Chỉ in dữ liệu gỡ lỗi có cấu trúc khi được yêu cầu."""
    if not enabled:
        return
    print(f"[GỠ LỖI] {title}")
    if isinstance(payload, (dict, list)):
        print(json.dumps(payload, indent=2))
    else:
        print(payload)


def build_summary(
    config: Dict[str, Any],
    attack_bundle: Dict[str, Any],
    k3_candidates: Any,
    main_key_candidates: Any,
    verify_result: Dict[str, Any],
    runtime_seconds: float,
) -> Dict[str, Any]:
    """Tạo đối tượng tóm tắt ngắn gọn cho artifact cuối cùng."""
    return {
        "config": config,
        "pair_counts": {sbox_id: len(pairs) for sbox_id, pairs in attack_bundle["pairs_by_sbox"].items()},
        "sbox_candidate_counts": {
            sbox_id: len(result["top_candidates"]) for sbox_id, result in attack_bundle["results_by_sbox"].items()
        },
        "k3_candidate_count": len(k3_candidates),
        "main_key_candidate_count_before_verify": len(main_key_candidates),
        "main_key_candidate_count_after_verify": len(verify_result["survivors"]),
        "verified_keys": [candidate["key_hex"] for candidate in verify_result["survivors"]],
        "runtime_seconds": round(runtime_seconds, 6),
    }


def print_final_report(summary: Dict[str, Any]) -> None:
    """In ra báo cáo ngắn gọn, dễ đọc cho người dùng."""
    print("=== Demo thám mã vi sai DES 3 vòng ===")
    print(f"Số cặp trên mỗi S-box: {summary['config']['pairs_per_sbox']}")
    print(f"Số ứng viên K3 sau khi ghép: {summary['k3_candidate_count']}")
    print(f"Số ứng viên khoá chính trước khi kiểm tra: {summary['main_key_candidate_count_before_verify']}")
    print(f"Số ứng viên khoá chính sau khi kiểm tra: {summary['main_key_candidate_count_after_verify']}")
    print(f"Tổng thời gian chạy, tính bằng giây: {summary['runtime_seconds']:.6f}")
    if summary["verified_keys"]:
        print("Các ứng viên khoá chính đã được kiểm tra đúng:")
        for key_hex in summary["verified_keys"]:
            print(f"  {key_hex}")
    else:
        print("Không có ứng viên khoá chính nào vượt qua bước kiểm tra.")