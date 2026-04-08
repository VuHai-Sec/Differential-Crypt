"""Bản demo đầu cuối để khôi phục các ứng viên khoá vòng 3 của DES."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

from assemble_roundkey import assemble_k3_candidates
from attack_k3_all_sboxes import attack_all_sboxes
from ddt import load_or_build_ddt
from oracle import DES3RoundOracle
from recover_mainkey_from_k3 import recover_main_keys_from_k3_candidates
from report_utils import build_summary, debug_print, print_final_report, save_json
from verify_mainkeys import verify_main_keys


def load_config(path: str = "config_demo.json") -> Dict[str, Any]:
    """Tải tệp cấu hình JSON cho bản demo."""
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    """Chạy toàn bộ bản demo khôi phục K3 của DES 3 vòng."""
    start_time = time.perf_counter()
    config = load_config()
    debug = bool(config.get("debug", False))
    oracle = DES3RoundOracle(seed=int(config.get("random_seed", 0)))
    ddt_data = load_or_build_ddt()
    attack_bundle = attack_all_sboxes(oracle=oracle, config=config, ddt_data=ddt_data)

    debug_print(debug, "Các cặp bản rõ đã sinh", attack_bundle["pairs_by_sbox"])
    debug_print(debug, "Kết quả tấn công theo từng S-box", attack_bundle["results_by_sbox"])

    k3_candidates = assemble_k3_candidates(
        results_by_sbox=attack_bundle["results_by_sbox"],
        prune_limit=int(config.get("roundkey_prune_limit", 4096)),
    )
    debug_print(debug, "Các ứng viên K3 sau khi ghép", k3_candidates)

    main_key_candidates = recover_main_keys_from_k3_candidates(k3_candidates)
    debug_print(debug, "Các ứng viên khoá chính đã khôi phục", main_key_candidates[: min(20, len(main_key_candidates))])

    verify_result = verify_main_keys(
        main_key_candidates=main_key_candidates,
        oracle=oracle,
        verify_plaintexts=int(config.get("verify_plaintexts", 4)),
        seed=int(config.get("random_seed", 0)),
    )
    debug_print(debug, "Nhật ký kiểm tra", verify_result)

    assumptions = [
        "Tấn công chỉ nhắm vào K3 và tạo ra các tập ứng viên.",
        "Quá trình sinh cặp áp đặt XOR bằng 0 cần thiết trên đầu vào S-box mục tiêu ở vòng 1 thông qua E(R0).",
        "Giản lược trong bản demo: các cặp cũng áp đặt L0 giống nhau để đại lượng quan sát ở vòng 3 có thể được rút gọn sạch về mức S-box.",
        "Việc ghép K3 dùng beam pruning để giữ cho tích Descartes ở mức có thể xử lý được.",
        "Lịch khoá nghịch mở rộng mỗi ứng viên K3 thành nhiều ứng viên khoá chính vì PC-2 không phải là song ánh.",
    ]

    runtime_seconds = time.perf_counter() - start_time
    summary = build_summary(
        config,
        attack_bundle,
        k3_candidates,
        main_key_candidates,
        verify_result,
        runtime_seconds,
    )
    full_report = {
        "summary": summary,
        "assumptions": assumptions,
        "attack_bundle": attack_bundle,
        "k3_candidates": k3_candidates,
        "main_key_candidates": main_key_candidates,
        "verify_result": verify_result,
    }

    save_json("artifacts/reports/attack_bundle.json", attack_bundle)
    save_json("artifacts/reports/k3_candidates.json", k3_candidates)
    save_json("artifacts/reports/main_key_candidates.json", main_key_candidates)
    save_json("artifacts/reports/verify_result.json", verify_result)
    save_json("artifacts/reports/demo_summary.json", summary)
    save_json("artifacts/reports/full_report.json", full_report)

    print_final_report(summary)


if __name__ == "__main__":
    main()