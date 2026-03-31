"""End-to-end demo for recovering DES round-3 key candidates."""

from __future__ import annotations

import json
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
    """Load the JSON config file for the demo."""
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    """Run the DES 3-round K3 recovery demo end-to-end."""
    config = load_config()
    debug = bool(config.get("debug", False))
    oracle = DES3RoundOracle(seed=int(config.get("random_seed", 0)))
    ddt_data = load_or_build_ddt()
    attack_bundle = attack_all_sboxes(oracle=oracle, config=config, ddt_data=ddt_data)

    debug_print(debug, "Generated plaintext pairs", attack_bundle["pairs_by_sbox"])
    debug_print(debug, "Per-S-box attack results", attack_bundle["results_by_sbox"])

    k3_candidates = assemble_k3_candidates(
        results_by_sbox=attack_bundle["results_by_sbox"],
        prune_limit=int(config.get("roundkey_prune_limit", 4096)),
    )
    debug_print(debug, "Assembled K3 candidates", k3_candidates)

    main_key_candidates = recover_main_keys_from_k3_candidates(k3_candidates)
    debug_print(debug, "Recovered main-key candidates", main_key_candidates[: min(20, len(main_key_candidates))])

    verify_result = verify_main_keys(
        main_key_candidates=main_key_candidates,
        oracle=oracle,
        verify_plaintexts=int(config.get("verify_plaintexts", 4)),
        seed=int(config.get("random_seed", 0)),
    )
    debug_print(debug, "Verification log", verify_result)

    assumptions = [
        "Attack only targets K3 and produces candidate sets.",
        "Pair generation enforces the required zero XOR on the target round-1 S-box input through E(R0).",
        "Demo simplification: pairs also enforce identical L0 so that the round-3 observable can be reduced to an S-box-level vote cleanly.",
        "K3 assembly uses beam pruning to keep the Cartesian product manageable.",
        "Inverse key schedule expands each K3 candidate into multiple main-key candidates because PC-2 is not bijective.",
    ]

    summary = build_summary(config, attack_bundle, k3_candidates, main_key_candidates, verify_result)
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
