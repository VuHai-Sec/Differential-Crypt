"""Artifact writing and console reporting helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def save_json(path: str, data: Any) -> None:
    """Write one JSON artifact with UTF-8 encoding."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def debug_print(enabled: bool, title: str, payload: Any) -> None:
    """Print structured debug data only when requested."""
    if not enabled:
        return
    print(f"[DEBUG] {title}")
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
) -> Dict[str, Any]:
    """Build a compact summary object for the final artifact."""
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
    }


def print_final_report(summary: Dict[str, Any]) -> None:
    """Print a concise human-readable report."""
    print("=== DES 3-round differential demo ===")
    print(f"Pairs per S-box: {summary['config']['pairs_per_sbox']}")
    print(f"K3 candidates after assembly: {summary['k3_candidate_count']}")
    print(f"Main-key candidates before verify: {summary['main_key_candidate_count_before_verify']}")
    print(f"Main-key candidates after verify: {summary['main_key_candidate_count_after_verify']}")
    if summary["verified_keys"]:
        print("Verified main-key candidates:")
        for key_hex in summary["verified_keys"]:
            print(f"  {key_hex}")
    else:
        print("No main-key candidate survived verification.")
