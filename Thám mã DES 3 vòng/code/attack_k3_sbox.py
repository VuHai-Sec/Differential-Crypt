"""Last-round subkey recovery for one DES S-box."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Dict, List, Sequence

from bit_utils import extract_sbox_chunk, int_to_hex, permute
from des_core import sbox_lookup
from des_tables import E
from diff_utils import derive_target_sbox_diff_from_ciphertexts
from pair_generator import PairRecord


@dataclass
class SBoxAttackResult:
    """Candidate scores and logs for one target S-box."""

    sbox_id: int
    score_table: List[int]
    max_score: int
    top_candidates: List[Dict[str, object]]
    pair_logs: List[Dict[str, object]]
    assumptions: List[str]

    def to_dict(self) -> Dict[str, object]:
        """Convert the attack result to JSON-friendly data."""
        return asdict(self)


def _select_top_candidates(score_table: Sequence[int], candidate_policy: Dict[str, object]) -> List[Dict[str, object]]:
    max_score = max(score_table)
    min_ratio = float(candidate_policy.get("min_score_ratio", 1.0))
    threshold = math.ceil(max_score * min_ratio)
    sorted_entries = sorted(enumerate(score_table), key=lambda item: (-item[1], item[0]))
    selected = [(key6, score) for key6, score in sorted_entries if score >= threshold]
    top_n = candidate_policy.get("top_n")
    if isinstance(top_n, int) and top_n > 0 and len(selected) > top_n:
        cutoff_score = selected[top_n - 1][1]
        selected = [(key6, score) for key6, score in selected if score >= cutoff_score]
    if candidate_policy.get("mode", "max") == "max":
        selected = [(key6, score) for key6, score in selected if score == max_score]
    if not selected:
        selected = [(key6, score) for key6, score in sorted_entries if score == max_score]
    return [
        {
            "key6": key6,
            "key6_bin": format(key6, "06b"),
            "key6_hex": format(key6, "02X"),
            "score": score,
        }
        for key6, score in selected
    ]


def attack_k3_for_sbox(
    sbox_id: int,
    pairs: Sequence[PairRecord],
    oracle,
    candidate_policy: Dict[str, object],
    ddt_data: Dict[str, List[List[int]]] | None = None,
) -> SBoxAttackResult:
    """Recover candidate 6-bit subkeys for one target S-box."""
    plaintexts: List[str] = []
    for pair in pairs:
        plaintexts.extend([pair.m1, pair.m2])
    ciphertexts = oracle.encrypt_many(plaintexts)
    score_table = [0 for _ in range(64)]
    pair_logs: List[Dict[str, object]] = []

    for pair_index, pair in enumerate(pairs):
        c1 = int(ciphertexts[2 * pair_index], 16)
        c2 = int(ciphertexts[2 * pair_index + 1], 16)
        observed = derive_target_sbox_diff_from_ciphertexts(c1, c2, sbox_id)
        expanded_r2_a = permute(observed["left3_a"], E, 32)
        expanded_r2_b = permute(observed["left3_b"], E, 32)
        input_a = extract_sbox_chunk(expanded_r2_a, sbox_id)
        input_b = extract_sbox_chunk(expanded_r2_b, sbox_id)
        input_diff = input_a ^ input_b
        output_diff = int(observed["observed_sbox_diff"])
        matched_keys: List[int] = []
        for key_candidate in range(64):
            sbox_out_a = sbox_lookup(sbox_id, input_a ^ key_candidate)
            sbox_out_b = sbox_lookup(sbox_id, input_b ^ key_candidate)
            if (sbox_out_a ^ sbox_out_b) == output_diff:
                score_table[key_candidate] += 1
                matched_keys.append(key_candidate)
        pair_log = {
            "pair_index": pair_index,
            "plaintext_1": pair.m1,
            "plaintext_2": pair.m2,
            "ciphertext_1": int_to_hex(c1, 64),
            "ciphertext_2": int_to_hex(c2, 64),
            "round3_r2_input_a": format(input_a, "06b"),
            "round3_r2_input_b": format(input_b, "06b"),
            "round3_input_diff": format(input_diff, "06b"),
            "observed_sbox_output_diff": format(output_diff, "04b"),
            "matched_key_count": len(matched_keys),
            "matched_keys_bin": [format(value, "06b") for value in matched_keys],
            "assumption": "derive ΔS3 from ΔR3 on 4 bits where ΔL2 is assumed zero via ΔL0=0 and round1 target-input diff=0",
        }
        if ddt_data is not None:
            pair_log["ddt_count"] = ddt_data[str(sbox_id)][input_diff][output_diff]
        pair_logs.append(pair_log)

    max_score = max(score_table)
    top_candidates = _select_top_candidates(score_table, candidate_policy)
    assumptions = [
        "Only K3 is attacked; output is a candidate set, not a guaranteed unique key.",
        "Demo simplification: pairs enforce ΔL0 = 0 in addition to the required round-1 target S-box input difference 0.",
        "Observed round-3 target S-box output difference is reconstructed from the 4 post-P bit positions whose ΔL2 terms vanish under the simplification above.",
    ]
    return SBoxAttackResult(
        sbox_id=sbox_id,
        score_table=score_table,
        max_score=max_score,
        top_candidates=top_candidates,
        pair_logs=pair_logs,
        assumptions=assumptions,
    )
