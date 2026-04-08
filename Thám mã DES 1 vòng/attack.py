"""Chosen-plaintext differential attack on the 1-round DES oracle."""

from __future__ import annotations

import itertools
import random
import subprocess
import sys
from pathlib import Path

from des_tables import E, S_BOXES
from des_utils import (
    DEBUG,
    P_INV,
    bits_to_hex,
    chunk_bits,
    int_to_bits,
    permute,
    plaintext_from_ip_state,
    preoutput_from_ciphertext,
    sbox_lookup,
    validate_hex,
    xor_bits,
)

CURRENT_DIR = Path(__file__).resolve().parent
ORACLE_PATH = CURRENT_DIR / "des_1_round_oracle.py"
TOP_DIFFERENCES_PER_SBOX = 3
BATCHES_PER_DIFFERENCE = 2
PAIRS_PER_BATCH = 6
EXTRA_BATCHES_IF_TIED = 1
RNG = random.Random(0xD35C0DE)


def build_ddt(sbox: tuple[tuple[int, ...], ...]) -> list[list[int]]:
    ddt = [[0] * 16 for _ in range(64)]
    for input_a in range(64):
        for input_b in range(64):
            delta_in = input_a ^ input_b
            row_a = ((input_a & 0b100000) >> 4) | (input_a & 1)
            row_b = ((input_b & 0b100000) >> 4) | (input_b & 1)
            col_a = (input_a >> 1) & 0b1111
            col_b = (input_b >> 1) & 0b1111
            delta_out = sbox[row_a][col_a] ^ sbox[row_b][col_b]
            ddt[delta_in][delta_out] += 1
    return ddt


def differential_profile(ddt: list[list[int]], delta: int) -> tuple[int, ...]:
    return tuple(sorted(ddt[delta][1:], reverse=True))


def choose_input_differences(
    box_index: int,
    ddt: list[list[int]],
    top_count: int = TOP_DIFFERENCES_PER_SBOX,
) -> list[str]:
    ranked_differences = []
    for delta in range(1, 64):
        delta_bits = int_to_bits(delta, 6)
        if delta_bits[0] != "0" or delta_bits[5] != "0":
            continue
        ranked_differences.append((differential_profile(ddt, delta), delta, delta_bits))

    ranked_differences.sort(key=lambda item: (item[0], -item[1]), reverse=True)
    chosen = [delta_bits for _, _, delta_bits in ranked_differences[:top_count]]
    if not chosen:
        raise RuntimeError(f"Could not choose any valid differential for S-box {box_index + 1}.")
    return chosen


def r_difference_for_sbox(box_index: int, input_difference6: str) -> str:
    if input_difference6[0] != "0" or input_difference6[5] != "0":
        raise ValueError("Chosen input difference must keep the shared boundary bits at zero.")
    delta_r = ["0"] * 32
    segment = E[box_index * 6:(box_index + 1) * 6]
    for bit_value, r_position in zip(input_difference6[1:5], segment[1:5]):
        delta_r[r_position - 1] = bit_value
    return "".join(delta_r)


def call_oracle(plaintext_hex: str) -> str:
    validate_hex(plaintext_hex, 64, "Plaintext")
    completed = subprocess.run(
        [sys.executable, str(ORACLE_PATH), plaintext_hex],
        cwd=str(CURRENT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Oracle execution failed.")

    for line in completed.stdout.splitlines():
        if line.startswith("CIPHERTEXT: "):
            return validate_hex(line.split(": ", 1)[1], 64, "Ciphertext")
    raise RuntimeError("Oracle output is missing the ciphertext line.")


def sample_pair_observation(box_index: int, delta_r: str) -> dict[str, str | tuple[str, str]]:
    l0 = int_to_bits(RNG.getrandbits(32), 32)
    r0 = int_to_bits(RNG.getrandbits(32), 32)
    paired_r0 = xor_bits(r0, delta_r)

    plaintext_a = plaintext_from_ip_state(l0 + r0)
    plaintext_b = plaintext_from_ip_state(l0 + paired_r0)
    ciphertext_a = call_oracle(plaintext_a)
    ciphertext_b = call_oracle(plaintext_b)

    preoutput_a = preoutput_from_ciphertext(ciphertext_a)
    preoutput_b = preoutput_from_ciphertext(ciphertext_b)
    r1_a = preoutput_a[:32]
    r1_b = preoutput_b[:32]

    delta_f = xor_bits(r1_a, r1_b)
    delta_sbox_outputs = permute(delta_f, P_INV)
    observed_output_difference = chunk_bits(delta_sbox_outputs, 4)[box_index]

    expanded_a = chunk_bits(permute(r0, E), 6)[box_index]
    expanded_b = chunk_bits(permute(paired_r0, E), 6)[box_index]

    return {
        "expanded_a": expanded_a,
        "expanded_b": expanded_b,
        "observed_output_difference": observed_output_difference,
        "reference_pair": (plaintext_a, ciphertext_a),
    }


def accumulate_scores_for_difference(
    box_index: int,
    input_difference6: str,
    scores: list[int],
) -> tuple[str, str] | None:
    delta_r = r_difference_for_sbox(box_index, input_difference6)
    reference_pair = None

    for _ in range(BATCHES_PER_DIFFERENCE):
        for _ in range(PAIRS_PER_BATCH):
            observation = sample_pair_observation(box_index, delta_r)
            if reference_pair is None:
                reference_pair = observation["reference_pair"]  # type: ignore[assignment]

            expanded_a = observation["expanded_a"]  # type: ignore[assignment]
            expanded_b = observation["expanded_b"]  # type: ignore[assignment]
            observed_output_difference = observation["observed_output_difference"]  # type: ignore[assignment]

            for subkey_candidate in range(64):
                candidate_bits = int_to_bits(subkey_candidate, 6)
                output_a = sbox_lookup(box_index, xor_bits(expanded_a, candidate_bits))
                output_b = sbox_lookup(box_index, xor_bits(expanded_b, candidate_bits))
                if xor_bits(output_a, output_b) == observed_output_difference:
                    scores[subkey_candidate] += 1

    return reference_pair


def best_candidates_for_sbox(scores: list[int]) -> tuple[int, list[str]]:
    max_score = max(scores)
    candidates = [int_to_bits(candidate, 6) for candidate, score in enumerate(scores) if score == max_score]
    return max_score, candidates


def score_subkeys_for_sbox(
    box_index: int,
    input_differences: list[str],
) -> tuple[list[int], tuple[str, str] | None]:
    scores = [0] * 64
    reference_pair = None

    for input_difference6 in input_differences:
        local_reference_pair = accumulate_scores_for_difference(box_index, input_difference6, scores)
        if reference_pair is None and local_reference_pair is not None:
            reference_pair = local_reference_pair

    max_score, candidates = best_candidates_for_sbox(scores)
    if len(candidates) > 1:
        for input_difference6 in input_differences:
            delta_r = r_difference_for_sbox(box_index, input_difference6)
            for _ in range(EXTRA_BATCHES_IF_TIED):
                for _ in range(PAIRS_PER_BATCH):
                    observation = sample_pair_observation(box_index, delta_r)
                    expanded_a = observation["expanded_a"]  # type: ignore[assignment]
                    expanded_b = observation["expanded_b"]  # type: ignore[assignment]
                    observed_output_difference = observation["observed_output_difference"]  # type: ignore[assignment]

                    for subkey_candidate in range(64):
                        candidate_bits = int_to_bits(subkey_candidate, 6)
                        output_a = sbox_lookup(box_index, xor_bits(expanded_a, candidate_bits))
                        output_b = sbox_lookup(box_index, xor_bits(expanded_b, candidate_bits))
                        if xor_bits(output_a, output_b) == observed_output_difference:
                            scores[subkey_candidate] += 1

        max_score, candidates = best_candidates_for_sbox(scores)

    if DEBUG:
        print(
            f"S{box_index + 1} MAX_SCORE={max_score} "
            f"CANDIDATES={','.join(candidates)} COUNT={len(candidates)}",
            file=sys.stderr,
        )

    return scores, reference_pair


def enumerate_round_key_candidates(sbox_candidate_lists: list[list[str]]) -> list[str]:
    seen_round_keys = set()
    round_key_candidates = []

    for sbox_chunks in itertools.product(*sbox_candidate_lists):
        round_key_hex = bits_to_hex("".join(sbox_chunks))
        if round_key_hex not in seen_round_keys:
            seen_round_keys.add(round_key_hex)
            round_key_candidates.append(round_key_hex)

    return round_key_candidates


def recover_round_key_candidates() -> tuple[str, str, list[str]]:
    ddts = [build_ddt(sbox) for sbox in S_BOXES]
    reference_plaintext = None
    reference_ciphertext = None
    sbox_candidate_lists = []

    for box_index, ddt in enumerate(ddts):
        input_differences = choose_input_differences(box_index, ddt)
        scores, reference_pair = score_subkeys_for_sbox(box_index, input_differences)
        _, candidates = best_candidates_for_sbox(scores)
        sbox_candidate_lists.append(candidates)

        if reference_plaintext is None and reference_pair is not None:
            reference_plaintext, reference_ciphertext = reference_pair

        if DEBUG:
            print(
                f"S{box_index + 1} DIFFS={','.join(input_differences)}",
                file=sys.stderr,
            )

    if reference_plaintext is None or reference_ciphertext is None:
        raise RuntimeError("No reference plaintext/ciphertext pair was collected.")

    round_key_candidates = enumerate_round_key_candidates(sbox_candidate_lists)
    return reference_plaintext, reference_ciphertext, round_key_candidates


def main() -> int:
    if len(sys.argv) != 1:
        print("Usage: python attack.py", file=sys.stderr)
        return 1

    try:
        reference_plaintext, reference_ciphertext, round_key_candidates = recover_round_key_candidates()
    except (RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"REFERENCE_PLAINTEXT: {reference_plaintext}")
    print(f"REFERENCE_CIPHERTEXT: {reference_ciphertext}")
    print(f"ROUND_KEY_CANDIDATE_COUNT: {len(round_key_candidates)}")
    print("ROUND_KEY_CANDIDATES:")
    for round_key_candidate in round_key_candidates:
        print(round_key_candidate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
