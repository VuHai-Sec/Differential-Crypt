"""Tấn công vi sai chosen-plaintext lên Oracle DES 1 vòng."""

from __future__ import annotations

import itertools
import random
import sys
from dataclasses import dataclass

from des_1_round_oracle import encrypt_many_blocks
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

TOP_DIFFERENCES_PER_SBOX = 3
BATCHES_PER_DIFFERENCE = 2
PAIRS_PER_BATCH = 6
EXTRA_BATCHES_IF_TIED = 1
RNG = random.Random(0xD35C0DE)
SUBKEY_CANDIDATE_BITS = [int_to_bits(candidate, 6) for candidate in range(64)]


@dataclass(frozen=True)
class PairRequest:
    plaintext_a: str
    plaintext_b: str
    expanded_a: str
    expanded_b: str


@dataclass(frozen=True)
class PairObservation:
    expanded_a: str
    expanded_b: str
    observed_output_difference: str
    reference_pair: tuple[str, str]


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
        raise RuntimeError(f"Không thể chọn được vi sai hợp lệ nào cho S-box {box_index + 1}.")
    return chosen


def r_difference_for_sbox(box_index: int, input_difference6: str) -> str:
    if input_difference6[0] != "0" or input_difference6[5] != "0":
        raise ValueError("Input difference đã chọn phải giữ các bit biên dùng chung bằng 0.")
    delta_r = ["0"] * 32
    segment = E[box_index * 6:(box_index + 1) * 6]
    for bit_value, r_position in zip(input_difference6[1:5], segment[1:5]):
        delta_r[r_position - 1] = bit_value
    return "".join(delta_r)


def generate_pair_request(box_index: int, delta_r: str) -> PairRequest:
    l0 = int_to_bits(RNG.getrandbits(32), 32)
    r0 = int_to_bits(RNG.getrandbits(32), 32)
    paired_r0 = xor_bits(r0, delta_r)

    plaintext_a = plaintext_from_ip_state(l0 + r0)
    plaintext_b = plaintext_from_ip_state(l0 + paired_r0)
    expanded_a = chunk_bits(permute(r0, E), 6)[box_index]
    expanded_b = chunk_bits(permute(paired_r0, E), 6)[box_index]

    return PairRequest(
        plaintext_a=plaintext_a,
        plaintext_b=plaintext_b,
        expanded_a=expanded_a,
        expanded_b=expanded_b,
    )


def generate_pair_requests_for_difference(
    box_index: int,
    delta_r: str,
    batch_count: int,
) -> list[PairRequest]:
    pair_requests = []
    for _ in range(batch_count):
        for _ in range(PAIRS_PER_BATCH):
            pair_requests.append(generate_pair_request(box_index, delta_r))
    return pair_requests


def process_encrypted_pair(
    box_index: int,
    pair_request: PairRequest,
    ciphertext_a: str,
    ciphertext_b: str,
) -> PairObservation:
    preoutput_a = preoutput_from_ciphertext(ciphertext_a)
    preoutput_b = preoutput_from_ciphertext(ciphertext_b)
    r1_a = preoutput_a[:32]
    r1_b = preoutput_b[:32]

    delta_f = xor_bits(r1_a, r1_b)
    delta_sbox_outputs = permute(delta_f, P_INV)
    observed_output_difference = chunk_bits(delta_sbox_outputs, 4)[box_index]

    return PairObservation(
        expanded_a=pair_request.expanded_a,
        expanded_b=pair_request.expanded_b,
        observed_output_difference=observed_output_difference,
        reference_pair=(pair_request.plaintext_a, ciphertext_a),
    )


def encrypt_pair_requests(box_index: int, pair_requests: list[PairRequest]) -> list[PairObservation]:
    plaintext_hex_list = []
    for pair_request in pair_requests:
        plaintext_hex_list.append(pair_request.plaintext_a)
        plaintext_hex_list.append(pair_request.plaintext_b)

    ciphertext_hex_list = encrypt_many_blocks(plaintext_hex_list)
    if len(ciphertext_hex_list) != len(plaintext_hex_list):
        raise RuntimeError("Kích thước output batch của Oracle không khớp với kích thước batch bản rõ.")

    observations = []
    for pair_index, pair_request in enumerate(pair_requests):
        ciphertext_a = validate_hex(ciphertext_hex_list[2 * pair_index], 64, "Bản mã")
        ciphertext_b = validate_hex(ciphertext_hex_list[2 * pair_index + 1], 64, "Bản mã")
        observations.append(process_encrypted_pair(box_index, pair_request, ciphertext_a, ciphertext_b))
    return observations


def score_observations(
    box_index: int,
    scores: list[int],
    observations: list[PairObservation],
) -> tuple[str, str] | None:
    reference_pair = None

    for observation in observations:
        if reference_pair is None:
            reference_pair = observation.reference_pair

        for subkey_candidate, candidate_bits in enumerate(SUBKEY_CANDIDATE_BITS):
            output_a = sbox_lookup(box_index, xor_bits(observation.expanded_a, candidate_bits))
            output_b = sbox_lookup(box_index, xor_bits(observation.expanded_b, candidate_bits))
            if xor_bits(output_a, output_b) == observation.observed_output_difference:
                scores[subkey_candidate] += 1

    return reference_pair


def accumulate_scores_for_difference(
    box_index: int,
    input_difference6: str,
    scores: list[int],
) -> tuple[str, str] | None:
    delta_r = r_difference_for_sbox(box_index, input_difference6)
    pair_requests = generate_pair_requests_for_difference(box_index, delta_r, BATCHES_PER_DIFFERENCE)
    observations = encrypt_pair_requests(box_index, pair_requests)
    return score_observations(box_index, scores, observations)


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
            pair_requests = generate_pair_requests_for_difference(box_index, delta_r, EXTRA_BATCHES_IF_TIED)
            observations = encrypt_pair_requests(box_index, pair_requests)
            score_observations(box_index, scores, observations)

        max_score, candidates = best_candidates_for_sbox(scores)

    if DEBUG:
        print(
            f"S{box_index + 1} DIEM_CAO_NHAT={max_score} "
            f"UNG_VIEN={','.join(candidates)} SO_LUONG={len(candidates)}",
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
                f"S{box_index + 1} VI_SAI={','.join(input_differences)}",
                file=sys.stderr,
            )

    if reference_plaintext is None or reference_ciphertext is None:
        raise RuntimeError("Không thu được cặp bản rõ/bản mã tham chiếu nào.")

    round_key_candidates = enumerate_round_key_candidates(sbox_candidate_lists)
    return reference_plaintext, reference_ciphertext, round_key_candidates


def main() -> int:
    if len(sys.argv) != 1:
        print("Cách dùng: python attack.py", file=sys.stderr)
        return 1

    try:
        reference_plaintext, reference_ciphertext, round_key_candidates = recover_round_key_candidates()
    except (RuntimeError, ValueError) as exc:
        print(f"LỖI: {exc}", file=sys.stderr)
        return 1

    print(f"BAN_RO_THAM_CHIEU: {reference_plaintext}")
    print(f"BAN_MA_THAM_CHIEU: {reference_ciphertext}")
    print(f"SO_LUONG_UNG_VIEN_KHOA_VONG: {len(round_key_candidates)}")
    print("CAC_UNG_VIEN_KHOA_VONG:")
    for round_key_candidate in round_key_candidates:
        print(round_key_candidate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
