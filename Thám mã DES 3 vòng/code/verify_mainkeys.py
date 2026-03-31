"""Verify main-key candidates using fresh oracle plaintexts."""

from __future__ import annotations

import random
from typing import Dict, List

from bit_utils import int_to_hex
from des_core import encrypt_3round_block


def generate_verify_plaintexts(count: int, seed: int) -> List[str]:
    """Generate deterministic verification plaintexts."""
    rng = random.Random(seed + 0xD35)
    values = set()
    while len(values) < count:
        values.add(rng.getrandbits(64))
    return [int_to_hex(value, 64) for value in sorted(values)]


def verify_main_keys(
    main_key_candidates: List[Dict[str, object]],
    oracle,
    verify_plaintexts: int,
    seed: int,
) -> Dict[str, object]:
    """Filter main-key candidates by comparing against the oracle."""
    test_plaintexts = generate_verify_plaintexts(verify_plaintexts, seed)
    oracle_ciphertexts = oracle.encrypt_many(test_plaintexts)
    survivors = list(main_key_candidates)
    verification_log: List[Dict[str, object]] = []

    for step_index, (plaintext_hex, ciphertext_hex) in enumerate(zip(test_plaintexts, oracle_ciphertexts), start=1):
        next_survivors: List[Dict[str, object]] = []
        for candidate in survivors:
            trial_cipher = int_to_hex(encrypt_3round_block(int(plaintext_hex, 16), int(candidate["key64"])), 64)
            if trial_cipher == ciphertext_hex:
                next_survivors.append(candidate)
        verification_log.append(
            {
                "step": step_index,
                "plaintext": plaintext_hex,
                "oracle_ciphertext": ciphertext_hex,
                "before": len(survivors),
                "after": len(next_survivors),
            }
        )
        survivors = next_survivors
        if len(survivors) <= 1:
            break

    return {
        "verification_plaintexts": test_plaintexts,
        "verification_log": verification_log,
        "survivors": survivors,
    }
