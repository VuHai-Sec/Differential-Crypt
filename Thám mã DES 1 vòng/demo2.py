"""Run the full DES 1-round key recovery pipeline."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from des_utils import DEBUG, validate_hex

CURRENT_DIR = Path(__file__).resolve().parent
ATTACK_PATH = CURRENT_DIR / "attack.py"
MAIN_KEY_PATH = CURRENT_DIR / "main_key.py"


def format_elapsed_time(seconds: float) -> str:
    return f"{seconds:.6f}"


def run_attack_script() -> tuple[str, str, list[str]]:
    completed = subprocess.run(
        [sys.executable, str(ATTACK_PATH)],
        cwd=str(CURRENT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "attack.py failed.")
    return parse_attack_output(completed.stdout)


def parse_attack_output(output: str) -> tuple[str, str, list[str]]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 4:
        raise RuntimeError("attack.py output is incomplete.")

    if not lines[0].startswith("REFERENCE_PLAINTEXT: "):
        raise RuntimeError("Missing REFERENCE_PLAINTEXT in attack.py output.")
    if not lines[1].startswith("REFERENCE_CIPHERTEXT: "):
        raise RuntimeError("Missing REFERENCE_CIPHERTEXT in attack.py output.")
    if not lines[2].startswith("ROUND_KEY_CANDIDATE_COUNT: "):
        raise RuntimeError("Missing ROUND_KEY_CANDIDATE_COUNT in attack.py output.")
    if lines[3] != "ROUND_KEY_CANDIDATES:":
        raise RuntimeError("Missing ROUND_KEY_CANDIDATES header in attack.py output.")

    reference_plaintext = validate_hex(lines[0].split(": ", 1)[1], 64, "Reference plaintext")
    reference_ciphertext = validate_hex(lines[1].split(": ", 1)[1], 64, "Reference ciphertext")
    candidate_count = int(lines[2].split(": ", 1)[1])
    round_key_candidates = [
        validate_hex(candidate_line, 48, "Round key candidate")
        for candidate_line in lines[4:]
    ]

    if len(round_key_candidates) != candidate_count:
        raise RuntimeError("Round key candidate count does not match the listed candidates.")

    return reference_plaintext, reference_ciphertext, round_key_candidates


def parse_main_key_output(output: str) -> list[str]:
    lines = [line.strip() for line in output.splitlines()]
    if len(lines) < 2:
        raise RuntimeError("main_key.py output is incomplete.")
    if not lines[0].startswith("MAIN_KEY_CANDIDATE_COUNT: "):
        raise RuntimeError("Missing MAIN_KEY_CANDIDATE_COUNT in main_key.py output.")
    if lines[1] != "MAIN_KEY_CANDIDATES:":
        raise RuntimeError("Missing MAIN_KEY_CANDIDATES header in main_key.py output.")

    candidate_count = int(lines[0].split(": ", 1)[1])
    main_key_candidates = [
        validate_hex(candidate_line, 64, "Main key candidate")
        for candidate_line in lines[2:]
        if candidate_line
    ]

    if len(main_key_candidates) != candidate_count:
        raise RuntimeError("Main key candidate count does not match the listed candidates.")

    return main_key_candidates


def run_main_key_script(round_key_hex: str, plaintext_hex: str, ciphertext_hex: str) -> list[str]:
    completed = subprocess.run(
        [sys.executable, str(MAIN_KEY_PATH), round_key_hex, plaintext_hex, ciphertext_hex],
        cwd=str(CURRENT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        if DEBUG and completed.stderr.strip():
            print(f"CODE3_ERROR[{round_key_hex}]: {completed.stderr.strip()}", file=sys.stderr)
        return []

    try:
        return parse_main_key_output(completed.stdout)
    except RuntimeError:
        if DEBUG:
            print(
                f"MAIN_KEY_PARSE_WARNING[{round_key_hex}]: could not parse main_key.py output",
                file=sys.stderr,
            )
        return []


def main() -> int:
    start_time = time.perf_counter()

    if len(sys.argv) != 1:
        print("Usage: python demo2.py", file=sys.stderr)
        print(f"TOTAL_RUNTIME_SECONDS: {format_elapsed_time(time.perf_counter() - start_time)}")
        return 1

    try:
        reference_plaintext, reference_ciphertext, round_key_candidates = run_attack_script()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(f"TOTAL_RUNTIME_SECONDS: {format_elapsed_time(time.perf_counter() - start_time)}")
        return 1

    print(f"ROUND_KEY_CANDIDATE_COUNT: {len(round_key_candidates)}")
    found_any = False

    for index, round_key_candidate in enumerate(round_key_candidates, start=1):
        if DEBUG or len(round_key_candidates) <= 32:
            print(f"TRYING_ROUND_KEY {index}/{len(round_key_candidates)}: {round_key_candidate}")

        recovered_main_keys = run_main_key_script(round_key_candidate, reference_plaintext, reference_ciphertext)
        if recovered_main_keys:
            found_any = True
            print(f"MATCHED_ROUND_KEY(S): {round_key_candidate}")
            print(f"MAIN_KEY_CANDIDATE_COUNT: {len(recovered_main_keys)}")
            print("MAIN_KEY_CANDIDATES:")
            for recovered_main_key in recovered_main_keys:
                print(recovered_main_key)

    if not found_any:
        print("ERROR: No round key candidate produced a valid main key.", file=sys.stderr)
        print(f"TOTAL_RUNTIME_SECONDS: {format_elapsed_time(time.perf_counter() - start_time)}")
        return 1

    print(f"TOTAL_RUNTIME_SECONDS: {format_elapsed_time(time.perf_counter() - start_time)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
