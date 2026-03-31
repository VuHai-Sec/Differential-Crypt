"""Run the full DES 1-round key recovery pipeline."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from des_utils import DEBUG, validate_hex

CURRENT_DIR = Path(__file__).resolve().parent
CODE2_PATH = CURRENT_DIR / "code2.py"
CODE3_PATH = CURRENT_DIR / "code3.py"


def run_code2() -> tuple[str, str, list[str]]:
    completed = subprocess.run(
        [sys.executable, str(CODE2_PATH)],
        cwd=str(CURRENT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "code2.py failed.")
    return parse_code2_output(completed.stdout)


def parse_code2_output(output: str) -> tuple[str, str, list[str]]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 4:
        raise RuntimeError("code2.py output is incomplete.")

    if not lines[0].startswith("REFERENCE_PLAINTEXT: "):
        raise RuntimeError("Missing REFERENCE_PLAINTEXT in code2.py output.")
    if not lines[1].startswith("REFERENCE_CIPHERTEXT: "):
        raise RuntimeError("Missing REFERENCE_CIPHERTEXT in code2.py output.")
    if not lines[2].startswith("ROUND_KEY_CANDIDATE_COUNT: "):
        raise RuntimeError("Missing ROUND_KEY_CANDIDATE_COUNT in code2.py output.")
    if lines[3] != "ROUND_KEY_CANDIDATES:":
        raise RuntimeError("Missing ROUND_KEY_CANDIDATES header in code2.py output.")

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


def parse_code3_output(output: str) -> list[str]:
    lines = [line.strip() for line in output.splitlines()]
    if len(lines) < 2:
        raise RuntimeError("code3.py output is incomplete.")
    if not lines[0].startswith("MAIN_KEY_CANDIDATE_COUNT: "):
        raise RuntimeError("Missing MAIN_KEY_CANDIDATE_COUNT in code3.py output.")
    if lines[1] != "MAIN_KEY_CANDIDATES:":
        raise RuntimeError("Missing MAIN_KEY_CANDIDATES header in code3.py output.")

    candidate_count = int(lines[0].split(": ", 1)[1])
    main_key_candidates = [
        validate_hex(candidate_line, 64, "Main key candidate")
        for candidate_line in lines[2:]
        if candidate_line
    ]

    if len(main_key_candidates) != candidate_count:
        raise RuntimeError("Main key candidate count does not match the listed candidates.")

    return main_key_candidates


def run_code3(round_key_hex: str, plaintext_hex: str, ciphertext_hex: str) -> list[str]:
    completed = subprocess.run(
        [sys.executable, str(CODE3_PATH), round_key_hex, plaintext_hex, ciphertext_hex],
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
        return parse_code3_output(completed.stdout)
    except RuntimeError:
        if DEBUG:
            print(
                f"CODE3_PARSE_WARNING[{round_key_hex}]: could not parse code3.py output",
                file=sys.stderr,
            )
        return []


def main() -> int:
    if len(sys.argv) != 1:
        print("Usage: python code0.py", file=sys.stderr)
        return 1

    try:
        reference_plaintext, reference_ciphertext, round_key_candidates = run_code2()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"ROUND_KEY_CANDIDATE_COUNT: {len(round_key_candidates)}")
    found_any = False

    for index, round_key_candidate in enumerate(round_key_candidates, start=1):
        if DEBUG or len(round_key_candidates) <= 32:
            print(f"TRYING_ROUND_KEY {index}/{len(round_key_candidates)}: {round_key_candidate}")

        recovered_main_keys = run_code3(round_key_candidate, reference_plaintext, reference_ciphertext)
        if recovered_main_keys:
            found_any = True
            print(f"MATCHED_ROUND_KEY(S): {round_key_candidate}")
            print(f"MAIN_KEY_CANDIDATE_COUNT: {len(recovered_main_keys)}")
            print("MAIN_KEY_CANDIDATES:")
            for recovered_main_key in recovered_main_keys:
                print(recovered_main_key)

    if not found_any:
        print("ERROR: No round key candidate produced a valid main key.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
