"""Chạy toàn bộ pipeline khôi phục khóa cho DES 1 vòng."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from des_1_round_oracle import compute_main_key_hex
from des_utils import DEBUG, validate_hex

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

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
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "attack.py chạy thất bại.")
    return parse_attack_output(completed.stdout)


def parse_attack_output(output: str) -> tuple[str, str, list[str]]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 4:
        raise RuntimeError("Output của attack.py chưa đầy đủ.")

    if not lines[0].startswith("BAN_RO_THAM_CHIEU: "):
        raise RuntimeError("Thiếu bản rõ tham chiếu trong output của attack.py.")
    if not lines[1].startswith("BAN_MA_THAM_CHIEU: "):
        raise RuntimeError("Thiếu bản mã tham chiếu trong output của attack.py.")
    if not lines[2].startswith("SO_LUONG_UNG_VIEN_KHOA_VONG: "):
        raise RuntimeError("Thiếu số lượng ứng viên khoá vòng trong output của attack.py.")
    if lines[3] != "CAC_UNG_VIEN_KHOA_VONG:":
        raise RuntimeError("Thiếu tiêu đề các ứng viên khoá chính trong output của main_key.py.")

    reference_plaintext = validate_hex(lines[0].split(": ", 1)[1], 64, "Bản rõ tham chiếu")
    reference_ciphertext = validate_hex(lines[1].split(": ", 1)[1], 64, "Bản mã tham chiếu")
    candidate_count = int(lines[2].split(": ", 1)[1])
    round_key_candidates = [
        validate_hex(candidate_line, 48, "Ứng viên khóa vòng")
        for candidate_line in lines[4:]
    ]

    if len(round_key_candidates) != candidate_count:
        raise RuntimeError("Số lượng ứng viên khóa vòng không khớp với danh sách được liệt kê.")

    return reference_plaintext, reference_ciphertext, round_key_candidates


def parse_main_key_output(output: str) -> list[str]:
    lines = [line.strip() for line in output.splitlines()]
    if len(lines) < 2:
        raise RuntimeError("Output của main_key.py chưa đầy đủ.")
    if not lines[0].startswith("SO_LUONG_UNG_VIEN_KHOA_CHINH: "):
        raise RuntimeError("Thiếu số lượng khoá chính trong output của main_key.py.")
    if lines[1] != "CAC_UNG_VIEN_KHOA_CHINH:":
        raise RuntimeError("Thiếu tiêu đề các ứng viên khoá chính trong output của main_key.py.")

    candidate_count = int(lines[0].split(": ", 1)[1])
    main_key_candidates = [
        validate_hex(candidate_line, 64, "Ứng viên khóa chính")
        for candidate_line in lines[2:]
        if candidate_line
    ]

    if len(main_key_candidates) != candidate_count:
        raise RuntimeError("Số lượng ứng viên khóa chính không khớp với danh sách được liệt kê.")

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
            print(f"Lỗi main key[{round_key_hex}]: {completed.stderr.strip()}", file=sys.stderr)
        return []

    try:
        return parse_main_key_output(completed.stdout)
    except RuntimeError:
        if DEBUG:
            print(
                f"Cảnh báo phân tích khoá chính:[{round_key_hex}]: không thể phân tích output của main_key.py",
                file=sys.stderr,
            )
        return []


def main() -> int:
    start_time = time.perf_counter()

    if len(sys.argv) != 1:
        print("Cách dùng: python demo2.py", file=sys.stderr)
        print(f"Tổng thời gian chạy (sec): {format_elapsed_time(time.perf_counter() - start_time)}")
        return 1

    try:
        reference_plaintext, reference_ciphertext, round_key_candidates = run_attack_script()
    except RuntimeError as exc:
        print(f"LỖI: {exc}", file=sys.stderr)
        print(f"Tổng thời gian chạy (sec): {format_elapsed_time(time.perf_counter() - start_time)}")
        return 1

    print(f"Khoá chính cần tìm: {compute_main_key_hex()}")
    print(f"Số ứng viên khoá vòng: {len(round_key_candidates)}")

    found_any = False

    for index, round_key_candidate in enumerate(round_key_candidates, start=1):
        if DEBUG or len(round_key_candidates) <= 32:
            print(f"Đang thử khoá vòng: {index}/{len(round_key_candidates)}: {round_key_candidate}")

        recovered_main_keys = run_main_key_script(round_key_candidate, reference_plaintext, reference_ciphertext)
        if recovered_main_keys:
            found_any = True
            print(f"Khoá vòng phù hợp: {round_key_candidate}")
            print(f"Số lượng ứng viên khoá chính: {len(recovered_main_keys)}")
            print("Các ứng viên khoá chính:")
            for recovered_main_key in recovered_main_keys:
                print(recovered_main_key)

    if not found_any:
        print("LỖI: Không có ứng viên khóa vòng nào sinh ra khóa chính hợp lệ.", file=sys.stderr)
        print(f"Tổng thời gian chạy (sec): {format_elapsed_time(time.perf_counter() - start_time)}")
        return 1

    print(f"Tổng thời gian chạy (sec): {format_elapsed_time(time.perf_counter() - start_time)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
