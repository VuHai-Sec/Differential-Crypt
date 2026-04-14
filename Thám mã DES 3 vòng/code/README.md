# DES 3-Round Differential Cryptanalysis Demo

Project này dựng một pipeline hoàn chỉnh để demo **thám mã vi sai DES 3 vòng** ở mức thực thi được:

1. sinh **chosen plaintext pairs**,
2. gọi **oracle** để lấy ciphertext,
3. vote ứng viên khóa 6 bit của **K3** theo từng S-box,
4. ghép các ứng viên S-box thành **K3 candidates** 48 bit,
5. đảo DES key schedule vòng 3 để sinh **main-key candidates**,
6. dùng oracle để **verify** và lọc các main-key candidates.

## Cấu trúc file

- `des_tables.py`: toàn bộ bảng DES chuẩn như `IP`, `FP`, `E`, `P`, `PC-1`, `PC-2`, `S-box`.
- `bit_utils.py`: tiện ích thao tác bit, permutation, format hex, parity.
- `des_core.py`: DES Feistel 3 vòng chuẩn, round function, key schedule, đổi giữa block và trạng thái sau `IP`.
- `oracle.py`: oracle giữ bí mật main key và chỉ lộ API mã hóa.
- `ddt.py`: sinh XOR distribution table cho từng S-box và cache vào `artifacts/cache/ddt_cache.json`.
- `diff_utils.py`: helper để suy luận vi sai và chiếu 32 bit sau `P` về đúng S-box mục tiêu.
- `pair_generator.py`: sinh các plaintext pairs thỏa ràng buộc ở vòng 1.
- `attack_k3_sbox.py`: attack từng S-box để vote 64 ứng viên khóa con 6 bit của `K3`.
- `attack_k3_all_sboxes.py`: chạy attack cho cả 8 S-box.
- `assemble_roundkey.py`: ghép ứng viên từng S-box thành `K3` 48 bit bằng beam pruning.
- `key_schedule_inverse.py`: đảo `PC-2`, đảo quay vòng khóa, đảo `PC-1`.
- `recover_mainkey_from_k3.py`: từ `K3` candidates sinh `main-key candidates`.
- `verify_mainkeys.py`: dùng plaintext mới và oracle để lọc main-key candidates.
- `report_utils.py`: ghi JSON artifacts và in báo cáo console.
- `demo_k3_recovery.py`: script end-to-end của toàn bộ pipeline.
- `config_demo.json`: cấu hình mẫu cho demo.

## Thư mục output

- `artifacts/cache/`: cache DDT.
- `artifacts/reports/attack_bundle.json`: pair logs và kết quả attack theo từng S-box.
- `artifacts/reports/k3_candidates.json`: các ứng viên `K3` sau bước ghép.
- `artifacts/reports/main_key_candidates.json`: các main-key candidates trước verify.
- `artifacts/reports/verify_result.json`: log verify và các candidate còn sống.
- `artifacts/reports/demo_summary.json`: tóm tắt gọn, có cả `runtime_seconds`.
- `artifacts/reports/full_report.json`: báo cáo đầy đủ, có cả `runtime_seconds`.

## Cách chạy

Yêu cầu: Python 3, không cần thư viện ngoài.

```bash
python demo_k3_recovery.py
```

Sau khi chạy xong, chương trình sẽ in báo cáo cuối trên console, bao gồm:

- số lượng `K3 candidates`,
- số lượng `main-key candidates` trước và sau verify,
- tổng thời gian chạy toàn bộ thực nghiệm, tính bằng giây qua dòng `Total runtime (seconds)`.

## Debug mode

Chỉnh trong `config_demo.json`:

```json
{
  "debug": true
}
```

Khi `debug = true`, chương trình in/log thêm:

- plaintext pairs đã sinh,
- kết quả attack của từng S-box,
- ciphertext trong pair logs,
- score table,
- top candidates,
- số lượng `K3 candidates`,
- số lượng `main-key candidates` trước và sau verify,
- tổng thời gian chạy trong báo cáo cuối,
- các assumption / simplification đang dùng.

Khi `debug = false`, output console gọn hơn, nhưng artifacts JSON vẫn được lưu.



