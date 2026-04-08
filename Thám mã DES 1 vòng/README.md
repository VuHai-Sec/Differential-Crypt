# Demo Thám Mã Vi Sai Trên DES Rút Gọn 1 Vòng

Bộ chương trình này mô phỏng quy trình thực hiện thám mã vi sai trên DES rút gọn 1 vòng, không dùng thư viện mã hóa ngoài. Toàn bộ bảng DES như `IP`, `FP`, `E`, `P`, `S-boxes`, `PC-1`, `PC-2` và `shift schedule` được cài đặt thủ công trong mã nguồn.

## Cấu trúc file

- `des_1_round_oracle.py`: oracle mã hóa DES 1 vòng. File này hard-code `main key` hiệu dụng 56 bit, chèn parity DES odd parity để tạo khóa 64 bit, sinh round key vòng 1, và trả về ciphertext từ plaintext đầu vào.
- `attack.py`: chosen-plaintext differential attack. File này tự xây DDT cho 8 S-box, tạo các cặp plaintext có vi sai phù hợp, gọi oracle, chấm điểm subkey từng S-box, và sinh toàn bộ `round key` candidates.
- `main_key.py`: từ `round key` 48 bit, đảo `PC-2`, vét cạn các bit chưa biết, chèn parity, mã hóa lại và liệt kê tất cả `main key` candidates hợp lệ.
- `demo2.py`: file điều phối toàn bộ pipeline. File này chạy `attack.py`, parse danh sách `round key` candidates, sau đó gọi `main_key.py` cho từng round key và in kết quả cuối cùng.
- `des_tables.py`: chứa toàn bộ bảng DES chuẩn.
- `des_utils.py`: các hàm dùng chung cho xử lý bit, hoán vị, key schedule, F-function, và mã hóa DES 1 vòng.

## Quy trình thực hiện

1. `des_1_round_oracle.py` nhận plaintext 64 bit, áp dụng `IP`, thực hiện 1 vòng Feistel, swap, rồi áp dụng `FP` để sinh ciphertext.
2. `attack.py` chọn nhiều input difference tốt từ DDT của từng S-box, tạo nhiều batch chosen-plaintext pairs, thống kê score cho 64 ứng viên subkey 6 bit mỗi S-box, giữ lại tất cả ứng viên đồng hạng cao nhất, rồi ghép thành danh sách `round key` candidates 48 bit.
3. `main_key.py` nhận một `round key` candidate, đảo ngược key schedule vòng 1 để tạo các `main key` 64 bit khả thi, sau đó verify lại bằng cặp plaintext/ciphertext tham chiếu.
4. `demo2.py` tự động hóa toàn bộ quá trình và in thêm tổng thời gian chạy ở dòng cuối.

## Yêu cầu môi trường

- Python 3
- Không cần cài thêm thư viện ngoài

## Cách chạy

### 1. Chạy oracle mã hóa 1 vòng

```powershell
python des_1_round_oracle.py 0123456789ABCDEF
```

Output:

```text
CIPHERTEXT: ...
```

Nếu `DEBUG = True` trong `des_utils.py`, oracle sẽ in thêm `effective main key`, `main key 64 bit`, và `round key`.

### 2. Chạy tấn công vi sai để tìm round key candidates

```powershell
python attack.py
```

Output chính:

```text
REFERENCE_PLAINTEXT: ...
REFERENCE_CIPHERTEXT: ...
ROUND_KEY_CANDIDATE_COUNT: ...
ROUND_KEY_CANDIDATES:
...
```

### 3. Liệt kê main key candidates từ một round key

```powershell
python main_key.py <ROUND_KEY_HEX> <PLAINTEXT_HEX> <CIPHERTEXT_HEX>
```

Ví dụ:

```powershell
python main_key.py 00000000C410 7E1C60DAB4A9F554 2F4930DBB5BDE010
```

Output:

```text
MAIN_KEY_CANDIDATE_COUNT: ...
MAIN_KEY_CANDIDATES:
...
```

### 4. Chạy toàn bộ pipeline tự động

```powershell
python demo2.py
```

Output sẽ có dạng:

```text
ROUND_KEY_CANDIDATE_COUNT: ...
TRYING_ROUND_KEY 1/N: ...
MATCHED_ROUND_KEY(S): ...
MAIN_KEY_CANDIDATE_COUNT: ...
MAIN_KEY_CANDIDATES:
...
TOTAL_RUNTIME_SECONDS: ...
```

## Ghi chú

- Với DES chỉ 1 vòng, một `round key` 48 bit không xác định duy nhất `main key` 64 bit. Vì vậy `main_key.py` có thể trả về nhiều khóa hợp lệ.
- Trong chế độ `DEBUG`, một số file sẽ in thêm log phân tích ra `stderr` để hỗ trợ kiểm tra.
