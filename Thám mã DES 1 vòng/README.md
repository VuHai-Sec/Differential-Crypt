# Demo Thám Mã Vi Sai Trên DES Rút Gọn 1 Vòng

Bộ chương trình này mô phỏng quy trình thám mã vi sai trên DES rút gọn 1 vòng, không dùng thư viện mã hóa ngoài. Toàn bộ các bảng DES như `IP`, `FP`, `E`, `P`, `Sbox`, `PC-1`, `PC-2` và `shift schedule` đều được cài đặt thủ công trong mã nguồn.

## Cấu trúc file

- `des_1_round_oracle.py`: Oracle mã hóa DES 1 vòng. File này hard-code `khóa chính` hiệu dụng 56 bit, chèn odd parity để tạo khóa 64 bit, sinh `khóa vòng` vòng 1 và trả về bản mã. Ngoài chế độ CLI cũ cho 1 bản rõ, file còn cung cấp Python API:

  ```python
  encrypt_one_block(plaintext_hex: str) -> str
  encrypt_many_blocks(plaintext_hex_list: list[str]) -> list[str]
  ```

  Với batch API, `main_key_hex` và `round key` chỉ được tính một lần cho mỗi lần gọi batch.

- `attack.py`: chương trình tấn công vi sai chosen-plaintext. File này tự xây DDT cho 8 Sbox, tạo nhiều cặp bản rõ có vi sai phù hợp, gom bản rõ theo batch, gọi trực tiếp `encrypt_many_blocks(...)`, chấm điểm subkey 6 bit cho từng Sbox và sinh toàn bộ ứng viên `khóa vòng` 48 bit.
- `main_key.py`: từ `khóa vòng` 48 bit, đảo `PC-2`, vét cạn các bit chưa biết, chèn parity và liệt kê tất cả ứng viên `khóa chính` hợp lệ.
- `demo2.py`: điều phối toàn bộ pipeline. File này chạy `attack.py`, phân tích danh sách ứng viên `khóa vòng`, sau đó gọi `main_key.py` cho từng khóa vòng và in kết quả cuối cùng.
- `des_tables.py`: chứa toàn bộ bảng DES chuẩn.
- `des_utils.py`: các hàm dùng chung cho xử lý bit, hoán vị, key schedule, F-function và mã hóa DES 1 vòng.

## Quy trình thực hiện

1. `des_1_round_oracle.py` nhận bản rõ 64 bit, áp dụng `IP`, thực hiện 1 vòng Feistel, hoán đổi rồi áp dụng `FP` để sinh bản mã.
2. `attack.py` chọn nhiều input difference tốt từ DDT của từng Sbox, sinh trước các cặp chosen-plaintext, gom toàn bộ bản rõ trong cùng một đợt thành danh sách, gọi `encrypt_many_blocks(...)` một lần rồi tiếp tục chấm điểm subkey như logic cũ.
3. `main_key.py` nhận một ứng viên `khóa vòng`, đảo ngược key schedule vòng 1 để tạo các `khóa chính` 64 bit khả thi.
4. `demo2.py` tự động hóa toàn bộ quá trình và in thêm tổng thời gian chạy ở dòng cuối.

## Yêu cầu môi trường

- Python 3
- Không cần cài thêm thư viện ngoài

## Cách chạy

### 1. Chạy Oracle mã hóa 1 vòng từ command line

```powershell
python des_1_round_oracle.py 0123456789ABCDEF
```

Kết quả:

```text
BAN_MA: ...
```

### 2. Dùng Oracle từ Python

```python
from des_1_round_oracle import encrypt_one_block, encrypt_many_blocks

c1 = encrypt_one_block("0123456789ABCDEF")
batch = encrypt_many_blocks([
    "0123456789ABCDEF",
    "7E1C60DAB4A9F554",
])
```

`encrypt_many_blocks(...)` giữ nguyên thứ tự bản mã theo thứ tự bản rõ đầu vào.

### 3. Chạy tấn công vi sai để tìm ứng viên khóa vòng

```powershell
python attack.py
```

Kết quả chính:

```text
BAN_RO_THAM_CHIEU: ...
BAN_MA_THAM_CHIEU: ...
SO_LUONG_UNG_VIEN_KHOA_VONG: ...
CAC_UNG_VIEN_KHOA_VONG:
...
```

### 4. Liệt kê ứng viên khóa chính từ một khóa vòng

```powershell
python main_key.py <ROUND_KEY_HEX> <PLAINTEXT_HEX> <CIPHERTEXT_HEX>
```

Ví dụ:

```powershell
python main_key.py 00000000C410 7E1C60DAB4A9F554 2F4930DBB5BDE010
```

Kết quả:

```text
SO_LUONG_UNG_VIEN_KHOA_CHINH: ...
CAC_UNG_VIEN_KHOA_CHINH:
...
```

### 5. Chạy toàn bộ pipeline tự động

```powershell
python demo2.py
```

Kết quả sẽ có dạng:

```text
SO_LUONG_UNG_VIEN_KHOA_VONG: ...
DANG_THU_KHOA_VONG 1/N: ...
KHOA_VONG_PHU_HOP: ...
SO_LUONG_UNG_VIEN_KHOA_CHINH: ...
CAC_UNG_VIEN_KHOA_CHINH:
...
TONG_THOI_GIAN_CHAY_GIAY: ...
```

## Debug

- `DEBUG` nằm trong `des_utils.py`.
- Khi `DEBUG = True`, các log bổ sung được in ra `stderr` để không làm hỏng output chính mà `demo2.py` phân tích.
- Trong chế độ batch, Oracle có thể in thêm:

  ```text
  SO_LAN_GOI_BATCH_ORACLE=...
  SO_LUONG_BAN_RO=...
  ```

## Ghi chú

- Với DES chỉ 1 vòng, một `khóa vòng` 48 bit không xác định duy nhất `khóa chính` 64 bit. Vì vậy `main_key.py` có thể trả về nhiều khóa hợp lệ.

