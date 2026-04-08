# Demo Tham Ma Vi Sai Tren DES Rut Gon 1 Vong

Bo chuong trinh nay mo phong quy trinh thuc hien tham ma vi sai tren DES rut gon 1 vong, khong dung thu vien ma hoa ngoai. Toan bo bang DES nhu `IP`, `FP`, `E`, `P`, `S-boxes`, `PC-1`, `PC-2` va `shift schedule` duoc cai dat thu cong trong ma nguon.

## Cau truc file

- `des_1_round_oracle.py`: oracle ma hoa DES 1 vong. File nay hard-code `main key` hieu dung 56 bit, chen parity DES odd parity de tao khoa 64 bit, sinh round key vong 1, va tra ve ciphertext tu plaintext dau vao.
- `attack.py`: chosen-plaintext differential attack. File nay tu xay DDT cho 8 S-box, tao cac cap plaintext co vi sai phu hop, goi oracle, cham diem subkey tung S-box, va sinh toan bo `round key` candidates.
- `main_key.py`: tu `round key` 48 bit, dao `PC-2`, vet can cac bit chua biet, chen parity, ma hoa lai va liet ke tat ca `main key` candidates hop le.
- `demo2.py`: file dieu phoi toan bo pipeline. File nay chay `attack.py`, parse danh sach `round key` candidates, sau do goi `main_key.py` cho tung round key va in ket qua cuoi cung.
- `des_tables.py`: chua toan bo bang DES chuan.
- `des_utils.py`: cac ham dung chung cho xu ly bit, hoan vi, key schedule, F-function, va ma hoa DES 1 vong.

## Quy trinh thuc hien

1. `des_1_round_oracle.py` nhan plaintext 64 bit, ap dung `IP`, thuc hien 1 vong Feistel, swap, roi ap dung `FP` de sinh ciphertext.
2. `attack.py` chon nhieu input difference tot tu DDT cua tung S-box, tao nhieu batch chosen-plaintext pairs, thong ke score cho 64 ung vien subkey 6 bit moi S-box, giu lai tat ca ung vien dong hang cao nhat, roi ghep thanh danh sach `round key` candidates 48 bit.
3. `main_key.py` nhan mot `round key` candidate, dao nguoc key schedule vong 1 de tao cac `main key` 64 bit kha thi, sau do verify lai bang cap plaintext/ciphertext tham chieu.
4. `demo2.py` tu dong hoa toan bo qua trinh va in them tong thoi gian chay o dong cuoi.

## Yeu cau moi truong

- Python 3
- Khong can cai them thu vien ngoai

## Cach chay

### 1. Chay oracle ma hoa 1 vong

```powershell
python des_1_round_oracle.py 0123456789ABCDEF
```

Output:

```text
CIPHERTEXT: ...
```

Neu `DEBUG = True` trong `des_utils.py`, oracle se in them `effective main key`, `main key 64 bit`, va `round key`.

### 2. Chay tan cong vi sai de tim round key candidates

```powershell
python attack.py
```

Output chinh:

```text
REFERENCE_PLAINTEXT: ...
REFERENCE_CIPHERTEXT: ...
ROUND_KEY_CANDIDATE_COUNT: ...
ROUND_KEY_CANDIDATES:
...
```

### 3. Liet ke main key candidates tu mot round key

```powershell
python main_key.py <ROUND_KEY_HEX> <PLAINTEXT_HEX> <CIPHERTEXT_HEX>
```

Vi du:

```powershell
python main_key.py 00000000C410 7E1C60DAB4A9F554 2F4930DBB5BDE010
```

Output:

```text
MAIN_KEY_CANDIDATE_COUNT: ...
MAIN_KEY_CANDIDATES:
...
```

### 4. Chay toan bo pipeline tu dong

```powershell
python demo2.py
```

Output se co dang:

```text
ROUND_KEY_CANDIDATE_COUNT: ...
TRYING_ROUND_KEY 1/N: ...
MATCHED_ROUND_KEY(S): ...
MAIN_KEY_CANDIDATE_COUNT: ...
MAIN_KEY_CANDIDATES:
...
TOTAL_RUNTIME_SECONDS: ...
```

## Ghi chu

- Voi DES chi 1 vong, mot `round key` 48 bit khong xac dinh duy nhat `main key` 64 bit. Vi vay `main_key.py` co the tra ve nhieu khoa hop le.
- Trong che do `DEBUG`, mot so file se in them log phan tich ra `stderr` de ho tro kiem tra.
