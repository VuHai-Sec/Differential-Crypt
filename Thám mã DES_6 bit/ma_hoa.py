# des_oracle.py

S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
]

def sbox_lookup(input_6bit):
    """Tra cứu S-box theo chuẩn DES (Bit 0 & 5 chọn hàng, 1-4 chọn cột)"""
    input_6bit &= 0x3F 
    row = ((input_6bit >> 5) << 1) | (input_6bit & 0x01)
    col = (input_6bit >> 1) & 0x0F
    return S4[row][col]

def main():
    print("--- [ORACLE] GIẢ LẬP MÃ HÓA DES S-BOX 4 ---")
    k = int(input("Nhập Key (Hex): "), 16) & 0x3F
    while (True):
        try:
            # Đầu vào như yêu cầu: key, p1, p2
            p1 = int(input("Nhập P1  (Hex): "), 16) & 0x3F
            p2 = int(input("Nhập P2  (Hex): "), 16) & 0x3F
            
            c1 = sbox_lookup(p1 ^ k)
            c2 = sbox_lookup(p2 ^ k)
            c_prime = c1 ^ c2
            
            # Đầu ra: c'
            print(f"\n[+] Kết quả: C' = {hex(c_prime).upper()}")
            print(f"    (Dùng giá trị {hex(c_prime).upper()} này để nhập vào công cụ thám mã)")
        except ValueError:
            print("Lỗi: Vui lòng nhập định dạng Hex.")
        

if __name__ == "__main__":
    main()