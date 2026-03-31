import collections
import random

# ==========================================================
# 1. CẤU HÌNH THÔNG SỐ CHUẨN CỦA DES (S-BOXES, E, P)
# ==========================================================

# 8 S-boxes chuẩn của DES
S_BOXES = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
]

# Bảng mở rộng E
E_TABLE = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
]

# Bảng hoán vị P
P_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
]

# ==========================================================
# 2. CÁC HÀM XỬ LÝ BIT TUYẾN TÍNH
# ==========================================================

def apply_table(val, table, input_len):
    res = 0
    for i in table:
        res = (res << 1) | ((val >> (input_len - i)) & 0x01)
    return res

def get_pbox_inv():
    p_inv = [0] * 32
    for i, pos in enumerate(P_TABLE):
        p_inv[pos-1] = i + 1
    return p_inv

P_INV_TABLE = get_pbox_inv()

def sbox_lookup(val_6bit, sbox_idx):
    sbox = S_BOXES[sbox_idx]
    row = ((val_6bit >> 4) & 0x02) | (val_6bit & 0x01)
    col = (val_6bit >> 1) & 0x0F
    return sbox[row * 16 + col]

# ==========================================================
# 3. GIẢ LẬP MÃ HÓA 1 VÒNG (ORACLE)
# ==========================================================

def des_round_f(r_32bit, key_48bit):
    """Hàm f của DES: E -> XOR Key -> S-boxes -> P"""
    expanded = apply_table(r_32bit, E_TABLE, 32)
    xor_key = expanded ^ key_48bit
    sbox_out = 0
    for i in range(8):
        chunk = (xor_key >> (6 * (7-i))) & 0x3F
        sbox_out = (sbox_out << 4) | sbox_lookup(chunk, i)
    return apply_table(sbox_out, P_TABLE, 32)

def encrypt_1_round(l0, r0, key_48bit):
    """1 vòng DES: L1 = R0, R1 = L0 XOR f(R0, K)"""
    l1 = r0
    r1 = l0 ^ des_round_f(r0, key_48bit)
    return l1, r1

# ==========================================================
# 4. THUẬT TOÁN THÁM MÃ (VOTING)
# ==========================================================

def attack_1_round(pairs_data):
    # Bảng đếm tần suất key xuất hiện của 8 vùng
    voting_tables = [collections.Counter() for _ in range(8)]

    for l0, r0, l1, r1, l0s, r0s, l1s, r1s in pairs_data:
        # f' = delta_R1 ^ delta_L0
        f_prime = (r1 ^ r1s) ^ (l0 ^ l0s)
        # y' = P_inv(f')
        y_all_prime = apply_table(f_prime, P_INV_TABLE, 32)

        # tinh sai phan dau vao
        # R0'
        r0_prime = r0 ^ r0s
        #X'
        x_all_prime = apply_table(r0_prime, E_TABLE, 32)
        e_r0 = apply_table(r0, E_TABLE, 32)

        for i in range(8):
            xi_prime = (x_all_prime >> (6 * (7-i))) & 0x3F
            yi_prime = (y_all_prime >> (4 * (7-i))) & 0x0F
            ei_r0 = (e_r0 >> (6 * (7-i))) & 0x3F
            
            for x_val in range(64):
                if sbox_lookup(x_val, i) ^ sbox_lookup(x_val ^ xi_prime, i) == yi_prime:
                    voting_tables[i][x_val ^ ei_r0] += 1

    recovered_key = 0
    print("\n--- KẾT QUẢ KHÔI PHỤC TỪNG S-BOX ---")
    for i in range(8):
        best_k, votes = voting_tables[i].most_common(1)[0]
        recovered_key = (recovered_key << 6) | best_k
        print(f"S-box {i+1}: Key {hex(best_k)} | Số phiếu: {votes}")
    
    return recovered_key

# ==========================================================
# 5. THỰC THI (MAIN)
# ==========================================================

if __name__ == "__main__":
    # Bước 1: Tạo khóa bí mật ngẫu nhiên (48-bit)
    SECRET_KEY = random.getrandbits(48)
    print(f"[!] Khóa bí mật Oracle đang giữ: {hex(SECRET_KEY)}")

    # Bước 2: Tạo dữ liệu mẫu (15 cặp bản rõ)
    print("[*] Đang thu thập 15 cặp bản rõ/bản mã...")
    test_pairs = []
    for _ in range(15):
        # Chọn đại một sai phân tốt (ví dụ 0x34 cho mọi S-box để dễ nổ)
        # 0x343434343434 (48-bit) -> 32-bit tương ứng qua E
        dx_32 = random.getrandbits(32) 
        
        p1_l0, p1_r0 = random.getrandbits(32), random.getrandbits(32)
        p2_l0, p2_r0 = p1_l0, p1_r0 ^ dx_32 # Giữ L0 giống nhau (L0'=0)
        
        c1_l1, c1_r1 = encrypt_1_round(p1_l0, p1_r0, SECRET_KEY)
        c2_l1, c2_r1 = encrypt_1_round(p2_l0, p2_r0, SECRET_KEY)
        
        test_pairs.append((p1_l0, p1_r0, c1_l1, c1_r1, p2_l0, p2_r0, c2_l1, c2_r1))

    # Bước 3: Tấn công
    recovered = attack_1_round(test_pairs)

    print("\n" + "="*40)
    print(f"KHÓA GỐC:      {hex(SECRET_KEY).upper()}")
    print(f"KHÓA KHÔI PHỤC: {hex(recovered).upper()}")
    if SECRET_KEY == recovered:
        print(">>> THÀNH CÔNG! ĐÃ PHÁ ĐƯỢC KHÓA 1 VÒNG DES.")
    else:
        print(">>> THẤT BẠI. CẦN THÊM DỮ LIỆU HOẶC KIỂM TRA LẠI SAI PHÂN.")