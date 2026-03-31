# Mảng S-box 4 của DES (Dạng chuẩn)
S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
]

def sbox_lookup(sbox, input_6bit):
    """Tra cứu S-box theo chuẩn DES (Bit 0 & 5 chọn hàng, 1-4 chọn cột)"""
    row = ((input_6bit >> 5) << 1) | (input_6bit & 0x01)
    col = (input_6bit >> 1) & 0x0F
    return sbox[row][col]

def generate_ddt(sbox):
    """Tạo bảng DDT 64x16"""
    ddt = [[0 for _ in range(16)] for _ in range(64)]
    for x1 in range(64):
        for x2 in range(64):
            dx = x1 ^ x2
            dy = sbox_lookup(sbox, x1) ^ sbox_lookup(sbox, x2)
            ddt[dx][dy] += 1
    return ddt

def find_high_probs(ddt):
    """Lấy danh sách các cặp sai phân, sắp xếp theo xác suất giảm dần"""
    probs = []
    for dx in range(64):
        for dy in range(16):
            # Loại bỏ trường hợp hiển nhiên dx=0, dy=0 (xác suất 64/64)
            if dx == 0: continue 
            if ddt[dx][dy] > 0:
                probs.append((dx, dy, ddt[dx][dy]))
    
    # Sắp xếp theo giá trị count (phần tử thứ 3 của tuple) giảm dần
    probs.sort(key=lambda x: x[2], reverse=True)
    return probs

def find_pairs(sbox, dx, dy):
    """Tìm các cặp duy nhất (X1, X2) thỏa mãn sai phân"""
    pairs = []
    for x1 in range(64):
        x2 = x1 ^ dx
        if sbox_lookup(sbox, x1) ^ sbox_lookup(sbox, x2) == dy:
            # Chỉ thêm vào nếu chưa có cặp đảo ngược để tránh trùng lặp
            if (x2, x1) not in pairs:
                pairs.append((x1, x2))
    return pairs

# --- THỰC THI ---

ddt_s4 = generate_ddt(S4)

print("--- TOP CÁC CẶP SAI PHÂN TỐT NHẤT (S-BOX 4) ---")
high_probs = find_high_probs(ddt_s4)
print(f"{'Input XOR':<12} | {'Output XOR':<12} | {'Tần suất':<10}")
print("-" * 40)
for dx, dy, count in high_probs[:15]: # In ra top 15 cặp tốt nhất
    print(f"{hex(dx):<12} | {hex(dy):<12} | {count:>2}/64")

print("=== TRUY VẤN CẶP SAI PHÂN S-BOX 4 ===")
while True:
    try:
        raw_dx = input("\nNhập Input XOR (X') [VD: 0x2a]: ").strip().lower()
        if raw_dx == 'q': break
        raw_dy = input("Nhập Output XOR (Y') [VD: 0x0c]: ").strip().lower()
        if raw_dy == 'q': break

        user_dx = int(raw_dx, 16)
        user_dy = int(raw_dy, 16)
        
        matching_pairs = find_pairs(S4, user_dx, user_dy)
        count_in_ddt = ddt_s4[user_dx][user_dy]
        
        print(f"\n[+] Tần suất trong DDT: {count_in_ddt}/64")
        print(f"[+] Tìm thấy {len(matching_pairs)} cặp (X1, X2) thỏa mãn:")
        print(f"(X1, X2 có thể đổi chỗ cho nhau)")
        print("-" * 60)
        
        for x1, x2 in matching_pairs:
            # Hiển thị cả X1 và X2 để user dễ kiểm tra XOR
            s1 = bin(x1)[2:].zfill(6)
            s2 = bin(x2)[2:].zfill(6)
            print(f"Cặp: ({hex(x1)}, {hex(x2)})")
                
    except ValueError:
        print(" [!] Lỗi: Nhập định dạng Hex hoặc 'q'.")