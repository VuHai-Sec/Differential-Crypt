import collections

# S-box S4 chuẩn của DES
S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
]

def sbox_lookup(input_6bit):
    row = ((input_6bit >> 5) << 1) | (input_6bit & 0x01)
    col = (input_6bit >> 1) & 0x0F
    return S4[row][col]

def generate_ddt():
    ddt = [[0 for _ in range(16)] for _ in range(64)]
    for x1 in range(64):
        for x2 in range(64):
            ddt[x1 ^ x2][sbox_lookup(x1) ^ sbox_lookup(x2)] += 1
    return ddt

# --- HÀM THÁM MÃ TỰ ĐỘNG ---

def automated_attack():
    ddt = generate_ddt()
    
    # 1. User thiết lập khóa bí mật
    try:
        secret_key = int(input("[?] Thiết lập khóa bí mật (6-bit, Hex - VD: 0x2b): "), 16) & 0x3F
    except:
        print("Lỗi định dạng. Dùng mặc định 0x2b"); secret_key = 0x2b

    # 2. Chọn ra Top các sai phân tốt nhất từ DDT (loại bỏ dx=0)
    # Cấu trúc: (xác suất, dx, dy)
    best_diffs = []
    for dx in range(1, 64):
        for dy in range(16):
            if ddt[dx][dy] >= 10: # Chỉ lấy các cặp có tần suất >= 10/64
                best_diffs.append((ddt[dx][dy], dx, dy))
    best_diffs.sort(reverse=True) # Sắp xếp giảm dần theo xác suất

    # Giới hạn lấy 3 sai phân đầu vào khác nhau để demo
    target_diffs = []
    seen_dx = set()
    for prob, dx, dy in best_diffs:
        if dx not in seen_dx:
            target_diffs.append((dx, dy, prob))
            seen_dx.add(dx)
        if len(target_diffs) == 3: break

    print(f"\n[*] Hệ thống chọn 3 chiến lược sai phân: " + ", ".join([hex(d[0]) for d in target_diffs]))
    
    # 3. Tiến hành Voting
    votes = collections.Counter()
    pairs_per_diff = 4 # Mỗi loại sai phân thử 4 cặp bản rõ khác nhau
    
    print(f"[*] Đang thực hiện tấn công (Tổng cộng {len(target_diffs) * pairs_per_diff} cặp)...")

    for dx, dy_expected, prob in target_diffs:
        for i in range(pairs_per_diff):
            # Tạo bản rõ ngẫu nhiên p1, p2 sao cho p1 ^ p2 = dx
            p1 = (i * 13 + dx) % 64
            p2 = p1 ^ dx
            
            # Giả lập Oracle trả về bản mã (chứa khóa bí mật)
            c1 = sbox_lookup(p1 ^ secret_key)
            c2 = sbox_lookup(p2 ^ secret_key)
            dy_observed = c1 ^ c2
            
            # Tra cứu các cặp X thỏa mãn sai phân quan sát được
            for x1 in range(64):
                if sbox_lookup(x1) ^ sbox_lookup(x1 ^ dx) == dy_observed:
                    # Suy ra ứng viên khóa: K = X ^ P
                    k_candidate = x1 ^ p1
                    votes[k_candidate] += 1

    # 4. Hiển thị kết quả
    print("\n[+] KẾT QUẢ PHÂN TÍCH THỐNG KÊ (VOTING):")
    print("-" * 45)
    print(f"{'Ứng viên Key':<15} | {'Số phiếu':<10} | {'Trạng thái'}")
    
    top_results = votes.most_common(8)
    for k, count in top_results:
        is_real = "<- CHÍNH XÁC!" if k == secret_key else ""
        print(f"{hex(k):<15} | {count:<10} | {is_real}")

if __name__ == "__main__":
    automated_attack()