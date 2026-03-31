# des_attacker.py
import collections

S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
]

def sbox_lookup(input_6bit):
    input_6bit &= 0x3F
    row = ((input_6bit >> 5) << 1) | (input_6bit & 0x01)
    col = (input_6bit >> 1) & 0x0F
    return S4[row][col]

def main():
    print("--- [ATTACKER] THÁM MÃ THỦ CÔNG S-BOX 4 ---")
    votes = collections.Counter()
    pair_count = 0
    
    while True:
        try:
            print(f"\n[Cặp #{pair_count + 1}]")
            # Đầu vào như yêu cầu: P1, P2, C'
            p1_in = input("Nhập P1 (Hex, hoặc 'q' để kết thúc): ").strip().lower()
            if p1_in == 'q': break
            
            p2_in = input("Nhập P2 (Hex): ").strip()
            cp_in = input("Nhập C' (Hex): ").strip()
            
            p1 = int(p1_in, 16) & 0x3F
            p2 = int(p2_in, 16) & 0x3F
            c_prime = int(cp_in, 16) & 0x0F
            
            dx = p1 ^ p2
            pair_count += 1
            
            # Thử mọi giá trị X1 khả thi (0-63)
            for x1 in range(64):
                x2 = x1 ^ dx
                if sbox_lookup(x1) ^ sbox_lookup(x2) == c_prime:
                    # Nếu X1 ^ X2 cho ra C', thì K = X1 ^ P1 là một ứng viên
                    k_candidate = x1 ^ p1
                    votes[k_candidate] += 1
            
            # Xuất bảng Voting Top 5 mỗi lượt
            print("\n--- BẢNG VOTING KEY (TOP 5) ---")
            print(f"{'Hạng':<5} | {'Key (Hex)':<10} | {'Số phiếu':<10}")
            top_5 = votes.most_common(5)
            for i, (k, count) in enumerate(top_5):
                print(f"{i+1:<5} | {hex(k).upper():<10} | {count:<10}")
                
        except ValueError:
            print("Lỗi: Nhập sai định dạng Hex.")

    print("\n[!] Kết thúc quá trình thám mã.")

if __name__ == "__main__":
    main()