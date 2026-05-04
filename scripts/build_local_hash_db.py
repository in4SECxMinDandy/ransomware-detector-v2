import sqlite3
import os
import time

def build_db(txt_path, db_path):
    print(f"Bắt đầu đọc file {txt_path}...")
    start_time = time.time()
    
    # Kết nối SQLite (tự động tạo file nếu chưa có)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Tạo bảng và đánh Index (PRIMARY KEY giúp tra cứu O(1))
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_hashes (
            hash TEXT PRIMARY KEY
        )
    ''')
    
    # Tối ưu hóa SQLite cho việc chèn lượng lớn dữ liệu
    cursor.execute('PRAGMA synchronous = OFF')
    cursor.execute('PRAGMA journal_mode = MEMORY')
    
    # Xóa dữ liệu cũ nếu import lại
    cursor.execute('DELETE FROM malicious_hashes')
    
    batch_size = 200000
    batch = []
    count = 0
    
    try:
        with open(txt_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Bỏ qua dòng trống và dòng ghi chú bắt đầu bằng '#'
                if not line or line.startswith('#'):
                    continue
                
                # MalwareBazaar file format: each line is just the hash
                # Example: 49e3b6fae519cf4c5091a37d6be6d8c343412de11c73993c494d29e905d2bb6f
                batch.append((line.lower(),))
                count += 1
                
                # Chèn theo lô (Batch Insert) để tăng tốc độ tối đa
                if len(batch) >= batch_size:
                    cursor.executemany('INSERT OR IGNORE INTO malicious_hashes (hash) VALUES (?)', batch)
                    conn.commit()
                    print(f"Đã nhập {count:,} mã băm...")
                    batch = []
                    
        # Chèn phần còn dư
        if batch:
            cursor.executemany('INSERT OR IGNORE INTO malicious_hashes (hash) VALUES (?)', batch)
            conn.commit()
            print(f"Đã nhập {count:,} mã băm...")
            
        # Tối ưu hóa Database sau khi chèn xong
        print("Đang tối ưu hóa cơ sở dữ liệu (VACUUM)...")
        cursor.execute('VACUUM')
        
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file {txt_path}")
        return
        
    finally:
        conn.close()
        
    elapsed = time.time() - start_time
    print(f"\n✅ THÀNH CÔNG! Đã lưu {count:,} mã hash vào: {db_path}")
    print(f"⏱️ Thời gian thực thi: {elapsed:.2f} giây")

if __name__ == "__main__":
    # Đường dẫn file database và dữ liệu
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(PROJECT_ROOT, "data")
    TXT_PATH = os.path.join(DATA_DIR, "full_sha256.txt")
    DB_PATH = os.path.join(DATA_DIR, "malware_hashes.db")
    
    os.makedirs(DATA_DIR, exist_ok=True)
    build_db(TXT_PATH, DB_PATH)
