# Hướng dẫn Thu thập Dữ liệu Thật để Training

> Tài liệu này mô tả quy trình thu thập dữ liệu **thật** (real-world PE files)
> để train model phát hiện ransomware. Dữ liệu synthetic (giả) đã bị loại bỏ hoàn toàn.

---

## Tổng quan Pipeline

```
Bước 1: Thu thập SAFE samples
  collect_safe_samples.py
  → Windows System32, SysWOW64 PE files (EXE/DLL/SYS)
  → datasets/prepared/external_pe/safe/

Bước 2: Thu thập MALWARE samples
  collect_malware_samples.py
  → MalwareBazaar API (ransomware + trojans thật)
  → datasets/prepared/external_pe/encrypted/

Bước 3: Train model với dữ liệu thật
  train_model.py --safe-dir ... --malware-dir ...
  → Feature extraction → SMOTE → Random Forest → models/
```

---

## Bước 1: Thu thập SAFE Samples

Script `collect_safe_samples.py` sao chép PE files từ thư mục Windows hệ thống.
Đây là các file đã được Microsoft ký số — 100% an toàn để dùng làm nhãn SAFE.

### Chạy cơ bản (khuyến nghị)

```bash
python collect_safe_samples.py
```

- Lấy tối đa **3000 files** từ `C:\Windows\System32`, `SysWOW64`, `drivers`
- Chỉ lấy PE files: `.exe`, `.dll`, `.sys`
- Lọc theo kích thước: 4 KB – 50 MB
- Đầu ra: `datasets/prepared/external_pe/safe/`

### Tùy chỉnh

```bash
# Lấy nhiều hơn, bao gồm cả Program Files
python collect_safe_samples.py --max 5000 --include-program-files

# Chỉ lấy 500 files để test nhanh
python collect_safe_samples.py --max 500

# Thư mục output tùy chỉnh
python collect_safe_samples.py --output path/to/safe_dir
```

### Kết quả mong đợi

```
Safe files   : ~3000 files
  Source     : C:\Windows\System32\*.exe, *.dll, *.sys
               C:\Windows\SysWOW64\*.exe, *.dll, *.sys
               C:\Windows\System32\drivers\*.sys
```

---

## Bước 2: Thu thập MALWARE Samples

Script `collect_malware_samples.py` tải malware thật từ **MalwareBazaar** (abuse.ch).

> **Lưu ý bảo mật**: Script tải malware **thật** về máy tính của bạn.
> - Chạy trong môi trường **isolated** (VM, sandbox) nếu có thể
> - Các file tải về là malware thực, Windows Defender có thể xóa chúng
> - Cần tạm thời tắt AV hoặc thêm exclusion cho thư mục `datasets/`

### Yêu cầu

```bash
pip install requests
```

### Chạy cơ bản

```bash
python collect_malware_samples.py
```

Tải tối đa **2000 mẫu** từ 40+ tags (ransomware + trojans).
- Không cần API key (anonymous, rate limit ~15 req/min)
- Tự động giải nén ZIP với password `infected`
- Chỉ lưu PE files có MZ header hợp lệ

### Tùy chỉnh

```bash
# Chỉ tải ransomware (không trojan)
python collect_malware_samples.py \
  --tags lockbit blackcat alphv ransomware wannacry ryuk conti \
         revil hive blackbasta maze clop babuk dharma phobos stop \
  --max-per-tag 100 \
  --max-total 1500

# Tải ít hơn để test nhanh
python collect_malware_samples.py --max-total 100 --max-per-tag 10

# Dùng API key để tăng rate limit (đăng ký tại bazaar.abuse.ch)
python collect_malware_samples.py --api-key YOUR_KEY

# Tiếp tục từ lần tải trước
python collect_malware_samples.py --resume
```

### Kết quả mong đợi

```
Malware files: 500–2000 files
  Tags: lockbit, blackcat, wannacry, ryuk, conti, revil, ...
  Type: PE32/PE32+ (EXE/DLL) — malware thật
  Source: MalwareBazaar (abuse.ch)
```

### Troubleshooting

| Vấn đề | Giải pháp |
|--------|-----------|
| Windows Defender xóa files | Thêm exclusion: `datasets/prepared/external_pe/encrypted/` |
| Rate limit lỗi | Tăng `--delay 2.0` hoặc đăng ký API key |
| "No samples found" | Tag không còn samples mới; thử tag khác |
| Kết nối chậm | Giảm `--max-total`, tải nhiều lần |

---

## Bước 3: Train Model với Dữ liệu Thật

```bash
python train_model.py \
  --safe-dir datasets/prepared/external_pe/safe \
  --malware-dir datasets/prepared/external_pe/encrypted
```

### Tùy chỉnh training

```bash
# Không dùng SMOTE (nếu dataset đã cân bằng)
python train_model.py \
  --safe-dir datasets/prepared/external_pe/safe \
  --malware-dir datasets/prepared/external_pe/encrypted \
  --no-smote

# Lưu dataset features ra CSV để phân tích
python train_model.py \
  --safe-dir datasets/prepared/external_pe/safe \
  --malware-dir datasets/prepared/external_pe/encrypted \
  --output-csv data/real_dataset.csv
```

### Output của training

```
models/rf_ransomware_detector.joblib       ← Model đã train
models/rf_ransomware_detector.joblib.sha256 ← Checksum bảo mật
models/model_metadata.json                 ← Metrics + metadata
data/real_dataset.csv                      ← Dataset features (tùy chọn)
```

---

## Số lượng Dữ liệu Khuyến nghị

| Quy mô | SAFE | MALWARE | Thời gian | Chất lượng |
|--------|------|---------|-----------|-----------|
| Tối thiểu | 100 | 100 | ~5 phút | Chấp nhận được |
| Khuyến nghị | 1000 | 500 | ~30 phút | Tốt |
| Tốt nhất | 3000 | 1500 | ~2 giờ | Rất tốt |

**Lưu ý**: Với dữ liệu thật, không cần nhiều như dữ liệu synthetic vì chất lượng cao hơn nhiều. Model với 200 real samples thường tốt hơn model với 5000 synthetic samples.

---

## Cấu trúc Thư mục

```
datasets/
└── prepared/
    └── external_pe/
        ├── safe/
        │   ├── <sha256>.exe    ← Windows system PE files
        │   ├── <sha256>.dll
        │   └── <sha256>.sys
        └── encrypted/
            ├── <sha256>.exe    ← Malware PE files từ MalwareBazaar
            └── ...

data/
└── real_dataset.csv            ← Features extracted từ file thật

models/
├── rf_ransomware_detector.joblib
├── rf_ransomware_detector.joblib.sha256
└── model_metadata.json
```

---

## Kiểm tra chất lượng Dataset

Sau khi thu thập, kiểm tra dataset:

```bash
python -c "
import os
safe_dir = 'datasets/prepared/external_pe/safe'
mal_dir = 'datasets/prepared/external_pe/encrypted'
safe_n = sum(1 for f in os.scandir(safe_dir) if f.is_file()) if os.path.exists(safe_dir) else 0
mal_n = sum(1 for f in os.scandir(mal_dir) if f.is_file()) if os.path.exists(mal_dir) else 0
print(f'SAFE files   : {safe_n}')
print(f'MALWARE files: {mal_n}')
ratio = max(safe_n, mal_n) / max(min(safe_n, mal_n), 1)
print(f'Ratio        : {ratio:.1f}:1')
if ratio > 10:
    print('WARN: Class imbalance cao, SMOTE sẽ giúp cân bằng')
else:
    print('OK: Tỷ lệ class cân bằng tốt')
"
```

---

## Nguồn Dữ liệu Bổ sung (Nâng cao)

Nếu muốn thêm dữ liệu đa dạng hơn:

| Nguồn | Loại | Ghi chú |
|-------|------|---------|
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware PE | Đã tích hợp sẵn |
| [VirusTotal](https://www.virustotal.com) | Malware + SAFE | Cần API key trả phí |
| [theZoo](https://github.com/ytisf/theZoo) | Malware historical | Clone repo, dùng trong sandbox |
| [Malware Traffic Analysis](https://malware-traffic-analysis.net) | Malware PE | Tải thủ công |
| Windows Optional Features | SAFE PE | Cài thêm components Windows |

---

## Ghi chú Bảo mật

1. **Luôn chạy trong VM/sandbox** khi làm việc với malware thật
2. **Không share** thư mục `datasets/prepared/external_pe/encrypted/` — chứa malware thật
3. Thư mục `datasets/` đã được thêm vào `.gitignore` để không commit malware lên Git
4. **Windows Defender**: Cần thêm exclusion cho thư mục encrypted khi thu thập
