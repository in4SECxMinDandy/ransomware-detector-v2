# Chạy MalwareBazaar Pipeline

## Bước 1: Kích hoạt Virtual Environment

Mở PowerShell hoặc CMD trong thư mục project:

```powershell
cd c:\Users\haqua\Documents\GitHub\ransomware-detector-v2
.venv\Scripts\Activate.ps1
```

Hoặc CMD:
```cmd
cd c:\Users\haqua\Documents\GitHub\ransomware-detector-v2
.venv\Scripts\activate.bat
```

## Bước 2: Chạy Pipeline

### Option A: Tải 5GB đầy đủ (sẽ mất nhiều thời gian)
```bash
python scripts\pipeline_download_and_train.py --total-size-gb 5 --pe-ratio 0.7 --rate-limit 1.0
```

### Option B: Tải 1GB trước để test
```bash
python scripts\pipeline_download_and_train.py --total-size-gb 1 --pe-ratio 0.7 --rate-limit 1.0
```

### Option C: Chỉ train với synthetic (không download)
```bash
python scripts\pipeline_download_and_train.py --train-synthetic
```

## Thông số quan trọng

| Tham số | Mô tả | Giá trị mặc định |
|---------|-------|------------------|
| `--total-size-gb` | Tổng GB mục tiêu | 5.0 |
| `--pe-ratio` | Tỉ lệ PE (còn lại là Office) | 0.7 (70%) |
| `--rate-limit` | Giây giữa các request | 1.0 |
| `--skip-download` | Bỏ qua download, chỉ train | false |
| `--train-synthetic` | Train với synthetic data | false |
| `--reset-tags` | Reset và query lại tags | false |

## Lưu ý quan trọng

1. **Rate Limit**: MalwareBazaar giới hạn ~100 files/ngày cho community users
2. **Thời gian**: Tải 5GB có thể mất 1-2 tuần do rate limit
3. **Resume**: Pipeline tự động save progress, chạy lại sẽ tiếp tục
4. **API Key**: Không cần API key cho download cơ bản (query + download public samples)

## Cấu trúc output

```
datasets/sources/encrypted/malwarebazaar/
├── pe/                    # File PE (.exe, .dll, .sys, .msi)
├── office/                # File Office
├── _daily_csvs/           # CSV metadata
└── _pipeline_progress.json # Progress tracking
```

## Theo dõi tiến trình

```bash
python main.py --training-progress --scale pilot
```

## Sau khi tải xong

Pipeline tự động:
1. Trích xuất 16 features từ file PE
2. Kết hợp với synthetic SAFE data
3. Train Random Forest model
4. Lưu model vào `models/`
