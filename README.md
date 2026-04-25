# Ransomware Detector v2.0 - PTIT Security Research Lab

> **Công cụ phát hiện và ngăn chặn Ransomware đa lớp mạnh mẽ.** 
> Kết hợp Machine Learning, Phân tích hành vi, YARA Rules và Threat Intelligence để bảo vệ hệ thống thời gian thực.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)

---

## 🌟 Tính năng nổi bật

Dự án cung cấp một giải pháp bảo mật toàn diện với 8 lớp phòng thủ chính:

1.  **ML Engine (Random Forest):** Phân tích 16 đặc trưng (features) như Entropy, Chi-Square, phân bố byte để nhận diện file bị mã hóa.
2.  **Real-time Protection:** Giám sát thay đổi file hệ thống bằng `watchdog`, phát hiện các đợt bùng phát mã hóa (Encryption Burst).
3.  **Process Monitoring:** Theo dõi hành vi các tiến trình (Burst IO, Extension Change, Rapid Rename) để ngăn chặn mã độc đang thực thi.
4.  **PE Analysis:** Phân tích cấu trúc file thực thi (.exe, .dll), phát hiện Packer (UPX, VMProtect...) và các API nguy hiểm.
5.  **Threat Intelligence:** Tích hợp tra cứu hash trên **VirusTotal**, **MalwareBazaar**, **ThreatFox** và **AlienVault OTX**.
6.  **YARA Engine:** Quét chữ ký nhận diện các dòng Ransomware nổi tiếng (WannaCry, LockBit, BlackCat, REvil...).
7.  **Honeypot/Decoy Files:** Tự động triển khai các file "mồi" để bẫy và phát hiện Ransomware ngay khi chúng bắt đầu hành động.
8.  **Auto-Response & Quarantine:** Tự động cô lập file nghi vấn, kết thúc tiến trình độc hại và chặn mạng qua Windows Firewall.

---

## 🏗️ Kiến trúc hệ thống

```text
┌─────────────────────────────────────────────────────────┐
│                   Ransomware Detector v2.0              │
│      (GUI - CustomTkinter / CLI - Python Argparse)      │
└───────────┬─────────────────────────────────────┬───────┘
            │                                     │
    ┌───────▼───────┐                     ┌───────▼───────┐
    │  Monitoring   │                     │    Scanner    │
    │  (Watchdog)   │                     │ (Multi-thread)│
    └───────┬───────┘                     └───────┬───────┘
            │                                     │
            └───────────────┬─────────────────────┘
                            │
            ┌───────────────▼──────────────────────────┐
            │          CORE ANALYSIS PIPELINE          │
            │  1. Whitelist Check (FP Reduction)       │
            │  2. Feature Extraction (16 features)     │
            │  3. ML Prediction (Random Forest)        │
            │  4. PE & YARA Structural Analysis        │
            │  5. Global Threat Intel (VT, MB, TF)     │
            └───────────────┬──────────────────────────┘
                            │
            ┌───────────────▼──────────────────────────┐
            │          RESPONSE & REPORTING            │
            │  • Quarantine / Process Kill             │
            │  • Toast Notification (Windows)          │
            │  • Detailed CSV/PDF Report               │
            └──────────────────────────────────────────┘
```

---

## 🚀 Cài đặt

### Yêu cầu
- Windows 10/11
- Python 3.10 trở lên

### Các bước cài đặt
1. **Clone repository:**
   ```bash
   git clone https://github.com/haquan/ransomware-detector-v2.git
   cd ransomware-detector-v2
   ```

2. **Tạo môi trường ảo và cài đặt thư viện:**
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Cấu hình API Keys:**
   - Copy file `data/config.json.template` thành `data/config.json`.
   - Điền API Keys cho VirusTotal, ThreatFox, AlienVault OTX vào file `config.json`.

---

## 📖 Hướng dẫn sử dụng

### 1. Giao diện đồ họa (GUI)
Khởi chạy ứng dụng với giao diện hiện đại:
```bash
python main.py
```
- **Dashboard:** Theo dõi trạng thái hệ thống.
- **Scan:** Quét thư mục tùy chỉnh (Full scan hoặc Incremental).
- **Honeypot:** Triển khai file mồi bảo vệ các thư mục quan trọng.
- **ML Training:** Giao diện huấn luyện lại model từ dữ liệu mới.

### 2. Giao diện dòng lệnh (CLI)
Quét thư mục nhanh chóng:
```bash
python main.py --scan C:\Users\Public\Documents
```

### 3. Quy trình huấn luyện Model nâng cao (Advanced Training Workflow)
Dự án tích hợp bộ công cụ quản lý dữ liệu huấn luyện PE-only:
- **Tìm kiếm nguồn dữ liệu:** `python main.py --search-training-sources --query "malware"`
- **Lập kế hoạch thu thập:** `python main.py --plan-training-source --scale pilot`
- **Tải và chuẩn bị dữ liệu:** `python main.py --prepare-training-source --source-id ID --kind safe`
- **Huấn luyện từ kế hoạch:** `python main.py --train-from-source-plan --scale pilot`

---

## ⚙️ Cấu hình (data/config.json)

Hệ thống cho phép tùy chỉnh sâu qua file cấu hình:
- `ml`: Ngưỡng phát hiện (threshold), tham số Random Forest.
- `scanner`: Số luồng xử lý, giới hạn kích thước file.
- `watchdog`: Thời gian debounce, kích thước hàng đợi.
- `notifications`: Bật/tắt thông báo và âm thanh cảnh báo.
- `virustotal` & `threat_intel`: Cấu hình API Keys và Rate limits.

---

## 🧪 Kiểm thử (Testing)

Sử dụng `pytest` để chạy các bản test:
```bash
pytest tests/
```
Hoặc kiểm tra độ bao phủ (coverage):
```bash
pytest tests/ --cov=core
```

---

## 🛡️ Tuyên bố miễn trừ trách nhiệm (Disclaimer)

Dự án này được phát triển cho mục đích nghiên cứu học thuật và thử nghiệm bảo mật. Chúng tôi không chịu trách nhiệm về bất kỳ thiệt hại nào do việc sử dụng phần mềm này gây ra trên hệ thống thực tế. Luôn sao lưu dữ liệu quan trọng trước khi thử nghiệm với các mẫu ransomware thật.

---

## 📝 License
Dự án được phát hành dưới giấy phép **MIT License**.

---
**PTIT Security Research Lab** - 2026
