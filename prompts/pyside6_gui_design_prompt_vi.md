# Prompt thiết kế GUI PySide6 (Dark Mode Only)

Sao chép nguyên văn prompt dưới đây để yêu cầu AI thiết kế lại giao diện PySide6 đồng nhất với flow hệ thống của dự án:

```text
Bạn là Senior Python Desktop Engineer + UX Engineer cho dự án cybersecurity "Ransomware Detector v2".

Hãy thiết kế và triển khai GUI bằng PySide6 với tiêu chí:
1) Giao diện chuyên nghiệp, dễ dùng cho SOC analyst/người dùng kỹ thuật.
2) Dark mode only (tuyệt đối không light mode, không toggle theme).
3) Luồng UI phải đồng nhất với hệ thống hiện tại của dự án.
4) Giữ đầy đủ chức năng hiện có, không cắt giảm feature.

## Bối cảnh hệ thống (phải bám sát)
- Ứng dụng phát hiện ransomware đa lớp: ML Engine + YARA + Process Behavior + Real-time Watchdog + Network Analysis + Auto-response.
- Các module nghiệp vụ nằm ở `core/`, GUI hiện tại ở `gui/main_window.py`, `gui/whitelist_editor.py`, `gui/tray_manager.py` (đúng theo cấu trúc hiện tại của dự án).
- Cần tương thích flow quét thủ công, quét real-time, xuất báo cáo, quản lý whitelist, quản lý ngưỡng threshold và cảnh báo hành vi.

## Yêu cầu bố cục (layout phải nhất quán)
- Header: Logo + Title + Version + trạng thái hệ thống.
- Left panel:
  - Chọn thư mục quét
  - Chọn scan mode (Full/Quick/Incremental)
  - Threshold slider (0.30 - 0.95)
    - Đây là ngưỡng confidence để gắn nhãn nguy cơ.
    - Giá trị thấp hơn = nhạy hơn/nhiều cảnh báo hơn.
    - Giá trị cao hơn = chặt hơn/ít cảnh báo hơn.
    - Giá trị khuyến nghị mặc định: 0.65.
  - Action buttons (Start Scan / Start Protection / Stop / Export)
  - Các block stats (files analyzed, threats, FP stats)
  - Entry points: Whitelist, ML Engine info, Network analysis, Auto-response
- Right panel:
  - Bảng kết quả với cột: Status | File | Path | Risk | Prob | Hash
  - Có filter/sort cơ bản, màu risk rõ ràng
- Bottom:
  - Log console realtime (timestamp, level, message)

## Design system (dark cyber style)
- Dùng tông màu dark cyber đồng nhất:
  - bg_dark: #0B0F14
  - bg_panel: #121821
  - bg_card: #161E29
  - border: #263042
  - text: #E6EAF0
  - text_dim: #A3ADBD
  - accent: #3B82F6
  - green: #22C55E
  - red: #EF4444
  - orange: #F59E0B
  - yellow: #FACC15
  - cyan: #22D3EE
- Quy ước sử dụng màu:
  - `bg_panel`: nền khối chức năng chính; `bg_card`: nền thẻ thông tin con bên trong panel.
  - `text`: nội dung chính; `text_dim`: label phụ, metadata, trạng thái ít ưu tiên.
- Mapping mức độ rủi ro:
  - CRITICAL: red
  - HIGH: orange
  - MEDIUM: yellow
  - LOW: cyan
  - SAFE: green
  - Với các màu risk hiển thị chữ/icon trên nền tối, phải kiểm tra contrast ratio tối thiểu theo WCAG AA cho từng cặp màu sử dụng thực tế.

## Yêu cầu UX
- Tất cả flow phải “one-click clear”, hạn chế thao tác thừa.
- Nút hành động chính nổi bật, trạng thái disable/enable rõ.
- Có loading/progress khi scan.
- Có empty state, error state, success state rõ ràng.
- Log và cảnh báo phải dễ đọc trong điều kiện ánh sáng thấp.
- Kiểm tra và đảm bảo tương phản màu đạt tối thiểu WCAG AA cho text chính/phụ trên nền tối.
  - Tối thiểu 4.5:1 cho text thường, 3:1 cho text lớn.
  - Ví dụ: `text (#E6EAF0) trên bg_dark (#0B0F14) ~ 16:1`.
  - Ví dụ: `text_dim (#A3ADBD) trên bg_panel (#121821) ~ 7:1`.

## Yêu cầu kỹ thuật PySide6
- Sử dụng kiến trúc tách lớp rõ ràng (UI / Controller / Service integration).
- Không hardcode business logic trong UI widget.
- Sử dụng signal/slot chuẩn cho cập nhật realtime từ scanner/watchdog thread.
- Thread-safe khi update bảng kết quả và log console.
- Chuẩn bị reusable components: HeaderWidget, ControlPanel, ResultTable, LogConsole, StatusBadge.

## Feature parity bắt buộc
- Manual Scan + Realtime Protection
- Threshold tuning
- Whitelist editor integration
- Behavior alert popup
- Export CSV/PNG/PDF
- System tray integration
- Network analysis summary view
- Auto-response controls (quarantine/kill process policy)

## Output bạn phải trả về
1) Đề xuất kiến trúc thư mục PySide6.
2) Wireframe mô tả từng màn hình/chế độ.
3) Danh sách component + trách nhiệm.
4) Bộ style guide dark mode (typography, spacing, color usage).
   - Kèm bảng contrast ratio cho các cặp màu text/nền chính để chứng minh đạt WCAG AA.
5) Skeleton code PySide6 chạy được (entry point + main window + signal/slot mẫu).
6) Mapping chi tiết từ flow cũ sang flow mới để đảm bảo đồng nhất hệ thống.
7) Checklist test thủ công cho toàn bộ luồng chính.

Lưu ý quan trọng:
- Không dùng light mode.
- Không làm thay đổi nghiệp vụ detection hiện có.
- Ưu tiên tính ổn định, rõ ràng, dễ vận hành trong môi trường an ninh.
```
