# myJB checkm8 tool (fork of openra1n)

Booter checkm8 (A7–A11) chạy Windows/Linux/macOS, phục vụ nhánh checkm8 của myJB.
Khác biệt so với openra1n gốc:

- **Gộp `boot.py` vào binary C** — không cần chạy python3 riêng sau khi pwn:
  sau khi boot PongoOS, tool tự gửi chuỗi palera1n (`fuse lock`, `sep auto`,
  `modload` KPF, `palera1n_flags`, `ramdisk`, `overlay`, `xargs rootdev=md0`, `bootx`).
- Binary tên `myjb_ktool(.exe)`, build Windows bằng MinGW trong CI.

## Trạng thái

- [x] checkm8 (gaster) + boot PongoOS + chuỗi palera1n trong 1 binary
- [ ] Tích hợp myJB (loader/kdev) — xem `../../Checkm8_myJB_Integration.md` (C4–C6)
- [ ] Payload pin + checksum (C2); nhánh iOS 12–14 (C7)

## Usage (Windows)

0. Đưa thiết bị vào **DFU**.
1. Gắn driver **libusbK** cho thiết bị DFU bằng **Zadig** (bắt buộc):
   chọn "Apple Mobile Device (DFU Mode)" (05AC 1227) → dropdown driver chọn
   **libusbK** → **Replace Driver**.
   - WinUSB **không đủ**: backend WinUSB của libusb không reset được device
     (chỉ cycle pipe) → tool treo ở heap spray.
   - UsbDk **không dùng được**: backend UsbDk của libusb 1.0.27 không hỗ trợ
     `cancel_transfer` (`NULL` trong `usbdk_backend`) — checkm8 cần abort
     control transfer đúng thời điểm từ stage 2 trở đi → tool đứng im ngay sau
     "Setting up the exploit". UsbDk reset thật nhưng thiếu cancel.
2. Chạy `myjb_ktool.exe` — tool tự chạy checkm8, boot PongoOS, và gửi chuỗi boot palera1n.
3. Khi tool báo đã gửi xong, thiết bị re-enumerate "Pongo USB Device" (05AC 4141):
   cài driver **libusbK** cho nó bằng Zadig.
   Mẹo: khi tool đang ở "Waiting for PongoOS device", chỉ cần mở Zadig →
   "Pongo USB Device" → Replace Driver → libusbK; tool đang chờ sẽ tự mở được
   thiết bị ngay, không phải chạy lại từ đầu.
4. Thiết bị boot vào jailbreak (palera1n rootless `/var/jb`). Cài bootstrap như bình thường.

> Lưu ý: checkm8 là semi-tethered — mỗi lần reboot phải chạy lại tool.
> iOS 15+ chỉ hỗ trợ chạy theo flow này; iOS 12–14 sẽ bổ sung sau (nhánh ra1npoc/legacy).

## Debug log (khi cửa sổ tự đóng)

Mọi log (bản không màu) được ghi vào `myjb_ktool.log` **cạnh exe**. Nếu tool
crash, log có thêm dòng `[FATAL]` kèm mã lỗi; log kết thúc bằng `[EXIT] process
exit code N`. Khi lỗi xảy ra mà chạy bằng double-click, cửa sổ sẽ dừng lại ở
"Press Enter to close this window..." để kịp đọc. Gửi kèm `myjb_ktool.log` khi
báo lỗi để chẩn đoán (đặc biệt với lỗi "tự thoát").

## Build

CI: `.github/workflows/build-checkm8.yml` (windows + linux artifacts).

Local:

```sh
# Windows (cross, cần MinGW + libusb MinGW package):
make LIBUSB=1 WINDOWS_CROSS=1 LIBUSB_MINGW=/path/to/libusb-1.0.27

# Linux:
sudo apt install libusb-1.0-0-dev
make LIBUSB=1

# macOS (IOKit backend — upload payload cần bản libusb):
make
```

## Payloads (dump từ palera1n v2.0.0 beta 8)

- `pongoOS_shellcode.bin` (+ `shellcode.bin`, `Pongo.bin`) — PongoOS
- `checkra1n-kpf-ploosh.bin` — KPF của checkra1n build cho PongoOS
- `ramdisk.bin`, `overlay.bin` (binpack) — bootstrap palera1n
- `yolo_*.bin` — stage-2 checkm8 per-chip

Kế hoạch: chuyển sang tải artifact có pin + checksum trong CI (như palera1n làm),
không commit binary vào release công khai (xem `Checkm8_myJB_Integration.md` mục C2).

## Attributions / License

- Code: [openra1n](https://github.com/mineek/openra1n) / [gaster](https://github.com/0x7ff/gaster) — Apache-2.0
- Payloads: [palera1n team](https://github.com/palera1n), [ra1npoc15](https://github.com/kok3shidoll/ra1npoc) — xem mục payloads
- [checkra1n](https://checkra.in/) — bootROM exploit / KPF
