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
1. Cài driver USB đặc biệt (checkm8 cần **USB Reset thật** giữa các stage):
   - **Cách A (khuyến nghị): UsbDk** — tải bản mới nhất tại
     <https://github.com/daynix/UsbDk/releases> (ví dụ `UsbDk_1.0.22_x64.msi`),
     cài rồi **khởi động lại máy**. Tool tự chuyển sang backend UsbDk khi có;
     không cần đổi driver cho thiết bị (giữ driver Apple) và dùng được luôn cho
     Pongo USB Device — không cần bước driver phụ.
   - **Cách B: libusbK qua Zadig** — chọn "Apple Mobile Device (DFU Mode)"
     (05AC 1227) → dropdown driver chọn **libusbK** → **Replace Driver**.
     Khi Pongo USB Device hiện ra phải đổi driver libusbK riêng cho nó (bước 3).
   - WinUSB (mặc định) **không đủ**: libusb 1.0.27 xác nhận backend WinUSB
     không reset được device (chỉ cycle pipe) → tool treo ở heap spray.
2. Chạy `myjb_ktool.exe` — tool tự chạy checkm8, boot PongoOS, và gửi chuỗi boot palera1n.
3. Khi tool báo đã gửi xong, thiết bị re-enumerate "Pongo USB Device":
   nếu dùng libusbK (cách B) và quá trình upload KPF/ramdisk/overlay bị kẹt chờ,
   cài lại driver **libusbK** cho Pongo USB Device rồi chạy lại tool.
   Với UsbDk (cách A) không cần làm gì thêm.
4. Thiết bị boot vào jailbreak (palera1n rootless `/var/jb`). Cài bootstrap như bình thường.

> Lưu ý: checkm8 là semi-tethered — mỗi lần reboot phải chạy lại tool.
> iOS 15+ chỉ hỗ trợ chạy theo flow này; iOS 12–14 sẽ bổ sung sau (nhánh ra1npoc/legacy).

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
