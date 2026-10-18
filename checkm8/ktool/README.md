# myJB checkm8 tool (fork of openra1n)

Booter checkm8 (A7–A11) chạy Windows/Linux/macOS, phục vụ nhánh checkm8 của myJB.
Khác biệt so với openra1n gốc:

- **Gộp `boot.py` vào binary C** — không cần chạy python3 riêng sau khi pwn:
  sau khi boot PongoOS, tool tự gửi chuỗi palera1n (`fuse lock`, `sep auto`,
  `modload` KPF, `palera1n_flags`, `ramdisk`, `overlay`, `xargs rootdev=md0`, `bootx`).
- **Chế độ `--legacy`** — chuỗi checkra1n 0.12.4b cho iOS 12.0–14.8.1
  (KPF legacy + ramdisk loader, `kpf_flags`, không overlay), theo đúng flow
  `pongoterm.c` của ra1npoc15.
- Binary tên `myjb_ktool(.exe)`, build Windows bằng MinGW trong CI.

## Trạng thái

- [x] checkm8 (gaster) + boot PongoOS + chuỗi palera1n trong 1 binary
- [x] Chuỗi legacy checkra1n 0.12.4b (`--legacy`) — đã jailbreak thành công trên máy iOS 12–14
- [x] Windows driver auto-bind (`tools\fix_driver.cmd` + kit `winra1n_mobile_device.inf`) —
      libusbK cho 1227/1338/4141, hết treo "Waiting for PongoOS device", không cần Zadig
- [ ] myJB stage trong legacy ramdisk (v1: fakefs) — nguồn `stage/`, build CI
      `build-stage.yml`; cách thay trực tiếp `/payload` phá bước cài rootfs
      (xem mục Payloads), hướng mới: hook `/pstage0`
- [ ] Tích hợp myJB (loader/kdev) — xem `../../Checkm8_myJB_Integration.md` (C4–C6)
- [ ] Payload pin + checksum (C2)

## Usage (Windows)

0. Đưa thiết bị vào **DFU**.
1. **Driver (bắt buộc, mỗi máy Windows chỉ làm 1 lần):** cả node DFU `05AC:1227`
   lẫn node PongoOS `05AC:4141` phải được bind **libusbK**.
   - Cách chuẩn (tự động, khuyến nghị) — driver kit trích từ WinRa1n 2.1:
     ```bat
     powershell -ExecutionPolicy Bypass -File tools\extract_driver_kit.ps1
     tools\fix_driver.cmd   :: script tự xin quyền Admin
     ```
     Kit `driver_kit\` chứa `libusbK\winra1n_mobile_device.inf` — sau khi cài,
     Windows **tự bind libusbK cho 05AC:1227/1338/4141 ở mọi lần enumerate**
     (không phụ thuộc cổng USB, sống qua reboot, không cần Zadig). Nguyên nhân
     + bằng chứng phân tích: `../../WinRa1n2.1_analysis.md` mục 12.
   - Fallback thủ công: Zadig → "Apple Mobile Device (DFU Mode)" (05AC 1227)
     → **libusbK** → Replace Driver; node PongoOS làm tương tự khi tool đang chờ
     (mẹo ở bước 3).
   - WinUSB **không đủ** (không reset được device → treo ở heap spray).
     UsbDk **không dùng được** (libusb 1.0.27 thiếu `cancel_transfer` → đứng im
     ngay sau "Setting up the exploit").
2. Chạy `myjb_ktool.exe` — tool tự chạy checkm8, boot PongoOS, và gửi chuỗi boot palera1n.
   - iOS 15+: chạy mặc định (palera1n boot).
   - iOS 12.0–14.8.1: chạy `myjb_ktool.exe --legacy` (checkra1n 0.12.4b boot);
     thêm `-L`/`--legacy-verbose` nếu cần verbose boot (màn hình hiện log -v).
     Máy clean sẽ tự boot vào loader checkra1n trên ramdisk (mở app "checkra1n"
     để cài bootstrap/Sileo như bình thường).
3. Thiết bị re-enumerate "Pongo USB Device" (05AC 4141). Nếu đã cài driver kit ở
   bước 1 thì libusbK tự bind — không cần làm gì thêm.
   - Fallback (chưa cài kit): khi tool đang ở "Waiting for PongoOS device", mở
     Zadig → "Pongo USB Device" → Replace Driver → libusbK; tool đang chờ sẽ tự
     mở được thiết bị ngay, không phải chạy lại từ đầu. Khi phát hiện node bị
     bind sai driver, tool in gợi ý chạy `tools\fix_driver.cmd`.
4. Thiết bị boot vào jailbreak (palera1n rootless `/var/jb`, hoặc checkra1n loader
   với `--legacy`). Cài bootstrap như bình thường.

> Lưu ý: checkm8 là semi-tethered — mỗi lần reboot phải chạy lại tool.

## Windows driver (nguyên nhân treo + khắc phục)

Windows chỉ cho user-mode mở raw USB khi node được bind driver `libusbK`/`WinUSB`.
Gói `winra1n_mobile_device.inf` (trích từ driver pack của WinRa1n 2.1) khai báo
đúng 3 hardware ID — `USB\VID_05AC&PID_1227` (DFU), `...PID_1338` và `...PID_4141`
(PongoOS). Sau khi cài vào DriverStore (máy-wide), Windows **tự gán libusbK** cho
các node này ở mỗi lần enumerate → tool không còn kẹt ở
"Waiting for PongoOS device (USB PID 0x4141)".

- Kiểm tra: `Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_05AC' }`
  → node 4141 kỳ vọng Class `libusbk devices`, FriendlyName `WinRa1n Mobile Device`.
- Gỡ kit khi cần: `pnputil /enum-drivers` để lấy tên `oemXX.inf`, rồi
  `pnputil /delete-driver oemXX.inf /uninstall`.
- Chi tiết phân tích (offset ZIP, nội dung INF, cert tự ký, quy trình WinRa1n):
  `../../WinRa1n2.1_analysis.md` mục 12.

## Debug log (khi cửa sổ tự đóng)

Mọi log (bản không màu) được ghi vào `myjb_ktool.log` **cạnh exe**. Nếu tool
crash, log có thêm dòng `[FATAL]` kèm mã lỗi; log kết thúc bằng `[EXIT] process
exit code N`. Khi lỗi xảy ra mà chạy bằng double-click, cửa sổ sẽ dừng lại ở
"Press Enter to close this window..." để kịp đọc. Gửi kèm `myjb_ktool.log` khi
báo lỗi để chẩn đoán (đặc biệt với lỗi "tự thoát").

## Build

CI: `.github/workflows/build-checkm8.yml` (windows + linux artifacts),
`.github/workflows/build-stage.yml` (macOS; build `myjb_stage` arm64 ký ad-hoc
kèm entitlements — stage chạy trong legacy ramdisk).

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

## Payloads

- `pongoOS_shellcode.bin` (+ `shellcode.bin`, `Pongo.bin`) — PongoOS
- `checkra1n-kpf-ploosh.bin` — KPF của checkra1n build cho PongoOS (dump từ palera1n v2.0.0 beta 8)
- `ramdisk.bin`, `overlay.bin` (binpack) — bootstrap palera1n (iOS 15+)
- `legacy_kpf.bin` — KPF gốc checkra1n 0.12.4b (nguồn: kho `headers/` của
  [ra1npoc15](https://github.com/kok3shidoll/ra1npoc)) — dùng cho `--legacy` (iOS 12–14)
- `legacy_ramdisk.bin` — ramdisk loader checkra1n 0.12.4b (stock, git 441edf1)
  với **10-byte vá gate loaderd** tại `/payload` (sha1 patched
  `179d82e6a29d96bbe0aa4af65acff328c974953c`, image sha256
  `e0c0e7d7…272af2b`): bỏ whitelist CDHash client — nop csops tbnz @0x8448,
  force dispatch branch @0x8688/0x86a0. Same-size in-place, không đổi cấu trúc
  HFS (delta vs stock đúng 10 byte; validate fresh-parse + hash từng bước).
  Bản cũ (stage thay `/payload` + `/payload.real`) **đã bỏ**: bước cài rootfs
  chỉ mang `/payload` sang rootfs, `/payload.real` không theo → chuỗi
  real-system chết trước khi job loaderd đăng ký (loader.app báo
  "Connection invalid"; xem `log.txt` 18/10 dòng 10949–10954). Hướng stage
  kế tiếp (v1 fakefs): hook `/pstage0` (vá string trong `/patch_dyld.ios`)
  để giữ `/payload` nguyên vẹn cho rootfs install.
- `yolo_*.bin` — stage-2 checkm8 per-chip

Kế hoạch: chuyển sang tải artifact có pin + checksum trong CI (như palera1n làm),
không commit binary vào release công khai (xem `Checkm8_myJB_Integration.md` mục C2).

## Attributions / License

- Code: [openra1n](https://github.com/mineek/openra1n) / [gaster](https://github.com/0x7ff/gaster) — Apache-2.0
- Payloads: [palera1n team](https://github.com/palera1n), [ra1npoc15](https://github.com/kok3shidoll/ra1npoc) — xem mục payloads
- Driver kit (`tools\extract_driver_kit.ps1` → `driver_kit\`): [libwdi](https://github.com/pbatard/libwdi) + libusbK (LGPL),
  trích xuất từ driver pack của WinRa1n 2.1 khi chạy script — binary không commit vào repo
- [checkra1n](https://checkra.in/) — bootROM exploit / KPF
