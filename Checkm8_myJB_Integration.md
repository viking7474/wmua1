# Checkm8 myJB Integration (Windows / checkra1n–palera1n)

Mục tiêu: mở rộng myJB sang thiết bị checkm8 (A7–A11, khớp ma trận "iOS 12–15")
với tool chạy Windows, dựa trên 2 repo bạn đưa + palera1n (nguồn payload).

---

## 1. Kết quả khảo sát repo

### 1.1 `wh1te4ever/openra1n` (Apache-2.0, fork của mineek/openra1n, base gaster của 0x7ff)

- `openra1n.c` (~1000 dòng): checkm8 exploit thuần USB (gaster) + boot PongoOS.
  - Bảng iBoot → CPID/offset cho ~16 dòng chip (S5L8960→T8015), payload stage-2 YOLO armv7
    nhúng sẵn (`yolo_*.bin`), 5 stage: RESET→SETUP→SPRAY→PATCH→PWNED.
  - 2 backend USB: **libusb** (`-DHAVE_LIBUSB`, dùng cho Windows/Linux) và IOKit (macOS/iOS).
    README Windows: cần cài **libusbK** driver cho DFU (PID 0x1227) và cho **PongoOS USB
    (PID 0x4141)** sau khi pwn.
  - Boot PongoOS: gửi `payloads/pongoOS_shellcode.bin` (148K, raw ARM64, đã nén sẵn) qua
    DFU_DNLOAD liên tục (retry từng chunk 0x800).
- `boot.py` (pyusb, ~70 dòng): PongoOS terminal — chuỗi lệnh ctrl transfer (0x21/3):
  1. `fuse lock` / `sep auto`
  2. `modload` ← upload `checkra1n-kpf-ploosh.bin` (**Mach-O arm64e**, KPF checkra1n build cho PongoOS)
  3. `palera1n_flags 0x4000000`
  4. `ramdisk` ← `ramdisk.dmg` (dump)
  5. `overlay` ← `binpack.dmg` (dump) — bootstrap overlay
  6. `xargs rootdev=md0` + `bootx`
- Payload đều là **dump từ palera1n v2.0.0-beta.8**.

### 1.2 `kok3shidoll/ra1npoc` (MIT, archived; branch `ios15`)

- Dump checkra1n **0.1337.x** dùng payload checkra1n: `legacy_kpf` + `legacy_ramdisk`
  (0.12.4b-compatible, "to run 0.1337 for iOS 14") + `Pongo.bin` từ checkra1n/PongoOS 2.6.1.
- Chạy **trên iOS host** (Lightning→USB camera adapter) — bản "portable", không cần PC.
- Coverage: **jailbreak lại iOS 12–14** cho máy đã từng checkra1n/odysseyra1n (`-rc` từ
  Recovery); iOS 15+ **chỉ boot PongoOS** (`-rE` + `-k` pongo image) — không có KPF/overlay 15.
- `helper/pongoterm.c`: giao thức PongoOS terminal qua IOUSB (modload/bootx...) — tham chiếu
  tốt để port sang C++/C trên Windows.

### 1.3 `palera1n/palera1n` (MIT) — nguồn payload chuẩn

- Hỗ trợ A8–A11 + T2, **iOS 15.0+** (rootless + fakefs-rootful).
- Makefile `download-deps` tải artifact (không build từ source):
  - `checkra1n` binaries: `assets.checkra.in/downloads/preview/<ver>/...`
  - `checkra1n-kpf-pongo`: `cdn.nickchan.lol/palera1n/artifacts/kpf/iOS15/...`
  - `ramdisk.dmg`, `binpack.dmg`, `Pongo.bin`: CDN palera1n (PongoOS fork iOS15 branch, MIT)
- **jbinit / plooshInit** (repo `palera1n/jbinit`): sau bootx, kernel patch trỏ vào
  `fakedyld` (`/cores/usr/lib/dyld`); jbinit chạy userland:
  - hook launchd (ellekit/Dobby) để cấp services, mount binpack/loader, fakefs, rc.d...
  - **dropbear SSH** loopback port 44; daemon qua `/var/jb/Library/LaunchDaemons`
  - **tweak injection chính là ElleKit** (BSD-3) — tương tự libhooker; TweakInject dir
    `/var/jb/Library/TweakInject`.

### 1.4 Tổng hợp licensing

| Thành phần | License | Ghi chú |
|-----------|---------|---------|
| openra1n / gaster (checkm8 + pongo upload) | Apache-2.0 | dùng trực tiếp, giữ notice |
| PongoOS (2.6.1 / palera1n fork) | MIT | build hoặc tải artifact |
| KPF `checkra1n-kpf-pongo` | binary của checkra1n (closed) | tải lúc build (không commit), như palera1n làm |
| ramdisk/binpack (palera1n) | MIT (repo) | tải từ CDN palera1n |
| ElleKit | BSD-3 | bootstrap có sẵn |
| ra1npoc | MIT | tham chiếu flow 12–14 |
| myJB basebins (của ta) | như dự án | dùng chung cho mọi nhánh |

---

## 2. Kiến trúc checkm8 path cho myJB

```
[Windows tool = fork openra1n]
  ├ checkm8 (gaster) → pwned DFU
  ├ upload pongoOS_shellcode → PongoOS USB (0x4141)
  ├ PongoOS script (port từ boot.py sang C):
  │   fuse lock / sep auto / modload(KPF) / [MYJB_FLAGS?] / ramdisk / overlay
  │   / xargs rootdev=md0 / bootx
  └ (sau boot) SSH dropbear 127.0.0.1:44 (qua usbmuxd) → cài deb myJB (tuỳ chọn - auto)
[Device đã jailbreak (palera1n rootless /var/jb)]
  ├ jbinit + ElleKit → mọi process có injection
  ├ /var/jb/usr/lib/TweakInject/ ← myjb_loader.dylib + myjb_loader.plist (filter rỗng)
  │     └ ElleKit quét đúng dir này (nguồn: ellekit `launchd/Tweak.swift` `getTweaksPath()` —
  │       ghép cặp `<tên>.dylib` + `<tên>.plist` cùng thư mục; filter rỗng = mọi process)
  │     └ quét *.myjb (như Amethyst P5 — code y nguyên)
  │     └ key: /var/mobile/Library/MyJB/kdev  (ưu tiên 1 — đã hỗ trợ sẵn)
  ├ /var/jb/Library/LaunchDaemons/com.staturnz.myjb.plist → myjbd (mới, sau này)
  │     └ XPC com.staturnz.jbserver: attest HMAC (chuẩn hoá lại jbserver của Amethyst)
  │     └ sinh/đăng ký kdev, telemetry, cập nhật container (server /build sau này)
  └ Tweaks: .myjb (Ed25519 + XChaCha20-Poly1305, đúng format v1 — không đổi)
```

Điểm mấu chốt: **myjb_loader v1 hiện đã đủ chạy trên palera1n bootstrap** —
- ellekit cấp engine (MSHookFunction) → loader thấy sẵn, bỏ qua bước tải libhooker;
- kdev file là ưu tiên số 1 trong `myjb_collect_keys()`;
- staging `/var/jb/usr/lib/myjb/run` + `/tmp` có sẵn và ghi được (rootless);
- jbserver (`jbserver_process_library`) **không còn là điều kiện bắt buộc**: loader chỉ log
  cảnh báo khi vắng jbserver rồi vẫn dlopen (`main.c` fallback — kernel checkm8 đã bị KPF
  patch bỏ cs enforce). Trên Amethyst hành vi không đổi: nếu trustcache/sign lỗi thì AMFI
  vẫn chặn dlopen. v2: myjbd cung cấp lại đúng API qua XPC.

## 3. Bảng điểm chèn myJB (checkm8)

| # | Điểm | Ở đâu | Việc |
|---|------|-------|------|
| C1 | Tool Windows | `checkm8/ktool/` (fork openra1n) | ✅ scaffold xong: giữ gaster+libusb, `boot.py` port sang C (`pongo_send_cmd`/`pongo_upload`/`pongo_run_palera1n`), binary `myjb_ktool`; CI `build-checkm8.yml` (mingw + linux) — **Windows ✅** (exe mingw), **Linux ❌** (đang điều tra) |
| C2 | Payload pin | build script/CI | tải `checkra1n-kpf-pongo`, `ramdisk.dmg`, `binpack.dmg`, `Pongo.bin` từ CDN + checksum; không commit binary; Pongo build từ palera1n/PongoOS (MIT) nếu cần |
| C3 | Driver layer | tool | checkm8 cần USB Reset thật: **UsbDk** (khuyến nghị — backend usbdk có sẵn trong libusb 1.0.27, cài 1 lần, không đổi driver thiết bị) hoặc **libusbK** qua Zadig (phải đổi driver cả DFU lẫn Pongo). WinUSB không reset được device. Gộp "Fix Driver" như WinRa1n 2.x |
| C4 | Loader trên bootstrap | deb myJB → `/var/jb/usr/lib/TweakInject/myjb_loader.dylib` + `.plist` | ✅ v1: `checkm8/package/` (control, postinst, plist filter rỗng, `build.sh`) + loader fallback khi thiếu jbserver; CI `build.yml` đóng gói deb từ artifact `myjb_loader.dylib` (upload `myjb-checkm8`) |
| C5 | kdev service | postinst deb (v1) + myjbd (v2) | 🟡 v1: postinst sinh 32B `/var/mobile/Library/MyJB/kdev` (chmod 600, chown mobile) + `kdev.txt` (hex) để copy sang tool; v2: myjbd `myjbctl kdev` đăng ký per-device + KPF secret RAM |
| C6 | myjbd daemon | `/var/jb/Library/LaunchDaemons/` | server-side OTA container, `/activate`, revoke; chuẩn hoá XPC `com.staturnz.jbserver` (dùng lại HMAC challenge code của Amethyst) |
| C7 | iOS 12–14 | nhánh riêng (sau) | dùng payload `legacy_kpf`/`legacy_ramdisk` (ra1npoc headers) + Pongo 2.6.1; bootstrap checkra1n/odysseyra1n (libhooker path đã có trong loader) |
| C8 | Windows UX | tool | DFU helper (như palera1n -D), log file, tiến trình %, chạy lại nhanh |
| C9 | CI | `.github/workflows/` | 🟡 `build-checkm8.yml` mingw xanh, linux đỏ (đang điều tra); `build.yml` (macOS) thêm bước đóng gói deb checkm8 (`checkm8/package/build.sh`) → artifact `myjb-checkm8` |
| C10 | Test matrix | thiết bị | 15.0–15.8 (A11/A10/A9) × rootless; 12–14 (A8–A11) sau |

## 4. Quyết định mặc định (có thể đổi)

1. **V1 = iOS 15+ (palera1n flow)** chạy trước — gần như "lắp ghép" (loader đã tương thích),
   giá trị DRM lấy ngay; iOS 12–14 làm nhánh C7 sau (cần test thiết bị thật).
2. Bootstrap **rootless** (`/var/jb`) — khớp toàn bộ basebins hiện có.
3. Không redistribute KPF/checkra1n binary trong repo; CI tải + checksum (đúng cách palera1n làm).
4. myjb_loader giữ **đúng format container v1** — tweak build 1 lần chạy cả Amethyst lẫn checkm8
   (`--target-jb any` nếu muốn dùng chung 1 file).

## 5. Việc kế tiếp (theo thứ tự)

1. ✅ `checkm8/ktool/` scaffold + CI `build-checkm8.yml` **xanh** (myjb_ktool.exe + linux binary).
2. Test máy thật: JB iOS 15 (A11) bằng tool (DFU → libusbK → chạy exe) → xác nhận boot
   palera1n như openra1n gốc (parity check trước khi thêm myJB).
3. ✅ Loader bản checkm8: fallback khi vắng jbserver (`myjb_loader/src/main.c`) + deb
   `checkm8/package/` — loader → `/var/jb/usr/lib/TweakInject/` (kèm plist filter rỗng cho
   ElleKit), postinst tạo dirs (0177 7) + sinh kdev, `build.sh` đóng gói (dùng chung
   `myjb_loader.dylib` với Amethyst); CI artifact `myjb-checkm8`.
4. Test container .myjb trên máy đã JB: cài deb qua Sileo (hoặc `dpkg -i` qua SSH dropbear
   127.0.0.1:44) → respring → đặt `.myjb` vào containers + kdev → `MYJB_DEBUG=1` kiểm log.
   Lưu ý: **không** bật `MYJB_LEGACY` trên checkm8 (ElleKit đã tự load tweak thường).
5. V2: myjbd (C5/C6), rồi nhánh iOS 12–14 (C7).
