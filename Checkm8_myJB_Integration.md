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
| C3 | Driver layer | tool | checkm8 cần USB Reset thật **và** hủy control transfer đúng timing (từ stage 2): dùng **libusbK** qua Zadig (đổi driver cho cả DFU 1227 lẫn Pongo 4141). WinUSB không reset được device; **UsbDk ❌** — backend usbdk của libusb 1.0.27 có `cancel_transfer = NULL`, đã kiểm chứng thực tế: treo ngay sau "Setting up the exploit". Gộp "Fix Driver" như WinRa1n 2.x |
| C4 | Loader trên bootstrap | deb myJB | ✅ v1: `checkm8/package/` — payload tách theo arch: rootless (`iphoneos-arm64`) → `/var/jb/usr/lib/TweakInject/myjb_loader.dylib` + `.plist` (filter rỗng, ElleKit); rootful (`iphoneos-arm`, checkra1n 12-14) → `/usr/lib/myjb_loader.dylib` (**không đụng `/var/jb`** — SDK chống JB MB Bank abort chỉ vì path này tồn tại, verified 13.5.1), postinst mirror vào `/Library/MobileSubstrate/DynamicLibraries` (Cydia Substrate) + `/usr/lib/TweakInject` (libhooker/ElleKit) **chỉ khi engine thật sự có mặt**; loader fallback khi thiếu jbserver; CI `build.yml` đóng gói deb (artifact `myjb-checkm8`) + tweak E2E (`myjb-e2e-testtweak`). **E2E ✅ verified iPhone 6s iOS 13.5.1** (container → kdev → dlopen, `e2e_ok`). Gotcha: Substrate classic (iOS 9+) **không** coi `Filter` rỗng là mọi process → postinst ghi plist rootful `Bundles = (springboard, Security, UIKit, Foundation)`; plist rỗng chỉ dành cho ElleKit rootless. **Substrate-free injector (basebins) — xem §6** |
| C5 | kdev service | postinst deb (v1) + myjbd (v2) | 🟡 v1: postinst sinh 32B `/var/mobile/Library/MyJB/kdev` (chmod 600, chown mobile) + `kdev.txt` (hex) để copy sang tool; v2: myjbd `myjbctl kdev` đăng ký per-device + KPF secret RAM |
| C6 | myjbd daemon | `/var/jb/Library/LaunchDaemons/` | server-side OTA container, `/activate`, revoke; chuẩn hoá XPC `com.staturnz.jbserver` (dùng lại HMAC challenge code của Amethyst) |
| C7 | iOS 12–14 | nhánh riêng | ✅ `myjb_ktool --legacy` (payload `legacy_kpf`/`legacy_ramdisk` từ ra1npoc, `kpf_flags`, wValue 0xffff) — **verified máy thật iPhone 6s iOS 13.5.1**: kernel boot + loader checkra1n. Lưu ý: chuỗi palera1n **không chạy được < 15** — jbinit (plooshInit) cần `mount("tmpfs","/cores")`, kernel 13.5.1 không có tmpfs → `err=19 ENODEV` (strings "cannot mount tmpfs onto /cores" nằm trong `ramdisk.bin` beta8). Bootstrap: Cydia/odysseyra1n rootful |
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
2. 🟡 Máy thật: chuỗi gửi đã verified (13.5.1 `--legacy` boot tới checkra1n loader; mode
   palera1n gửi hết chain trên 13.5.1 — treo sau bootx do tmpfs, xem C7). Còn cần: máy
   A11/IOS 15 rootless để xác nhận boot palera1n đầy đủ.
3. ✅ Loader bản checkm8: fallback khi vắng jbserver (`myjb_loader/src/main.c`) + deb
   `checkm8/package/` — payload tách arch: rootless → `/var/jb/usr/lib/TweakInject/`
   (plist rỗng cho ElleKit); rootful → `/usr/lib/myjb_loader.dylib` (không đụng `/var/jb`,
   mirror engine chỉ khi engine có mặt, plist `Bundles` tường minh), postinst tạo dirs
   (0177 7) + sinh kdev, `build.sh` đóng gói (dùng chung `myjb_loader.dylib` với Amethyst);
   CI artifact `myjb-checkm8` + `myjb-e2e-testtweak`.
4. ✅ E2E container trên máy 13.5.1 đã JB (iPhone 6s): deb → `kdev.txt` → `myjb_build.py`
   (DEV seed + `--kdev-hex`) → containers → respring → `e2e_ok` + `loader.log` xác nhận
   decrypt/dlopen thành công (guide mục I). Root cause lần đầu thất bại: plist `Filter`
   rỗng không được Substrate classic inject — đã sửa trong postinst.
   Lưu ý: **không** bật `MYJB_LEGACY` trên checkm8 (bootstrap tự load tweak thường).
5. **Kế tiếp**: myjbd (C5/C6) — OTA container, `/activate`, revoke; sau đó C2 payload pin.

## 6. Substrate-free injector (không cần substrate/libhooker) — checkra1n rootful

Port basebins kiểu Amethyst để spoof myJB **không phụ thuộc Cydia Substrate** (thiết bị test đã gỡ substrate). Chuỗi:

1. `/amethyst/jbutil -k` (fallback `jbutil -i 1 /amethyst/launchd_hook.dylib`) → inject
   `launchd_hook` vào launchd (pid 1) qua `task_for_pid` (jbutil/src/process.c:363) —
   checkra1n root làm được (AMFI off / entitlement `task_for_pid-allow`).
2. `launchd_hook` (trong launchd) hook `posix_spawn` → thêm
   `DYLD_INSERT_LIBRARIES=/usr/lib/base_hook.dylib` cho mọi process mới (trừ blocklist).
3. `base_hook` ctor (base_hook/src/main.c:27) → dlopen `/usr/lib/myjb_loader.dylib`
   → spoof layer (`myjb_hide`) chạy.

Khác biệt checkra1n — **degraded kernel mode** (code đã sửa):

- Không hsp4: `launchd_hook/src/main.c` fallback `task_for_pid(mach_task_self(), 0)` lấy
  tfp0; không có `/amethyst/handoff.plist` → `kernel_base/slide` suy từ `TASK_DYLD_INFO`
  (không có plist cũng không abort như trước).
- `kernel_ready = (kern_proc_addr && kern_task_addr)` — thiếu patch addrs thì bỏ qua
  cs flags/sandbox/arm64e/PPL/trustcache; jbserver vẫn hook xpc nhưng API cần kernel
  trả lỗi mềm (loader đã có fallback từ trước).
- `trustcache.c`: cờ `trustcache_enabled` — init fail (thiếu addrs) thì mọi
  check/add no-op (checkra1n AMFI off nên dlopen vẫn chạy).
- **Không nhánh nào tạo `/var/jb` trên rootful**: jbserver `myjb_prepare_dirs` và loader
  `myjb_stage_write` đều gate `access("/var/jb")` (bài học MB Bank).
- jbutil `-k` không phụ thuộc hsp4 trước khi inject (jbutil/src/main.c:88 inject thẳng);
  tnsv2/handoff generation fail mềm trên checkra1n.

Deploy: `sh checkm8/deploy_injector.sh` ([ssh_target] [port] [basebins_tar]) — cần
`basebins.tar` từ `make all stage` (macOS/CI `build.yml`). Debug: `MYJB_DEBUG=1` thêm
marker `/var/mobile/Library/MyJB/.myjb_debug` → loader ghi `loader.log`.
Rollback: xóa 5 file (`/amethyst/{jbutil,launchd_hook.dylib}`,
`/usr/lib/{base_hook,libjailbreak,myjb_loader}.dylib`) + reboot.
