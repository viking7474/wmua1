# Hướng dẫn tích hợp tweak vào myJB (Amethyst + checkm8)

Tài liệu này trả lời: **khi build tweak thành công, tương tác với hệ myJB thế nào?**
Gồm 3 phần: (A) luồng runtime để biết "ai làm gì", (B) quy trình đóng gói tweak,
(C) các API/knob tùy chọn cho tweak dev. Code tham chiếu:
`amethyst/basebins/myjb_loader/` (loader), `tools/myjb_build.py` (builder),
`TweakProtection_Design.md` §3 (spec format).

---

## A. Luồng runtime — tweak của bạn được load thế nào

```
boot → JB (Amethyst) → base_hook.dylib inject mọi process (DYLD_INSERT_LIBRARIES)
  └ init_tweaks()
      ├ attestation: challenge "myjb-session-key-v1" → jbserver (HMAC-SHA256, secret RAM-only)
      │   → ghi myjb_tweak_key[32] + myjb_attested vào base_hook (symbol export)
      └ dlopen("/usr/lib/myjb_loader.dylib")            ← ưu tiên trước Sonar/TweakInject
          └ myjb_loader ctor (myjb_start):
              1. pubkey = nhúng trong loader, override bởi /amethyst/.myjb_pubkey (32B)
              2. keys = [ /var/mobile/Library/MyJB/kdev, /amethyst/.myjb_devkey,
                          session key (nếu myjb_attested) ]       ← thử lần lượt
              3. quét *.myjb: /var/jb/usr/lib/myjb/containers → /var/mobile/Library/MyJB/containers
                   parse → verify Ed25519 → min_ios → target_jb → filters → dedupe tweak_id
              4. (nếu MYJB_LEGACY) quét thêm TweakInject *.dylib (không plist filter)
              5. nếu chưa có MSHookFunction → dlopen libhooker RTLD_GLOBAL
              6. mỗi container: decrypt XChaCha20-Poly1305 → check SHA-256 payload
                   → ghi staging /var/jb/usr/lib/myjb/run|/var/mobile/Library/MyJB/run|/tmp
                     (tên myjb-<pid>-<rand>.dylib)
                   → jbserver_process_library() (ký ad-hoc / trustcache)
                   → dlopen(RTLD_NOW) → unlink ngay
              7. crypto_wipe(keys)
```

Điểm tweak dev cần nhớ:

- **Tweak không cần code gì đặc biệt** — loader giải mã rồi `dlopen`, ctor tweak chạy bình thường.
- Payload trong container chỉ có **dylib**, không có bundle/plist (prefs bundle phải phát hành riêng).
- Trong process, tweak thấy image path của chính nó là **đường dẫn staging ngẫu nhiên**
  (`.../run/myjb-<pid>-<hex>.dylib`) — đừng code cứng theo tên file.
- Thứ tự load: engine (libhooker) → container (tên file sort alphabet, dedupe theo `--id`).
- Không set filter nào → **load trong mọi process** (xem B3).

---

## B. Đóng gói tweak

### B1. Build tweak

Theos như bình thường → lấy dylib. Ký ad-hoc trước khi đóng gói (loader vẫn tự ký/trustcache
lúc runtime, nhưng payload nên là Mach-O hợp lệ ngay từ đầu):

```sh
ldid -S .theos/obj/arm64e/Tweak.dylib
```

### B2. Đóng container `.myjb`

```sh
py -3 tools/myjb_build.py \
  --in  Tweak.dylib \
  --out com.example.tweak.myjb \
  --id  com.example.tweak \
  --version 1.0.0 \
  --min-ios 12.0 \
  --target-jb amethyst \
  --filter SpringBoard \
  --filter "*/MobileSafari" \
  --seed-file myjb_signing_seed.bin \
  --kdev-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

| Flag | Ý nghĩa |
|------|---------|
| `--id` | tweak id (reverse-DNS); dùng để dedupe + làm input KDF (**đổi id = phải build lại container**) |
| `--version` | chỉ là metadata, hiện log/info |
| `--min-ios 12.0` | lưu `major*100+minor` = 1200; process có iOS < 1200 bỏ qua. `0` = không giới hạn |
| `--target-jb` | `amethyst` (= giá trị loader hiện tại nhận), `any` (0xFFFF), hoặc `checkm8`/`taurine` (bản loader tương lai) |
| `--filter` | fnmatch(3), tối đa 8, mỗi cái ≤ 63 ký tự — xem B3 |
| `--seed-file/--seed-hex` | **seed Ed25519 ký container** (32B). Giữ bí mật phía bạn; đây là khóa ký, không nhầm với kdev |
| `--kdev-hex/--kdev file` | khóa mã hóa container (32B) — xem B4 |
| `--salt-hex/--nonce-hex` | override để test vector; bình thường để trống (random mỗi lần build) |

Kiểm tra lại sau khi đóng:

```sh
py -3 tools/myjb_build.py --info com.example.tweak.myjb --pubkey-hex <pubkey_hex_của_bạn>
# signed_ok: yes  + in đủ manifest
```

### B3. Filters — thay thế plist Theos

Loader so khớp `fnmatch(filter, exec_path)` **hoặc** `fnmatch(filter, basename)`:

- `SpringBoard` → khớp basename chính xác.
- `*/MobileSafari` → khớp đuôi full path.
- `*` → mọi process (cẩn thận).
- Không filter nào → load mọi process.
- Exec path thực tế, ví dụ: `/var/containers/Bundle/Application/<UUID>/Foo.app/Foo`,
  `/Applications/MobileSafari.app/MobileSafari`, `/usr/libexec/backboardd`.
  Nếu không chắc, dùng filter basename (`Foo`, `MobileSafari`) — an toàn nhất.
- Hết hạn/đổi filter = build container mới (manifest được ký, không sửa tay được).

### B4. Khóa mã hóa (kdev) — chọn 1 trong 3 nguồn

Container mã hóa bằng `K_file = HKDF-SHA256(kdev, salt, "myjb-file-v1:" + id)`.
Loader thử **theo thứ tự**, key nào decrypt + khớp SHA-256 trước thì thắng:

1. `/var/mobile/Library/MyJB/kdev` — 32B, persistent (dự kiến cho production).
2. `/amethyst/.myjb_devkey` — 32B, dành cho dev/test.
3. **Session key** — ngẫu nhiên mỗi boot, chỉ sống trong RAM của JB. **Không dùng được để
   đóng gói offline** (builder không biết trước); path này để sau này server cấp nội dung
   theo session. Hiện chỉ hữu ích cho attestation.

Thực tế v1: đóng gói bằng kdev (1 hoặc 2). Với dev/test, tạo file trên máy **đúng 32 byte**:

```sh
# trên thiết bị (SSH/Filza), root:
printf '<same bytes as builder>' > /amethyst/.myjb_devkey   # hoặc scp file 32B
chmod 600 /amethyst/.myjb_devkey
```

Lưu ý: v1 kdev dùng chung (mọi user cùng kdev trừ khi bạn build container per-user).
Server-side per-device build là kế hoạch sau (P6+).

### B5. Phát hành qua Sileo/deb

Deb chỉ cần chứa file ở đúng path (dpkg giải nén vào `/var/jb`-prefixed path):

```
package/
  DEBIAN/control                # Package: com.example.tweak, Architecture: iphoneos-arm64, ...
  var/jb/usr/lib/myjb/containers/com.example.tweak.myjb
```

- Cài xong → **respring** (tweak load khi process khởi động lại; launcher/Safari đang chạy
  không nhận ngay).
- Update: thay file → respring. **Một file / một tweak_id**; nếu có 2 file cùng id (đặt ở cả
  2 containers dir), file đầu tiên theo thứ tự dir + tên alphabet thắng.
- Uninstall: dpkg xóa file → tweak biến mất sau respring.
- Muốn cài không qua deb (dev): copy file trực tiếp vào
  `/var/jb/usr/lib/myjb/containers/` (root, 0644) rồi respring.

---

## C. Tương tác tùy chọn từ tweak code

### C1. Kiểm tra "đang chạy trên myJB" (attestation)

base_hook export 2 symbol (visibility default, đã verify trong build):

```c
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

static bool myjb_session(uint8_t out_key[32]) {
    void *bh = dlopen("/usr/lib/base_hook.dylib", RTLD_NOW);
    if (bh == NULL) return false;
    uint8_t *key = dlsym(bh, "myjb_tweak_key");
    int *attested = dlsym(bh, "myjb_attested");
    if (key == NULL || attested == NULL || *attested == 0) return false;
    if (out_key) memcpy(out_key, key, sizeof(uint8_t) * 32);
    return true;
}
```

Dùng để làm gì (tùy chọn, không bắt buộc):

- Gate tính năng: `myjb_session(NULL)` false → chạy chế độ hạn chế.
- `out_key` là session key giống cái loader thấy — có thể dùng làm HMAC key cho
  request/kết quả server, watermark telemetry... (đổi mỗi boot, không persist).
- Muốn chắc loader thật sự chạy: quét `_dyld_image_count()` tìm image chứa `myjb_loader`
  (lưu ý loader là dylib nằm ở `/usr/lib/myjb_loader.dylib`, còn tweak nằm ở staging path).

### C2. Knob/marker trên máy (không cần code)

| Điều khiển | Tác dụng |
|-----------|----------|
| `MYJB_DISABLE=1` (env) hoặc file `/amethyst/.myjb_disabled` | tắt loader hoàn toàn |
| `MYJB_DEBUG=1` (env) | log ra stderr + `/var/mobile/Library/MyJB/loader.log` |
| `MYJB_LEGACY=1` hoặc `/amethyst/.myjb_legacy` | bật quét TweakInject legacy (không mã hóa) |
| `/amethyst/.myjb_verify` | bật strict: attestation fail → không load tweak nào (gate ở base_hook) |
| `/amethyst/.myjb_pubkey` (32B) | override pubkey nhúng — test nhanh trước khi build lại loader |

Set env toàn cục để test: `launchctl setenv MYJB_DEBUG 1` (reset sau reboot).

### C3. Hook engine

Loader tự dlopen `libhooker.dylib` (RTLD_GLOBAL) nếu process chưa có `MSHookFunction`.
Tweak cứ link/hook như thường (libhooker/Substrate API), hoặc tự nhúng engine riêng nếu muốn.

---

## D. Khóa ký container (Ed25519) — quy trình

1. `py -3 tools/myjb_build.py --gen-key` → in ra **seed** (32B, giữ kín) + **pubkey** (32B).
2. Nhúng pubkey vào loader: sửa `myjb_embedded_pubkey[32]` trong
   `amethyst/basebins/myjb_loader/src/main.c` (dòng ~14) → commit → CI build lại basebins.
   - Test nhanh không cần build lại: đặt 32 byte pubkey vào `/amethyst/.myjb_pubkey`.
   - **Quan trọng**: loader hiện nhúng DEV key (RFC 8032 test #1) — phải thay trước khi phát hành.
3. Mọi container build bằng `--seed-*` tương ứng; loader từ chối chữ ký sai (log
   `parse/verify failed`).

---

## E. Troubleshooting (theo đúng log của loader)

| Log (stderr + loader.log khi MYJB_DEBUG) | Nguyên nhân thường gặp |
|------------------------------------------|------------------------|
| `parse/verify failed` | sai/không khớp pubkey, container hỏng, hoặc file không phải `.myjb` |
| `no available key could decrypt` | kdev/devkey trên máy ≠ kdev lúc build (byte khác 1 ký tự cũng fail) |
| tweak không chạy ở process X | filter fnmatch không khớp exec path; thử filter basename |
| `trustcache/sign failed` | jbserver chưa chạy (JB lỗi timeout) — reboot/jailbreak lại |
| `cannot stage payload` | hết quyền/hết chỗ 3 staging dir |
| tweak chạy nhưng mất sau respring | file bị xóa khỏi containers dir (deb update/uninstall?) |
| `X container(s), 0 key(s)` | không có kdev/devkey và attestation fail (kiểm tra `/amethyst/.myjb_verify`, jbserver) |

Xem log nhiều process: `MYJB_DEBUG=1` rồi `tail -f /var/mobile/Library/MyJB/loader.log`
(log append từ mọi process, có thể xen dòng).

---

## F. Giới hạn v1 (biết trước khi thiết kế tweak)

- Payload phải **giải mã tại chỗ** để dlopen được → có cửa sổ ngắn plaintext nằm ở staging
  dir (01777, file 0644) trước khi unlink. Đây là điểm yếu đã biết, vá ở P6+ (watermark,
  siết staging). Đừng coi container là "chống dump tuyệt đối".
- Chưa có flow tự động tạo `kdev` persistent / build per-device / server `/build` (kế hoạch P6+).
- Session-key path không dùng được để đóng gói offline (random mỗi boot).
- Chỉ dylib payload; không bundle/plist filter/prefs bundle trong container.
- `--target-jb checkm8/taurine` sẽ bị loader Amethyst bỏ qua (chỉ nhận `amethyst`/`any`).

---

## G. Checklist nhanh cho tweak mới

1. Build dylib → `ldid -S`.
2. `myjb_build.py --gen-key` (lần đầu) → giữ seed, nhúng/đặt pubkey.
3. Tạo kdev 32B (hex) → `--kdev-hex` khi build + file `kdev`/`.myjb_devkey` trên máy.
4. `myjb_build.py --in ... --out ... --id ... --filter ...` → `--info` verify.
5. Test máy thật: copy `.myjb` vào `/var/jb/usr/lib/myjb/containers/`, đảm bảo devkey đúng,
   `launchctl setenv MYJB_DEBUG 1`, respring, mở process đích, xem loader.log.
6. Chạy → đóng deb cho Sileo (file vào containers dir). Chưa chạy → bảng E.

---

## H. Chạy trên checkm8/palera1n (rootless, iOS 15+)

Cùng builder + cùng container v1; chỉ khác cách cài loader và engine:

- **Cài loader**: deb `com.wmua1.myjb.checkm8` (nguồn `checkm8/package/`, CI `build.yml`
  → artifact `myjb-checkm8`). Deb đặt `myjb_loader.dylib` + `myjb_loader.plist` (filter rỗng)
  vào `/var/jb/usr/lib/TweakInject/` — ElleKit tự inject vào mọi process. (Rootful thì
  postinst ghi plist riêng có `Bundles` tường minh — xem mục I.)
- **Điều kiện**: JB bằng `myjb_ktool` (hoặc palera1n tương đương) — bootstrap có ElleKit.
  Engine hook = ElleKit (`MSHookFunction` có sẵn; loader không cần tải libhooker).
- **kdev**: postinst sinh `/var/mobile/Library/MyJB/kdev` + hex ở `.../kdev.txt`
  (copy sang PC để `--kdev-hex`, sau đó **xóa kdev.txt**).
- **Không có session-key/attestation** trên nhánh này (không có base_hook như Amethyst) →
  đóng gói bằng kdev hoặc devkey; container `--target-jb any` dùng chung 2 nhánh.
- **Trustcache/sign**: không cần — kernel đã patch (KPF), loader dlopen trực tiếp; dòng log
  `trustcache/sign unavailable` là **bình thường** trên checkm8.
- **Đừng bật `MYJB_LEGACY`** trên checkm8: ElleKit đã load tweak thường, bật sẽ double-load.
- Containers: `/var/jb/usr/lib/myjb/containers/` (ưu tiên) hoặc `/var/mobile/Library/MyJB/containers/`.
- Cài deb → respring → xem log như mục E (`MYJB_DEBUG`).

---

## I. Chạy trên checkm8/checkra1n (rootful, iOS 12–14) — verified 13.5.1

JB bằng `myjb_ktool.exe --legacy` (chuỗi checkra1n 0.12.4b). Bootstrap checkra1n
(Cydia hoặc odysseyra1n): engine hook do Substrate/libhooker của bootstrap cấp;
postinst tự mirror loader vào `/Library/MobileSubstrate/DynamicLibraries` (Cydia
Substrate) và/hoặc `/usr/lib/TweakInject` (libhooker) — thư mục nào tồn tại.

**Lưu ý filter (đã kiểm chứng trên 13.5.1):** Cydia Substrate classic **không** coi
`Filter` rỗng là "mọi process" — loader sẽ không được inject (im lặng, không log).
Postinst ghi plist rootful với `Bundles` tường minh:
`com.apple.springboard`, `com.apple.Security`, `com.apple.UIKit`, `com.apple.Foundation`.
Nếu cài tay, phải dùng plist có `Bundles` (bản deb cũ dùng filter rỗng thì thay bằng
mục Filter tương ứng rồi respring).

E2E smoke test (đã có sẵn tweak test trong repo):

1. Cài deb **đúng arch** lên máy (CI artifact `myjb-checkm8` xuất cả 2 biến thể):
   - checkra1n classic/Cydia (iOS 12–14, `dpkg --print-architecture` = iphoneos-arm):
     `com.wmua1.myjb.checkm8_*_iphoneos-arm.deb`
   - Procursus/palera1n rootless (iphoneos-arm64): `..._iphoneos-arm64.deb`
   - Cách cài: Filza (chép deb vào máy qua web server → tap → Install); hoặc SSH:
     `dpkg -i <deb>` (nếu dpkg kêu arch, dùng `dpkg -i --force-architecture <deb>`).
   CI artifacts: `myjb-checkm8` (deb) + `myjb-e2e-testtweak` (test_tweak.dylib).
2. Lấy kdev từ máy: `cat /var/mobile/Library/MyJB/kdev.txt` → copy hex sang PC.
3. Trên PC, đóng gói tweak test (tweak dylib từ artifact CI):
   ```sh
   py -3 tools\myjb_build.py --in test_tweak.dylib --out test.myjb \
     --id com.wmua1.myjb.e2e --target-jb any --filter SpringBoard \
     --seed-hex 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 \
     --kdev-hex <hex bước 2>
   ```
   (seed trên là DEV RFC 8032 test #1 — khớp pubkey đang nhúng trong loader; đổi seed
   riêng trước khi phát hành — mục B4.)
4. Chép `test.myjb` vào `/var/mobile/Library/MyJB/containers/`.
5. Respring: `sbreload` (nếu có) hoặc `killall -9 SpringBoard`.
6. Kiểm tra kết quả:
   - `/var/mobile/Library/MyJB/e2e_ok` xuất hiện (payload đã được decrypt + dlopen) ✅
   - Log chi tiết: `launchctl setenv MYJB_DEBUG 1` trước khi respring → `/var/mobile/Library/MyJB/loader.log`.

Kết quả đã verify trên iPhone 6s iOS 13.5.1 (checkra1n rootful) — `cat loader.log`:
```
myjb_loader: /System/Library/CoreServices/SpringBoard.app/SpringBoard: 1 container(s), 0 legacy, 1 key(s)
myjb_loader: com.wmua1.myjb.e2e: trustcache/sign unavailable (9), loading anyway
myjb_loader: com.wmua1.myjb.e2e: loaded
```
và `cat e2e_ok`: `myjb e2e payload loaded: pid=1877 proc=SpringBoard time=...`.
(`trustcache/sign unavailable (9)` là bình thường — rootful không có jbserver.)
