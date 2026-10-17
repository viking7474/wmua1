# Amethyst × myJB — Phân tích điểm chèn loader/DRM

> Nguồn: `git clone --depth 1 https://github.com/staturnzz/amethyst.git` → `E:\winrain\amethyst`
> (MIT, iOS 12.0–13.7, mọi thiết bị A7–A13 qua Trigon/Hemlock, semi-untethered)
> Tài liệu liên quan: `TweakProtection_Design.md` (thiết kế DRM v2), `Jailbreak_Exploit_Comparison.md`.
> Mọi tham chiếu dạng `file:line` là của repo đã clone.

---

## 1. Kiến trúc thực tế (BaseBin kiểu Dopamine)

Amethyst **không** dùng kernel extension (KEXT). Toàn bộ cơ chế cấp quyền, trustcache,
inject process nằm ở userland nhưng giữ kernel R/W qua `tfp0` (host special port 4):

```
[App Amethyst]
  exploit (trigon → fallback hemlock)                      exploit/trigon, exploit/hemlock
  KPF: tìm offsets trustcache/ptov/pidhash/bootargs        jailbreak/jailbreak.c:252 run_kpf()
  DMA+PPL init (arm64e)                                    jailbreak/dma.c, jailbreak/ppl.c
  remount rootfs rw                                        jailbreak/remount.c
  trustcache_init                                          jailbreak/trustcache.c
  jailbreak_handoff()                                      jailbreak/handoff.c:258
     ├─ extract basebins.tar → /amethyst/{jbutil,launchd_hook.dylib,dyld_patch_text_*.bin}
     │                       → /usr/lib/{base_hook.dylib,libjailbreak.dylib}
     ├─ ghi /amethyst/handoff.plist (địa chỉ kernel + trustcache + pplrw…)   handoff.c:137
     ├─ preload_basebin: trustcache add + PPL trust level write              handoff.c:170
     ├─ jbutil --kickstart = inject_dylib(1, launchd_hook.dylib)             jbutil/main.c:88
     └─ chờ heartbeat jbserver == 0x1337                                     handoff.c:268,302
  jbutil --patch-dyld: chèn shellcode vào __eh_frame của /usr/lib/dyld
     + swap_namecache_vnode(dyld_patch ↔ dyld)                              jailbreak.c:392-404, jbutil/dyld.c:608
  install bootstrap tar + sileo/zebra debs                                  jailbreak/install.c:131
  nvram generator + userspace_reboot                                        jailbreak.c:463-473

[launchd (pid 1)] ← launchd_hook.dylib (giữ tfp0 qua host_get_special_port 4)  launchd_hook/main.c:22
  hook posix_spawn: mọi process con nhận env DYLD_INSERT_LIBRARIES=base_hook  launchd_hook/loader.c:101-107
  respawn /sbin/launchd → tự inject lại launchd_hook + env AMETHYST=1         launchd_hook/loader.c:72-77
  trustcache add / ad-hoc sign binary trước khi spawn (process_binary)        launchd_hook/loader.c:42-68
  HOST jbserver XPC "com.staturnz.jbserver" (hook libxpc)                     launchd_hook/jbserver.c:456 init_server

[base_hook.dylib] trong MỌI process (qua env từ launchd_hook + dyld patch)
  ctor: basebin_init → unsandbox → init_hooks → init_loader → init_tweaks     base_hook/main.c:32-82
  init_hooks: hook csops/csops_audittoken giả CS_VALID|CS_DEBUGGED            base_hook/hooks.c:51-69
  init_loader: hook posix_spawn/execve lan truyền env cho con cháu            base_hook/loader.c:193-196
  init_tweaks: GATE + dlopen libsonar.dylib | TweakInject.dylib               base_hook/main.c:10-30

[dyld patched] — /usr/lib/dyld (shellcode riêng + info struct)
  patch: amfi_check_dyld_policy_self cho phép mọi thứ, closureValid=0,
         magically env DYLD_INSERT_LIBRARIES=/usr/lib/base_hook.dylib          jbutil/dyld.c:345-515
```

**jbserver protocol** (XPC + mach-msg, magic riêng): `common/include/basebin_jbserver.h`,
server dispatch `launchd_hook/src/jbserver.c:256`. Lệnh: TRUSTCACHE, SIGN_BINARY,
INIT_PROCESS, PLATFORMIZE, UNSANDBOX, SET_UID_GID, HEARTBEAT (`0x1337`).
Client lib: `common/src/basebin_jbserver.c` (link vào base_hook + launchd_hook).

**Tweak loader thực tế hôm nay**: `libsonar.dylib` (Sonar – CoolStar, ĐÓNG nguồn),
fallback `TweakInject.dylib`. `migrate_install()` còn tự thêm APT repo Sonar
(`jailbreak/install.c:163-195`). → Đây chính là chỗ phải thay bằng loader myJB.

**Chimera/TNSV2 shim**: `/chimera/launchctl` → symlink `jbutil` (argv[0]=="launchctl"
→ `tnsv2_startup()`), `pspawn_payload*` trỏ vào 2 hook dylib, `jailbreakd.plist` chứa
`KernelBase`/`AllProc` (jailbreak/install.c:11-89). Tweak cũ gọi protocol Chimera sẽ
đi qua đường này → **cửa bypass tiềm năng**.

---

## 2. Bảng điểm chèn myJB

| # | Điểm chèn | File:line | Vai trò myJB |
|---|-----------|-----------|--------------|
| P1 | jbserver command enum + dispatch | `common/include/basebin_jbserver.h`, `launchd_hook/src/jbserver.c` | ✅ **ĐÃ LÀM** `JBSERVER_CMD_MYJB_ATTEST` (XPC) |
| P2 | ~~handoff.plist secret~~ | — | ❌ Bỏ — chuyển sang P3' |
| P3' | Session secret trong RAM launchd_hook | `launchd_hook/src/jbserver.c` (`init_server`) | ✅ **ĐÃ LÀM** `arc4random_buf` 32B mỗi instance, không chạm đĩa |
| P4 | **Gate load tweak** | `base_hook/src/main.c:22-24` (`init_tweaks`) | ✅ **ĐÃ LÀM**: attest → `myjb_tweak_key` |
| P5 | Thay loader dylib | `base_hook/src/main.c:22-24` | ✅ **ĐÃ LÀM** `/usr/lib/myjb_loader.dylib` (ưu tiên) thay `libsonar/TweakInject` |
| P6 | dyld patch info | `common/include/basebin_common.h:53-75`, `jbutil/dyld.c:494-495` | Đổi `base_hook_str`, nhúng build-ID/watermark vào shellcode |
| P7 | Env marker respawn launchd | `launchd_hook/src/loader.c:72-77` (`AMETHYST=1`) | Đổi tên env riêng myJB (anti-fake) |
| P8 | postinst (bootstrap) | `basebins/resources/postinst:15-33` | Watermark + device marker; đây cũng là kênh OTA (`/amethyst/update`) |
| P9 | TNSV2/Chimera shim | `jailbreak/install.c:11-89` | Chặn/bypass-gate đường tweak cũ |
| P10 | XPC whitelist | `launchd_hook/src/jbserver.c:17-23`, `base_hook/src/hooks.c:9-15` | Thêm service myJB vào `lookup_allow_list` |

---

## 3. Chi tiết từng điểm

### P1 + P3'. Key service per-JB-session — ✅ đã triển khai

Thiết kế chốt khi triển khai (đơn giản hơn kế hoạch kernel-slot ban đầu, cùng tính
chất bảo mật, không cần thêm KPF):

- **Secret**: 32B random sinh bằng `arc4random_buf` trong `init_server()`
  (launchd_hook ctor) — **chỉ sống trong RAM của launchd_hook, không ghi đĩa** →
  mỗi boot session một khóa mới, cold reboot mất (đúng mô hình semi-untethered).
- **Lệnh mới** `JBSERVER_CMD_MYJB_ATTEST` (append sau HEARTBEAT trong enum — giữ
  nguyên giá trị các lệnh cũ):
  - Client (`common/src/basebin_jbserver.c`): `jbserver_myjb_attest(challenge, len,
    out32)` → gửi `"challenge"`, nhận `"response"` =
    `HMAC-SHA256(session_secret, challenge)`.
  - Server (`launchd_hook/src/jbserver.c`): `CCHmac` (CommonCrypto — link sẵn qua
    libSystem, giống cách jbutil dùng CC_SHA256).
- **Vì sao không cần secret trong kernel**: muốn trả HMAC đúng phải có secret —
  secret chỉ nằm trong process launchd_hook của mình; chạy được nó = đang chạy
  jailbreak của mình (đúng mục tiêu "tweak chỉ chạy trên bản JB của mình").
  Attacker JB khác không có binary + XPC name + magic của mình → không attest được.
- **Nâng cấp sau (tùy chọn)**: nếu cần chống cả trường hợp copy binary sang cấu
  hình lạ, chuyển secret sang kernel scratch qua KPF (`kpf_find_myjb_slot()`) —
  giữ nguyên interface, chỉ đổi nơi lưu.

### P4. Gate trong base_hook — ✅ đã triển khai

`base_hook/src/main.c` (sau khối safemode, trước khi chọn loader):
```c
__attribute__((visibility("default"))) uint8_t myjb_tweak_key[32] = {0};
__attribute__((visibility("default"))) int myjb_attested = 0;
...
static const uint8_t myjb_challenge[] = "myjb-session-key-v1";
myjb_attested = (jbserver_myjb_attest(myjb_challenge, sizeof(myjb_challenge) - 1, myjb_tweak_key) == JBSERVER_ERR_SUCCESS) ? 1 : 0;
if (myjb_attested == 0 && access("/amethyst/.myjb_verify", F_OK) == 0) return 0;   // strict mode
```
- `myjb_tweak_key` / `myjb_attested` export visibility default → loader dylib (P5)
  `dlsym` được từ handle của base_hook.
- Marker `/amethyst/.myjb_verify` = bật chế độ strict (attest fail → cấm nạp tweak);
  chưa có marker = hành vi như cũ (giai đoạn chuyển tiếp).

### P5. Loader `myjb_loader.dylib` — ✅ đã triển khai (v1)

Nguồn: `basebins/myjb_loader/` → cài `/usr/lib/myjb_loader.dylib` (staging tarball + deb OTA).
Ctor chạy khi `base_hook init_tweaks()` dlopen (ưu tiên trước Sonar/TweakInject):

1. Quét `/var/jb/usr/lib/myjb/containers` + `/var/mobile/Library/MyJB/containers` (`*.myjb`):
   parse header/manifest, verify Ed25519 (pubkey nhúng — DEV = RFC 8032 test key #1, override
   test bằng `/amethyst/.myjb_pubkey` 32B), check `min_ios` / `target_jb` / filters
   (`fnmatch` với exec path + basename), dedupe theo `tweak_id`, sort theo tên file.
2. Thử khóa theo thứ tự: `/var/mobile/Library/MyJB/kdev` → `/amethyst/.myjb_devkey` →
   session key attest (`dlsym` handle base_hook: `myjb_tweak_key` + `myjb_attested`) →
   `K_file = HKDF-SHA256(K_root, manifest.salt, "myjb-file-v1:" + tweak_id)`.
3. Giải mã XChaCha20-Poly1305 (Monocypher 4.0.2 vendored, CC0/BSD-2), đối chiếu SHA-256 payload.
4. Load: ghi staging `run/` (tên random, 1777) → `jbserver_process_library()` (sign/trustcache
   qua jbserver — dylib variant của `process_binary`) → `dlopen(RTLD_NOW)` → `unlink`
   (ciphertext-at-rest; plaintext chỉ thoáng qua trên đĩa, chết ngay sau dlopen).
5. Hook engine: nếu chưa có `MSHookFunction` → thử `/var/jb/usr/lib/libhooker.dylib`
   (RTLD_GLOBAL) trước khi load tweak (bỏ qua nếu không có).
6. Legacy (không mã hóa): **tắt mặc định**; bật bằng env `MYJB_LEGACY=1` hoặc marker
   `/amethyst/.myjb_legacy` → quét `/var/jb/Library/TweakInject` (+ `/var/mobile`) `*.dylib`
   (v1 không đọc plist filter — legacy chỉ để chuyển tiếp).

Knobs: `MYJB_DISABLE=1` hoặc `/amethyst/.myjb_disabled` (tắt hẳn); `MYJB_DEBUG=1` → log thêm
vào `/var/mobile/Library/MyJB/loader.log`. Dirs `myjb/{containers,run}` + quyền (run 1777,
MyJB thuộc mobile) do `myjb_prepare_dirs()` trong launchd_hook `init_server()` tạo (root);
loader tự fallback nếu thiếu. Builder: `tools/myjb_build.py` (spec: `TweakProtection_Design.md`
§3; có `--selftest` RFC 8032/8439/draft-xchacha/5869 + `--info` verify container).

### P6–P7. Binding vào binary của mình

- `dyld_patch_text_12/13.bin` là shellcode **do mình build** — mỗi release nhúng
  UUID/serial; loader kiểm tra bằng cách đọc lại vùng `__eh_frame` của dyld.
- `base_hook_str` (dyld.c:495, struct tại basebin_common.h:73) đổi thành
  `/usr/lib/myjb_hook.dylib` → fork khác copy binary cũng lộ ngay.
- Env `AMETHYST=1` (loader.c:74) đổi thành env riêng; jbserver name
  (`com.staturnz.jbserver`, jbserver.c:332) + magic `JBSERVER_MSG_MAGIC` đổi riêng.

### P8. postinst + OTA

`resources/postinst` chạy root khi cài bootstrap: thêm bước ghi
`/var/mobile/.myjb_serial` + watermark jbutil/launchd_hook (ví dụ patch chuỗi build).
`/amethyst/update` + `update_jailbreak()` (jbserver.c:310-327) là kênh cập nhật —
mọi bản update phải ký bằng key server.

### P9. Chimera shim

Nếu không chặn, tweak cũ đi qua `/chimera/launchctl` → `tnsv2_startup()` → **bỏ qua
gate myJB**. Phương án: thêm attest vào `tnsv2_startup()` hoặc gỡ shim trong fork.

---

## 4. Luồng đề xuất (1 boot)

```
Cold boot → mất JB (semi-untethered)
User mở app → run_jailbreak():
   exploit → KPF → handoff.plist (địa chỉ kernel — KHÔNG chứa secret)
   kickstart launchd_hook → ctor sinh session_secret (RAM) → heartbeat OK
   --patch-dyld + namecache swap → userspace_reboot
Sau userspace_reboot: mọi process spawn → base_hook
App/tweak chạy → base_hook init_tweaks:
   MYJB_ATTEST(jbserver trong launchd) → HMAC-SHA256(session_secret, challenge)
   → myjb_tweak_key (32B) → myjb_loader giải mã .myjb → dlopen
Không có jbserver của mình (chưa JB / JB khác / binary lạ) → không attest → tweak không nạp
```

## 5. MVP vs v2 (khớp TweakProtection_Design.md)

| | MVP | v2 |
|---|---|---|
| Loader | giữ Sonar, chèn attest vào `init_tweaks` trước khi dlopen | thay hoàn toàn bằng `myjb_loader.dylib` |
| Tweaks | phát hành dạng `.deb` bình thường, gate bằng marker | `.myjb` ciphertext-at-rest, per-session key |
| Độ mạnh | chặn máy không JB / JB khác (không có jbserver của mình) | + chống copy file tweak sang máy khác |

## 6. Rủi ro

- **handoff.plist lộ** — tuyệt đối không để secret trong plist; plist chỉ chứa địa chỉ.
- **Fake jbserver**: attacker phải chạy đúng launchd_hook.dylib của mình mới có
  secret — tức đang chạy JB của mình (đúng threat model). Chống copy sâu hơn:
  đổi name/magic (P7) + nhúng build-ID vào shellcode dyld (P6).
- **Sonar đóng nguồn** — v2 phải thay (ElleKit fork hoặc loader tự viết).
- **TNSV2 bypass** (P9) và **bootstrap của jailbreak khác** (`is_bootstrap_installed`
  + `purge cũ` trong migrate_install).

## 7. Trạng thái triển khai (đã sửa trong repo clone)

| File | Thay đổi |
|------|----------|
| `basebins/common/include/basebin_jbserver.h` | + `JBSERVER_CMD_MYJB_ATTEST`, + prototype `jbserver_myjb_attest` |
| `basebins/common/src/basebin_jbserver.c` | + client `jbserver_myjb_attest` (XPC data "challenge"/"response") |
| `basebins/launchd_hook/include/jbserver.h` | + cmd enum đồng bộ giá trị |
| `basebins/launchd_hook/src/jbserver.c` | + `myjb_session_secret`, + handler HMAC (`CCHmac`), + dispatch case, + sinh secret trong `init_server()` |
| `basebins/base_hook/src/main.c` | + gate attest trong `init_tweaks()`, + export `myjb_tweak_key` / `myjb_attested` |
| `basebins/libjailbreak/include/common.h` | + include `mach/*` (Xcode 26 coi implicit declaration là error), + enum sync `JBSERVER_CMD_MYJB_ATTEST` |
| `basebins/myjb_loader/**` | **MỚI (P5)**: `include/myjb_format.h`, `include|src/myjb_crypto.*` (SHA-256/HKDF qua CommonCrypto), `include|src/myjb_container.*` (parse/verify/decrypt/fnmatch), `src/main.c`, `Makefile`, `vendor/` Monocypher 4.0.2 (CC0/BSD-2) |
| `basebins/common/src/basebin_jbserver.c` + `include/basebin_jbserver.h` | + `jbserver_process_library()` (dylib variant: macho_load → `macho_should_sign` ? sign_binary : trustcache) |
| `basebins/base_hook/src/main.c` | `init_tweaks()` dlopen `/usr/lib/myjb_loader.dylib` trước Sonar/TweakInject |
| `basebins/launchd_hook/src/trustcache.c` | trustcache `/usr/lib/myjb_loader.dylib` (cả flow `created` + lock) |
| `basebins/launchd_hook/src/util.c` | `update_jailbreak()` OTA: rename/remove/chmod/trustcache `myjb_loader.dylib` |
| `basebins/launchd_hook/src/jbserver.c` | + `myjb_prepare_dirs()` (myjb/{containers,run} + quyền) trong `init_server()` |
| `basebins/Makefile` + `.gitignore` | myjb_loader vào all/clean/staging (chmod 0755) + ignore artifact |
| `amethyst/Amethyst/Amethyst/jailbreak/handoff.c` | `extract_basebins()` remove stale `myjb_loader.dylib`; `jailbreak_handoff()` `preload_basebin` (F_ADDFILESIGS + trust level 3) |
| `amethyst/Amethyst/Amethyst/ui/MainController.m` | nhận diện jailbroken qua image `/usr/lib/myjb_loader.dylib` |
| `tools/myjb_build.py` | **MỚI**: builder container v1 thuần stdlib (Ed25519/ChaCha20-Poly1305/HKDF ref impl) — `--selftest` 12/12 PASS, `--info`, `--gen-key` |
| `MyJB_Tweak_Dev_Guide.md` | **MỚI**: hướng dẫn tích hợp tweak (đóng container, filters, kdev, attestation API, deb Sileo, troubleshooting) |

Toolchain build (xác nhận từ Makefile): macOS + Xcode CLT
(`xcrun --sdk iphoneos clang`, `-arch arm64e -arch arm64`, `-mios-version-min=12.0`,
`-Werror`), `ldid`, `llvm-objcopy` cho jbutil; framework CoreFoundation/ImageIO/
CoreGraphics/IOKit cho launchd_hook; `make -C basebins package` →
`basebins.tar` + `tnsv2_updater*.deb` (cài `ldid` trên runner, ví dụ qua brew).
Chưa compile được trên Windows — verify bằng GitHub Actions `macos-latest`.

## 8. Việc kế tiếp

1. CI `build.yml` đã chạy xanh 1 lần (`basebins.zip` + `ipa.zip` trong thư mục gốc);
   lần push tới sẽ là lần compile đầu của `myjb_loader.dylib` — cần theo dõi log
   (rủi ro: chỉnh sửa C nhỏ, giống vụ libjailbreak/common.h).
2. Test trên thiết bị thật A12/A13 (iOS 12/13):
   - tạo cặp khóa DEV → nhúng pubkey khi build loader (thay RFC test key #1);
   - tạo `/amethyst/.myjb_devkey` (32B) + container test bằng `tools/myjb_build.py`;
   - JB bình thường → tweak chạy; gỡ launchd_hook/jbserver → tweak bị chặn
     (bật strict bằng marker `/amethyst/.myjb_verify`).
3. Các điểm P6–P10 (watermark dyld shellcode, đổi env/jbserver name/magic, postinst,
   chặn Chimera shim `tnsv2_startup`).
4. Sinh khóa production khi phát hành: `myjb_build.py --gen-key` → thay DEV key nhúng
   trong `myjb_loader/src/main.c` (`myjb_embedded_pubkey`).
