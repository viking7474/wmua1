# Thiết kế bảo vệ tweak cho custom jailbreak (checkm8 & Taurine) — v2

Mục tiêu đã chốt:
- **Tweak chỉ chạy trên bản jailbreak của bạn** (exclusive), không chạy trên Taurine stock / unc0ver / palera1n / checkra1n gốc.
- **Thư viện check nằm trong công cụ jailbreak, KHÔNG nằm trong file tweak.**

Phạm vi:
- Tool checkm8 custom của bạn (Windows, A8–A11, iOS 12–17) — kiểm soát KPF/pongoOS.
- Fork Taurine mở nguồn: `github.com/Odyssey-Team/Taurine` (BSD-4-Clause, iOS 14.0–14.3, A8–A14).

---

## 0. Quyết định kiến trúc: mô hình "encrypted tweak + loader trong tool"

### 0.1 Vì sao "check thuần trong tool" không đủ

Trên một jailbreak khác, **tool của bạn không tồn tại** → check không bao giờ chạy → libhooker/Substitute
vẫn load file dylib bình thường. Vậy điều kiện để "chỉ chạy trên myJB" đúng nghĩa là:

> Tweak phải **không thể hoạt động nếu thiếu tool** — tức là file tweak không phải dylib "sống",
> mà là **ciphertext**, và chỉ thành viên của myJB (tool + server) giữ khóa.

"Check nằm ở tool" = tool giữ **khóa + logic xác thực + quyết định load**. Tweak file chứa 0 code check.

### 0.2 Bốn thành phần

| # | Thành phần | Ở đâu | Vai trò |
|---|---|---|---|
| 1 | Container `.myjb` | Ciphertext phát hành cho user | header + manifest ký Ed25519 + payload XChaCha20-Poly1305 |
| 2 | `myjbd` (loader) | Trong tool, cài qua bootstrap **cả 2 path** | xác thực manifest, lấy khóa, giải mã, cài/load, quản lý vòng đời |
| 3 | Key service | Kernel (checkm8) hoặc daemon/post-exploit (Taurine fork) | cung cấp khóa/per-device secret |
| 4 | Server | Hạ tầng của bạn | phát hành per-device, activation, revoke, telemetry |

Cùng một format container + cùng server + cùng myjbd → một tweak chạy trên cả hai đường (checkm8 & Taurine fork),
nhưng **không chạy trên bất kỳ JB nào khác**.

### 0.3 Luồng hoạt động

```
Kích hoạt (1 lần / refresh):
  myjbd → challenge(nonce) + myJB-proof
  myJB-proof = chữ ký nonce bằng kernel secret (checkm8)
             | daemon secret (Taurine fork)
  Server → { token Ed25519 (udid_hash, features, expiry), K_wrapped }
  myjbd → unwrap K, lưu keychain + /var/mobile/Library/MyJB/

Cài tweak:
  user tải container .myjb từ repo/Sileo (hoặc app của bạn)
  myjbd → verify manifest (Ed25519) + license token + đúng device
        → giải mã payload bằng K → cài đặt (mục 6)

Load:
  theo cơ chế load của từng path (mục 6) — trên JB khác: không có myjbd, file vô dụng.
```

---

## 1. Key service — hai biến thể

### 1.1 checkm8 path (mạnh nhất — bạn kiểm soát kernel)

- KPF (hoặc patch stage tương đương) tạo secret S trong kernel: per-boot hoặc per-device
  (`S = KDF(kernel_secret, udid)`).
- Export qua kênh nhỏ: custom syscall / sysctl node / kernel var — trả về đúng cho myjbd.
- `K = HKDF(S, label="myjb-tweak-key", udid_hash)`.
- Phòng fake: userland tự thêm boot-arg/sysctl giả không tạo được S vì không có signature kernel.

### 1.2 Taurine fork path (trung bình — secret userland)

- Secret sinh trong stage `post-exploit` (sau khi có r/w kernel), ghi vào kernel memory bằng primitives
  (`kern-rw`/`amfidebilitate`), hoặc handoff trực tiếp cho myjbd qua pipe trong memory.
- Nếu attacker debug được daemon → có thể trích S. Bù lại:
  - Server phát hành **K per-device** (mỗi máy một payload ciphertext khác nhau).
  - Watermark per-device (mục 4) → lộ bản giải mã truy được UDID.
  - Revoke server-side.
- Kết luận: dùng được, nhưng đặt kỳ vọng đúng — "tăng chi phí", không "không thể phá".

---

## 2. Tích hợp vào fork Taurine (điểm chèn cụ thể theo cấu trúc repo)

Repo `Odyssey-Team/Taurine` (BSD-4-Clause) gồm: `Taurine.xcodeproj`, `Taurine/{app, exploit, post-exploit,
resources}`, `amfidebilitate/` (exploit), `ctbypass/` (CoreTrust bypass), `kern-rw/` (+`test-kernrw`),
`external/SwiftZSTD`, `Makefile`.

| Thành phần của bạn | Chèn vào đâu |
|---|---|
| Cài + khởi động `myjbd` sau jailbreak | `Taurine/post-exploit/` (stage hậu khai thác) |
| Components trong bootstrap | `Taurine/resources/` (đóng gói ZSTD qua SwiftZSTD) |
| Secret kernel (biến thể 1.2) | code path dùng `kern-rw/` + `amfidebilitate/` sau khai thác |
| Payload ký tự do (nếu cần) | tận dụng `ctbypass/` |
| UI trạng thái/license | `Taurine/app/` |

Lưu ý:
- **libhooker không nằm trong repo** (binary đóng của CoolStar). Hai lựa chọn:
  - Giữ libhooker → myjbd giải mã container ra thư mục substrate (mức MVP — mục 6.1).
  - Thay bằng Substitute/ElleKit (mã mở) → kiểm soát toàn bộ chuỗi load, làm ciphertext-at-rest (mục 6.2).
- License BSD-4: fork được; giữ copyright notice + đáp ứng advertising clause khi phát hành.

---

## 3. Container `.myjb` — format v1 (đã chốt, khớp code P5)

Số nguyên little-endian, packed (không padding).

```
offset        size          nội dung
0             4             magic "MYJB"
4             1             format_version = 1
5             1             algo_id = 1 (Ed25519 + XChaCha20-Poly1305)
6             2             header_flags (reserved = 0)
8             4             manifest_size (u32 LE; v1 = 712)
12            712           manifest (packed):
                            u32 min_ios (major*100+minor, 0=any)
                            u16 target_jb (0xFFFF=any-myJB, 2=amethyst, 1=checkm8, 3=taurine)
                            u16 flags (reserved)
                            u8 payload_hash[32]  — SHA-256(payload plaintext)
                            u8 salt[32]          — HKDF salt
                            u8 nonce[24]         — XChaCha20 nonce
                            u64 payload_size
                            char tweak_id[64] (NUL padded)
                            char version[32]
                            char filters[8][64] — fnmatch pattern, match exec path
                                                  (full hoặc basename); rỗng = mọi process
724           64            Ed25519 signature(header+manifest[0..724)) — private key server
788           payload_size  ciphertext = XChaCha20-Poly1305(key=K_file, nonce=manifest.nonce,
                                          AD=724 byte đầu, plaintext=payload)
788+N         16            Poly1305 tag
```

- Payload = dylib arm64/arm64e đã ký ad-hoc (`ldid -S`) **trước** khi đóng gói; loader
  đọc cdhash từ LC_CODE_SIGNATURE → `jbserver_trustcache` → dlopen file staging → unlink.
- Dẫn xuất khóa (loader thử `K_root` theo thứ tự, dùng cái decode thành công):
  `K_file = HKDF-SHA256(ikm = K_root, salt = manifest.salt, info = "myjb-file-v1:" || tweak_id)`
  1. `/var/mobile/Library/MyJB/kdev` (32B) — **K_device persistent** (server activation đẩy xuống sau này;
     giai đoạn test: tự tạo file 32B random).
  2. `/amethyst/.myjb_devkey` (32B) — chỉ dành cho test field.
  3. `myjb_tweak_key` — session key từ attestation (container dựng theo từng session; dùng cho
     luồng "server mã hóa tại thời điểm activation" — chưa có server).
- Public key Ed25519 nhúng trong `myjb_loader.dylib`; override test bằng
  `/amethyst/.myjb_pubkey` (32B raw). Key DEV hiện tại = RFC 8032 test key #1
  (`d75a9801...`) — **bắt buộc thay bằng key thật khi phát hành**.
- Builder: `tools/myjb_build.py` (thuần Python stdlib: Ed25519 reference, ChaCha20/Poly1305/
  HChaCha20, HKDF-SHA256; `--selftest` chạy RFC 8032/8439/draft-xchacha/RFC 5869).
- Manifest ký bằng private key của bạn (server-side khi build container).
- Payload mã hóa bằng `K` per-device (1.1/1.2) → copy container sang máy khác: vô dụng.
- `target_jb` cho phép chặn tuyệt đối cùng lúc: ví dụ tweak chỉ cho checkm8 path.

---

## 4. Server

- `POST /build`: từ dylib gốc → sinh container per-device:
  1. thêm **watermark** (hằng số/chiruỗi theo udid_hash) vào code/plist;
  2. mã hóa bằng `K_device`;
  3. ký manifest.
- `POST /activate`: nhận challenge + myJB-proof → trả token + `K_wrapped`.
- `POST /refresh`: gia hạn token (offline grace 7–30 ngày).
- `POST /revoke`: thu hồi theo udid/token version.
- `POST /telemetry`: log verify fail, bypass attempt (best-effort).

Token (giữ từ v1): Ed25519, `{udid_hash, features, issued_at, expires_at, nonce}` — verify **trong myjbd**, không trong tweak.

---

## 5. File tweak

- Phát hành: **container `.myjb`** (ciphertext). Không chứa code check.
- (Tùy chọn, lớp phụ) dylib bên trong container có thể import symbol `_myjb_require` với `-undefined dynamic_lookup`;
  thiếu symbol → dlopen fail. Chỉ là lớp làm chậm — kẻ có thể viết stub; vì vậy **không thay thế** mô hình khóa.
- Không hardcode bất kỳ chuỗi "crack check" nào để giảm bề mặt static analysis.

---

## 6. Cơ chế load — hai mức triển khai

### 6.1 MVP: decrypt-at-install (plaintext-at-rest)

- myjbd verify license + giải mã 1 lần/1 lần jailbreak → ghi dylib đã watermark vào substrate dir.
- Ưu: đơn giản, chạy ngay cả khi giữ libhooker.
- Nhược: máy chủ sở hữu có thể copy dylib plaintext đi nơi khác. Giảm thiểu:
  - watermark per-device (mục 4) + telemetry + revoke;
  - giải mã lại mỗi lần boot JB (semi-untethered tự nhiên);
  - mount dir quyền hạn chế, kiểm tra hash lúc load.

### 6.2 v2: ciphertext-at-rest (khuyến nghị khi ổn định)

- Dylib luôn là ciphertext trên đĩa; giải mã **trong RAM tiến trình đích** lúc load.
- checkm8 path: bạn sở hữu chuỗi load → tích hợp vào loader của tool.
- Taurine fork: thay libhooker bằng Substitute/ElleKit (mã mở) + patch lớp đọc dylib → đọc từ store mã hóa.
- Không loại bỏ hoàn toàn dump RAM (chủ máy dump được) — nhưng chặn copy file và giảm mạnh trường hợp share.

Nguyên tắc chung: **không có tuyệt đối** — mục tiêu là "copy container = vô dụng, share bản giải mã = truy được,
server revoke được".

---

## 7. Anti-tamper & telemetry (trong myjbd và loader, không trong tweak)

- Chống debug daemon: `PT_DENY_ATTACH`, kiểm tra `P_TRACED`.
- Chống hook myjbd: verify checksum code segment khi start; chạy kiểm tra rải rác (không 1 điểm).
- Chống fake myJB-proof: proof phải ký nonce bằng secret kernel/daemon (không phải boolean).
- Telemetry: mỗi fail/verify bất thường → log server; dùng để tinh chỉnh + phát hiện share hàng loạt.
- Nếu phát hiện container được copy máy khác: fail K_unwrap (khác device) — ghi nhận và có thể soft-ban.

---

## 8. Checklist triển khai

1. ✅ Format container `.myjb` v1 + builder `tools/myjb_build.py` (thuần stdlib, `--selftest`
   12/12 PASS RFC 8032/8439/draft-xchacha/5869; cross-check pycryptodome). Cặp khóa hiện là
   DEV (RFC 8032 test key #1) — `--gen-key` khi phát hành.
2. 🟡 `myjbd`/loader: bản loader embedded trong Amethyst basebin (P5) đã xong — parse/verify
   Ed25519 (Monocypher), XChaCha20-Poly1305, HKDF-SHA256, staging + trustcache/sign qua
   jbserver, dlopen + unlink (`Amethyst_myJB_Integration.md` §3 P5). Daemon đầy đủ
   (install/quản lý version/uninstall/telemetry) còn ở giai đoạn sau.
3. checkm8 path: KPF chèn secret + kênh export; bootstrap cài + launch myjbd.
4. Taurine fork: chèn vào `post-exploit/` (+ `resources/`), quyết định giữ libhooker (6.1) hay thay Substitute/ElleKit (6.2).
5. Server: `/build` (per-device + watermark), `/activate`, `/refresh`, `/revoke`, `/telemetry`.
6. Kích hoạt từ tool Windows (AFC push helper / app) + repo Sileo cho user còn lại.
7. Test matrix:
   - myJB checkm8 (A8–A11 × 12–17): pass, tweak hoạt động.
   - myJB Taurine fork (A8–A14 × 14.0–14.3): pass.
   - Taurine stock / unc0ver / palera1n / checkra1n gốc: container **vô dụng** (không có myjbd/K).
   - Copy container sang máy khác: unwrap fail.
   - Sửa manifest / giả proof: fail + telemetry.
   - Revoke + hết hạn + offline grace.
8. Drill revoke định kỳ; theo dõi telemetry.

---

## 9. Ranh giới pháp lý & phạm vi

- Bảo vệ tweak của chính bạn (license/DRM hợp pháp) — mục tiêu của tài liệu này.
- Fork Taurine: giữ BSD-4-Clause notice + advert clause; tách code license thương mại khỏi code jailbreak mở nguồn.
- Không tuyên bố "chống crack tuyệt đối"; định vị là "tăng chi phí + server-side revoke + per-device key".
