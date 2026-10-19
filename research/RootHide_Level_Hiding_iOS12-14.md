# Ẩn jailbreak cấp RootHide trên iOS 12–14 (legacy checkra1n + myJB)

> Nguồn: phân tích nhánh `--legacy` trong `checkm8/ktool` (`openra1n.c`) + payload đã dump
> (`legacy_kpf.bin`, `legacy_ramdisk.bin`, `ramdisk.bin`, `overlay.bin` — palera1n v2.0.0-beta.8,
> checkra1n 0.12.4b) + thiết kế myJB (`TweakProtection_Design.md`, `Checkm8_myJB_Integration.md`,
> `Amethyst_myJB_Integration.md`).
> Phạm vi: iOS 12.0–14.8.1, A8–A11 (checkm8, semi-tethered). Mọi tham chiếu `file:line` là của repo này.

---

## 0. TL;DR

- "Cấp RootHide" = 3 trụ: **prefix động/randomized** + **hook runtime ẩn path/mount/dyld** +
  **profile theo app cập nhật liên tục** (roothidepatches). Không phải một switch kỹ thuật đơn lẻ.
- Trên 12–14 có thể đạt tương đương và **vượt ở một trục**: checkm8 cho kernel r/w **mỗi lần JB boot**
  → lớp ẩn kernel (RootHide thuần userland không có).
- Hai việc bắt buộc để có "đĩa sạch khi tắt JB": **fakefs** (rootfs không bị ghi) +
  **relocate artifact** khỏi path cố định.
- Giới hạn cứng không tránh được 100%: app tự quét `vm_map` trong process (cần kernel fake
  `mach_vm_region`), syscall gọi trực tiếp (bỏ qua hook userland), bảo trì profile theo app.
- Bootstrap prefix-aware cho 12–14 **không có sẵn**: roothide bootstrap là Procursus 15–16 arm64e —
  không port được; phải tự fork Procursus 12–14 hoặc "virtual prefix" bằng hook.

---

## 1. "Cấp RootHide" thực chất gồm gì

| Trụ | RootHide (15–16, Dopamine base) | Tương đương trên 12–14 legacy |
|---|---|---|
| Prefix động | Bootstrap trong app container `.jbroot-xxxx` + `jbroot()` runtime | Mục 3-L1 (relocate) + L3 (virtual prefix bằng hook) |
| Runtime hooks | `libroot` ẩn path/mount/dyld cho app "không được phép thấy" | `myjb_loader` (đã chạy trong mọi process bootstrap) |
| Profile theo app | `roothidepatches` — patch theo từng app, cập nhật liên tục | Container ký + server OTA + myjbd (hạ tầng myJB đã có) |
| Trạng thái ngoài JB | Rootless, không đụng rootfs | Fakefs + không mount khi chưa JB |

Điểm khác nền tảng cần nhớ: Dopamine rootless (15–16) nên "đĩa sạch" là mặc định; checkra1n
legacy 12–14 **rootful** — dấu vết trên đĩa tồn tại cả khi không JB → đây là bài toán phải giải trước.

---

## 2. Dấu vết hiện tại của nhánh legacy (cần xử lý)

| Dấu vết | Bằng chứng trong repo | Detector điển hình |
|---|---|---|
| Rootfs bị sửa (snapshot remount / shared-region patch 12.x) | `legacy_kpf.bin` chứa `kpf_find_offset_p_flags`, `_kpf_shared_region_root_dir_patch`, `_kpf_vnop_rootvp_auth_patch`, `"KPF: Disabled snapshot temporarily"` | liệt kê `/Applications/Cydia.app`, `/var/lib/dpkg`, `/etc/apt` |
| Mount snapshot/fakefs khi JB đang bật | KPF (xem thêm `WinRa1n2.1_analysis.md` §5.4: "APFS mount/rename cho fakefs") | `getfsstat` / `statfs` |
| Substrate + mirror loader | `checkm8/package/DEBIAN/postinst` (`mirror_into` — chỉ mirror vào engine dirs khi engine thật sự có mặt; rootful không đụng `/var/jb`) | path + `_dyld_get_image_name` |
| Env inject (`DYLD_INSERT_LIBRARIES`, marker) | cơ chế inject của bootstrap; `launchd_hook/src/loader.c` (Amethyst) | `getenv`, `sysctl KERN_PROCARGS2` |
| Daemon lạ (jailbreakd/dropbear/myjbd) | process list | `sysctl KERN_PROC_ALL`, `proc_listpids` |
| csflags giả (CS_DEBUGGED) | tiền lệ Amethyst `basebins/base_hook/src/hooks.c:51-69` | `csops_audittoken` |
| Flags cờ boot legacy | `checkm8/ktool/openra1n.c:139-141` (`LEGACY_KPF_FLAG_VERBOSE_BOOT 0x2`), payload có command `checkra1n_flags`/`kpf_flags` | `sysctl kern.bootargs`, behavioral |

Lợi thế tự nhiên của semi-tethered: sau reboot chưa qua ktool — kernel sạch, không mount, không
inject; chỉ còn dấu trên đĩa. Nên thứ tự ưu tiên là **đĩa (L0/L1) → runtime (L3) → kernel (L2)**.

---

## 3. Kiến trúc 4 lớp đề xuất

| Lớp | Cơ chế | Điểm chèn trong repo | Việc cần làm |
|---|---|---|---|
| L0 Data | Relocate kdev/containers khỏi path cố định; bind kdev theo ECID | `checkm8/package/DEBIAN/postinst:4-22` (`/var/mobile/Library/MyJB`) | Dời sang path kiểu app-container random; ktool đọc ECID trong DFU (gaster) để sinh/bind kdev |
| L1 Cấu trúc | Fakefs + "virtual prefix": rootfs không ghi, path JB chỉ tồn tại khi mount | Chuỗi `--legacy` (`openra1n.c:1459-1485`); payload beta8 có `create_fakefs.sh` + `checkrain_option_*`; legacy KPF có snapshot/rename + `checkra1n_flags` | Verify bits cờ fakefs của payload legacy, thêm `--fakefs` vào ktool, test matrix theo combo máy/iOS |
| L2 Kernel | Filter syscall theo allowlist, che mount, ẩn PID, fake mach traps | Module PongoOS tự build (`modload`) hoặc myjbd patch runtime qua tfp0 (kênh kiểu jailbreakd — cần verify API) | Demo trước: che 1 mount + 1 path; sau: force `fork()` EPERM, fake `mach_vm_region` |
| L3 Userland | Hook table + policy per-app (tương đương `libroot`/roothidepatches) | `basebins/myjb_loader/` (chạy trong mọi process qua Substrate/ElleKit) | Thêm module "hide": file/mount/dyld/env/csops; ẩn chính loader khỏi image list; policy đọc từ container ký |

Ghi chú L1: `ramdisk.bin` (beta8) chứa sẵn `create_fakefs.sh`, `palerain_option_clean_fakefs`,
`checkrain_option_force_revert` — chứng minh mảnh máy fakefs tồn tại trong dòng payload;
khả năng áp cho 12–14 legacy cần test thực nghiệm (ra1npoc từng chạy checkra1n 0.1337.x cho iOS 14).

---

## 4. Bề mặt hook khả dụng theo tầng

### 4.1 Kernel (mạnh nhất — chỉ checkm8 có)

**Nhóm syscall có thể filter qua bảng `sysent` (hoặc patch hàm):**

| Nhóm | Syscall / API | Dùng để |
|---|---|---|
| File | `open`, `openat`, `open_dprotected_np`, `fstatat` (stat/lstat), `access`, `faccessat`, `readlink(at)`, `getattrlist`, `getattrlistbulk`, `getdirentries`, `realpath` | ẩn path JB/myJB trên toàn hệ thống, kể cả process không bị inject |
| Mount | `statfs`, `getfsstat` | ẩn fakefs/snapshot bind khỏi mount table |
| Process | `sysctl` (KERN_PROC_*), `proc_info`, `posix_spawn`, `ptrace`, `task_for_pid` | ẩn/che daemon, chặn debug, chặn `fork()` thành công cho app không-cho-phép |
| Security | `csops`, `sysctl kern.*` | fake csflags/boot-args/KPF traces |
| Mach | `_kernelrpc_mach_vm_region`, `_kernelrpc_mach_vm_region_recurse` (mach trap) | che vùng nhớ dylib inject khi app tự quét address space (userland không hook được mach trap gọi thẳng) |

**Cấu trúc dữ liệu kernel có thể sửa:**

- `mountlist` — che fakefs/snapshot bind (đổi hướng iterator kiểu VNodeBypasser/KernBypass).
- `allproc` / `p_flag` — ẩn PID, ẩn process jailbreak; force `fork()` lỗi.
- csflags per-proc — nhất quán với hook `csops` ở userland.
- `PE_state.PE_i_can_has_debugger`, `cs_enforcement_disable`, `PE_parse_boot_argn` — trạng thái
  KPF/AMFI mà detector có thể dò gián tiếp.
- **IORegistry properties** — điểm mạnh cho consistency thiết bị (mục 5): mọi consumer IOKit đọc
  cùng một giá trị nếu fake ở kernel.

**Cách chèn:** (a) module PongoOS (patch kernel in-memory trước `bootx` — đúng cách KPF hoạt động);
(b) daemon sau boot patch qua tfp0 (iterate nhanh hơn, mất khi reboot — khớp mô hình semi-tethered).
Với maintenance, (b) nên làm trước, (a) chỉ cho thứ bắt buộc phải có trước userland.

### 4.2 launchd / XPC (tầng hệ thống)

| Điểm | Cơ chế | Ghi chú trong repo |
|---|---|---|
| `posix_spawn`/`execve` hook | Scrub env trước app, quyết định inject, chặn spawn đáng ngờ | Mẫu: `launchd_hook/src/loader.c` (Amethyst) |
| LaunchDaemons/jobs | Đặt daemon + plist ở path random, ẩn khỏi `launchctl list` | Mở rộng `checkm8/package/DEBIAN/postinst` |
| XPC service | jbserver riêng (tên + magic riêng), attestation | Mẫu: `launchd_hook/src/jbserver.c` (Amethyst), kế hoạch myjbd |
| Kênh kernel r/w cho userland | jailbreakd (bootstrap checkra1n — verify API trước khi phụ thuộc) hoặc myjbd tự phát lại bộ lệnh jbserver | `basebins/common/src/basebin_jbserver.c` |

### 4.3 Per-process — `myjb_loader` (chạy trong mọi process bootstrap)

| Nhóm | API | Mục đích |
|---|---|---|
| File | `open/openat`, `fstatat`, `access/faccessat`, `readlink`, `getattrlist(bulk)`, `getdirentries`, `opendir/readdir/scandir`, `realpath` | Ẩn path JB/myJB, fake nội dung file nhạy cảm |
| Mount | `getmntinfo`, `statfs`, `getfsstat` | Ẩn mount, fake dung lượng trống "/" |
| Process | `sysctl` (KERN_PROC*, KERN_PROCARGS2), `proc_listpids`, `proc_pidinfo`, `proc_pidpath`, `kill` | Ẩn daemon, che env/cmdline |
| dyld | `_dyld_image_count`, `_dyld_get_image_name`, `_dyld_get_image_header`, `dladdr`, `dlsym` | Ẩn `myjb_loader` + engine inject khỏi image list |
| Env | `getenv`, `_NSGetEnviron`, `NSProcessInfo.environment` | Scrub `DYLD_*`, marker myJB |
| cs/sandbox | `csops`, `csops_audittoken`, `sandbox_check(_by_audit_token)` | Fake CS_VALID/CS_DEBUGGED, denial nhất quán theo policy |
| Mach/VM | `mach_vm_region(_recurse)` wrapper, `task_info` | Che vùng inject — chỉ khi detector gọi qua wrapper; gọi syscall trực tiếp phải dùng L2 |
| ObjC | `NSFileManager`, `NSURL`, `UIApplication canOpenURL:` | Che `cydia://`, `sileo://`, check mức cao |
| libc stdio | `fopen/fread/fgets`, `statvfs` | Detector dùng stdio thay vì POSIX |

**Đối chiếu nhanh "app nào thấy gì":**

- App thường (NSFileManager, MGCopyAnswer, IOKit qua wrapper) → L3 đủ.
- App khó (syscall trực tiếp, quét `vm_map`, so chéo userland vs kernel value) → cần L2.
- Tooling hệ thống/MDM → L1 + L2.

---

## 5. Thông tin thiết bị có thể hook / spoof (ví dụ)

Nguyên tắc vàng: **fake ở tầng thấp nhất có thể** để mọi đường đọc khớp nhau
(MobileGestalt đọc lại IORegistry/sysctl; detector hay so chéo nhiều nguồn).
Userland hook chỉ dùng thêm cho policy per-app (riêng app nào thấy giá trị nào).

| # | Thông tin | Nguồn chuẩn (12–14) | Hook 1 điểm | Ghi chú |
|---|---|---|---|---|
| 1 | UDID | MobileGestalt `UniqueDeviceID`; PC: lockdown/AFC | `MGCopyAnswer` (L3) | ECID thật đọc được từ PC trong DFU (gaster in CPID/ECID) — dùng bind kdev/đối chiếu |
| 2 | Serial | IOKit `IOPlatformSerialNumber`; MG `SerialNumber` | IORegistry (L2) hoặc MG (L3) | Fake ở L2 → MG tự khớp, IOKit apps cũng khớp |
| 3 | IMEI/ICCID | baseband private API; MG `InternationalMobileEquipmentIdentity` | MG (L3); baseband: khó | Cần nhất quán với carrier check |
| 4 | MAC WiFi/BT | IONetworkInterface `IOMACAddress` (en0); MG `WifiAddress`/`BluetoothAddress` | IORegistry (L2) / MG | Detector hay so với BSD interface thật |
| 5 | Model | `hw.machine`, MG `ProductType` (`iPhone10,3`), `HWModel` (`D221AP`) | sysctl (L2) + MG | |
| 6 | iOS version/build | `kern.osversion` (`17G80`), MG `BuildVersion`, `ProductVersion` | sysctl (L2) + MG | Cẩn thận: lệch với dyld/header version → detectable |
| 7 | Tên máy, UIDevice fields | `UIDevice`; preferences | ObjC swizzle (L3) | |
| 8 | IDFA/IDFV | AdSupport; NSUUID | swizzle (L3) | |
| 9 | APFS volume UUID, DiskUsage | IOMedia props; MG `DiskUsage` | IORegistry (L2) / MG | Anti-fraud hay dùng |
| 10 | Battery serial/cycle count | `AppleSmartBattery` IORegistry | IORegistry (L2) | |
| 11 | Uptime/boottime, boot-args | `kern.boottime`, `kern.bootargs` | L2 | Che `-v`, `rd=md0`, dấu KPF |
| 12 | Danh sách process/daemon | `kern.proc` | L2 | Giấu jailbreakd/myjbd/dropbear |
| 13 | csflags (debugged) | `csops` | L3 (tiền lệ Amethyst) — L2 backup | |
| 14 | Dung lượng trống "/" | `statfs` | L3/L2 | Detector phổ biến |
| 15 | MLBSerial, Regulatory model, hàng chục key MG khác | MobileGestalt | **`MGCopyAnswer` (L3)** | 1 hook phủ rất nhiều key |

### 5.1 Ví dụ "1 điểm hook phủ nhiều thông tin"

`MGCopyAnswer(CFStringRef)` là cửa ngõ chung của gần như mọi app khi cần serial/UDID/MAC/model:

```c
/* L3 (myjb_loader) — policy per-app đọc từ container ký (attestation đã có sẵn) */
static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef);
static CFTypeRef hook_MGCopyAnswer(CFStringRef key) {
    if (myjb_policy_applies(getprogname(), key))
        return myjb_fake_value(key);        /* UDID/serial/MAC/model... theo profile */
    return orig_MGCopyAnswer(key);
}
```

Giới hạn: app đọc serial qua IOKit trực tiếp sẽ không thấy bản fake ở L3 → muốn "cross-check proof"
phải fake ở L2 (IORegistry/kernel). Vì vậy bảng trên phân tầng theo **nguồn chuẩn**, không theo API.

### 5.2 ECID — không phải điểm hook, mà là "ground truth"

ECID không lộ cho app trên máy, nhưng **tool PC đọc được ngay trong DFU** (gaster: CPID/ECID;
WinRa1n dùng `AMRecoveryModeDeviceGetECID`). Dùng làm neo:
kdev derive theo ECID (bỏ copy tay), attestation per-device, phát hiện spoof phía máy.

---

## 6. Giới hạn / rủi ro

1. **Self-scan `vm_map`**: app quét address space của chính nó vẫn thấy vùng dylib inject —
   cần fake `mach_vm_region` ở L2. RootHide cũng không giải triệt để trục này.
2. **Syscall trực tiếp**: detector dùng `__syscall` bỏ qua toàn bộ L3 → bắt buộc L2 cho tier cao.
3. **Offsets kernel theo build**: 12.0–14.8.1 có rất nhiều build → cần patchfinder + test matrix
   (khớp C10 trong `Checkm8_myJB_Integration.md`); ưu tiên patch runtime qua daemon để iterate nhanh.
4. **Fake IORegistry là global**: đổi cả daemon hệ thống (activation/backup) — cân nhắc kết hợp
   filter theo process ở L2 (được nhưng phức tạp), hoặc chỉ global cho key ít rủi ro.
5. **Lệch giá trị giữa các nguồn = detectable**: mỗi key cần một "source of truth" và fake đồng bộ
   từ đó (bảng mục 5 thiết kế theo tiêu chí này).
6. **Spoof local không lừa được attestation phía Apple/server** (DeviceCheck/App Attest) — 12–14
   dùng ít, nhưng DRM của myJB vẫn nên dựa vào server + per-device key (`TweakProtection_Design.md`).
7. **Duy trì profile theo app** — đây là "roothidepatches equivalent": nội dung thật của cấp RootHide
   là quy trình cập nhật, không phải code.

---

## 7. Roadmap hành động

1. `--fakefs` cho chuỗi legacy: verify bits cờ (`checkra1n_flags`/`kpf_flags`), thêm option vào
   `checkm8/ktool`, test máy thật 12–14 (ưu tiên 12.2+ và 13.5.1 đã có E2E).
2. Hook-table skeleton trong `myjb_loader`: file/mount/dyld/env trước, policy từ container ký.
3. Demo L2: che 1 mount + 1 path qua daemon tfp0 (runtime trước, module PongoOS sau).
4. Relocate kdev/containers (L0) + bind ECID từ ktool.
5. Profile per-app qua server OTA (myjbd) — biến cấp RootHide thành dịch vụ duy trì được.

---

## 8. Kết quả verify (2026-10-17) — cập nhật mục L1 & roadmap 1

### 8.1 Cờ legacy — đã xác minh từ ra1npoc (branch `ios15`) + binary

- `kpf_flags` (gửi cho KPF): layout **cũ** `old_checkrain_option_verbose_boot = 1<<1`
  → `0x2` (code hiện tại `openra1n.c:139-141` đúng).
- `checkra1n_flags` (userland/loader): layout cũ `old_checkrain_option_safemode = 1<<0`;
  layout mới (0.1337): `safemode 1<<0, bind_mount 1<<1, overlay 1<<2, force_revert 1<<7`.
- **Không tồn tại bit fakefs trong checkra1n** — fakefs không phải khái niệm của checkra1n.
  Chuỗi legacy của ra1npoc thậm chí không gửi `checkra1n_flags` (dead code).
- `legacy_kpf.bin` (111864 B, Mach-O kext) là KPF họ checkra1n hỗ trợ 12–16, có
  `_checkra1n_flags`/`_gkpf_flags`/`_preboot_hook`, APFS-mount patch, snapshot patch;
  **không có** rootdev/paleinfo/bootprep (khác `checkra1n-kpf-ploosh.bin`).

### 8.2 Giải phẫu `legacy_ramdisk.bin` (HFS+ 1 MB, blockSize 4096, 7 file)

```
/payload               116768  = loaderd (com.apple.checkra1n.loaderd, ObjC)
/payload.dylib          52608  = stage4entry hook (DYLD_INSERT_LIBRARIES vào launchd)
/sbin/launchd           35168  = fakelaunchd (checkra1n mini-launchd + entitlements)
/usr/lib/dyld           50560  = dyld đã patch
/patch_dyld.{ios,tvos,bridgeos} 56336 = patcher dyld (symtab forEachSupportedPlatform)
/binpack/lib/                 = rỗng (bản ra1npoc lược binpack/loader.dmg)
```

- Boot: pongoOS → KPF → md0 → fakelaunchd → payload.dylib (remount md0 rw, spawn `/payload`)
  → loaderd (mount binpack/loader.dmg, tải `checkra1n.dmg` qua TCP **1337** từ host —
  "host connected, writing" — hoặc WiFi check.in; cài bootstrap; snapshot ops).
- loaderd mount/mở rộng theo **`/dev/disk0s1s1` hardcoded** + `orig-fs` (iOS 14:
  rename boot-snapshot, "remounting / as rw"; `fs_snapshot_*`); **không có cơ chế fakefs**.
- ⇒ Không thể "redirect cài đặt vào fakefs" chỉ bằng cờ/boot-arg. Fakefs cho 12–14 phải
  do stage riêng trong ramdisk thực hiện (thay thế/hook loaderd) hoặc thay ramdisk.

### 8.3 Fakefs của palera1n (đã trích `create_fakefs.sh` từ `ramdisk.bin` beta8)

- `newfs_apfs -A -D -o role=r -v Xystem /dev/disk0s1` → volume mới; mount realfs ro;
  `cp -a` toàn bộ rootfs (partial mode copy subset) → boot từ volume mới.
- Cờ: `palerain_option_setup_rootful (1<<2)` = "create fakefs", `clean_fakefs (1<<9)`,
  `force_revert (1<<24)`, `verbose_boot (1<<26)`; flags truyền qua struct `paleinfo`
  ('PLSH') **append vào ramdisk** + command `palera1n_flags` (KPF ploosh). Chuỗi palera1n
  hiện gửi `0x4000000` = verbose_boot (không phải setup_rootful).
- Điều kiện: jbloader cần `mount("tmpfs","/cores")` → kernel < 15 không có tmpfs
  (C7: 13.5.1 ENODEV) ⇒ chuỗi palera1n/fakefs gốc không chạy 12–14.

### 8.4 Hệ quả cho L1 trên 12–14

- iOS 14: checkra1n tự rename snapshot `orig-fs` (bản chất "livefs + snapshot gốc giữ lại")
  — tương đương một nửa fakefs (revert được, nhưng mods vẫn nằm trong rootfs thật).
- iOS 12/13: không có snapshot; fakefs thật cần stage riêng: tạo volume + copy rootfs +
  boot `rootdev=<fakefs>` (kernel 12–14 có tôn trọng rootdev cho APFS volume? — cần test máy thật)
  + installer của myJB thay loaderd để cài basebin vào fakefs.
- Hook khả thi trong ramdisk hiện có: thay `/payload` bằng stage riêng (payload.dylib spawn
  `/payload`) rồi exec loaderd thật; thêm binary qua repack HFS+; build binary stage cần
  cross-toolchain Mach-O (checkra1n/SDK công khai).
