# Phân tích kỹ thuật: WinRa1n 2.1 (Windows)

> Tài liệu phân tích tĩnh binary `WinRa1n2.1.exe` — tập trung vào **cơ chế hoạt động trên Windows** (khác với checkra1n/palera1n trên Linux/macOS đã có sẵn công cụ).
>
> - **File:** `WinRa1n2.1.exe` (126.509.568 bytes)
> - **SHA-256:** `195eb3d5707ec45d372edfd00017086a977a04dbc6aad0d056078d543a2a5255`
> - **Nhà phát triển:** iKeyTools (2023) — phiên bản 2.1.0.0
> - **Công cụ phân tích:** pefile, dnfile, dncil, quét magic/entropy thủ công
> - Các offset ghi trong tài liệu là **offset trong file**, có thể xê dịch ±vài trăm byte do suy luận từ cấu trúc.

---

## 1. Tổng quan file

| Thuộc tính | Giá trị |
|---|---|
| Định dạng | PE32+ (x64), .NET Framework 4.x (CLR v4.0.30319), WinForms |
| Subsystem | Windows GUI (2) |
| EntryPoint RVA | `0x0` (bất thường — loader đặc biệt của assembly .NET) |
| Import table | Trống (đặc trưng .NET); toàn bộ native API qua P/Invoke trong metadata |
| Assembly | `WinRa1n, Version=2.1.0.0` |
| CompanyName (version info) | `iKeyTools` — Copyright `iKeyTools 2023` |
| Manifest | `asInvoker` (tool yêu cầu user tự "Run as administrator"), `longPathAware`, DPI-aware |
| Sections | `.text` (~62 MB), `.LNz` (~63 MB, entropy ~8.0), `.#<m` (545 KB), `.rsrc` |
| Kích thước "logic" thật | ~5.535 method — phần còn lại là **payload nhúng** (chạy offline, không cần tải ramdisk) |

### 1.1. Bảo vệ / obfuscation

- Tên Type/Method bị đổi thành chuỗi hex ngẫu nhiên (`A5B530BD`, `B73DE2AF`…); namespace gốc còn sót: `iKeyUtils`, `WinRa1n.Properties`.
- Assembly reference giả `FA9FED87` (không resolve type nào) — dấu hiệu protector.
- IL có **control-flow obfuscation**: chuỗi `ldloc/ldc.i4/and/xor/shr` vô nghĩa (opaque predicates) + nhánh giả trỏ tới địa chỉ không hợp lệ.
- 6 manifest resource đổi tên hex (`870EA20A.resources`…) — dữ liệu mã hóa, là nơi chứa payload/string mã hóa.
- User-string heap (#US) rất nhỏ (~780 byte) → hầu hết string literal bị mã hóa và giải mã runtime.
- Toàn bộ payload nhúng nằm dạng **plaintext** trong `.text`/`.LNz` (không mã hóa) — đây là điểm yếu giúp phân tích.

---

## 2. Vì sao Windows là phần khó (khác Linux/macOS)

Trên Linux/macOS, checkra1n/palera1n chạy trực tiếp vì hệ điều hành cho phép **raw USB access** qua libusb/thư viện chuẩn. Trên Windows có 3 rào cản:

| Rào cản trên Windows | Hệ quả | WinRa1n giải quyết |
|---|---|---|
| Windows không cho user-mode truy cập USB device trực tiếp; driver mặc định (`usbaapl64.sys` của Apple) chỉ expose giao tiếp MTP/usbmux, không cho control/bulk transfer tùy ý | Không thể gửi payload checkm8 vào DFU | **Thay driver**: gỡ Apple driver khỏi thiết bị, bind `libusbK`/`libusb0` (qua libwdi) để mở raw USB bằng WinUSB/LibUSBK API |
| Windows không có `usbmuxd`/`libimobiledevice` sẵn | Không nói chuyện được với iOS ở mode Normal/Recovery | P/Invoke trực tiếp vào **MobileDevice.dll** + `CoreFoundation.dll` (từ Apple Mobile Device Support) và `USBMuxConnectByPort` (ws2_32) làm tunnel |
| Windows không có sẵn checkra1n/palera1n binary | Không có engine jailbreak | **Nhúng sẵn engine**: pongoOS, KPF, loaders, ramdisk DMG, bootstrap (~112 MB) chạy trực tiếp từ app |

---

## 3. Kiến trúc tổng thể (các tầng)

```
┌────────────────────────────────────────────────────────────────┐
│  GUI (.NET WinForms) — nút Checkm8 / Checkra1n / Palera1n /   │
│  Fix Driver / Rootful-Rootless / tiến trình, ads, GuideUrl    │
├────────────────────────────────────────────────────────────────┤
│  License layer (iKeyUtils: HttpBag/ConfigBag)                  │
│  activation.php?code&hwid&hash  →  MD5/SHA256(HWID=MAC)        │
├────────────────────────────────────────────────────────────────┤
│  Payload manager: giải mã resources → thư mục tạm → extract    │
│  (ZipFile.ExtractToDirectory), quản lý thư mục làm việc        │
├──────────────┬─────────────────────┬───────────────────────────┤
│  Windows     │  USB raw layer      │  Apple layer              │
│  driver layer│  (libusb)           │  (MobileDevice / CF)      │
│  newdev,     │  libusbK.dll        │  AMDevice*, AFC*,         │
│  setupapi,   │  libusb0.dll        │  USBMuxConnectByPort,     │
│  drvstore,   │  USBDK backend      │  AirTrafficHost,          │
│  CfgMgr32    │  (LoadLibrary +     │  CoreFoundation           │
│              │  GetProcAddress +   │                           │
│              │  GetDelegateForFP)  │                           │
├──────────────┴─────────────────────┴───────────────────────────┤
│  Engine nhúng: checkm8 → pongoOS 2.6.2 → KPF → ramdisk DMG →   │
│  bootstrap (Sileo/Zebra/ellekit/dropbear) — bản checkra1n &    │
│  palera1n                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## 4. Toàn bộ P/Invoke theo DLL (trích từ bảng ImplMap — 297 entry)

### 4.1. `MobileDevice.dll` (91 hàm) — giao tiếp thiết bị Apple
- **Session/Notify:** `AMDeviceNotificationSubscribe/Unsubscribe`, `AMDListenForNotifications`, `AMDPostNotification`, `AMDObserveNotification`
- **Vòng đời:** `AMDeviceConnect/Disconnect`, `AMDeviceStartSession/StopSession`, `AMDevicePair/Unpair/ValidatePairing/IsPaired`, `AMDeviceRetain/Release`
- **Thông tin máy:** `AMDeviceCopyDeviceIdentifier/CopyValue/SetValue/RemoveValue`, `AMDeviceGetConnectionID/GetInterfaceType`
- **Recovery/DFU:** `AMDeviceEnterRecovery`, `AMRecoveryModeDeviceGet{ProductType,ProductID,BoardID,ECID,LocationID,TypeID}`, `AMRecoveryModeDeviceCopy{IMEI,SerialNumber}`, `AMRecoveryModeDeviceReboot`, `AMRecoveryModeDeviceSetAutoBoot`, `AMRecoveryModeDeviceCopyEnvironmentVariableFromDevice`, `AMRecoveryModeDeviceCopyAuthlnstallPreflightOptions`, `AMDFUModeDeviceGet{ProductID,ProductType,ECID,BoardID}`
- **Restore:** `AMRestoreModeDeviceCreate/CopyIMEI/CopyBoardConfig`, `AMRestorableDeviceGetECID`, `AMRestoreCreateDefaultOptions`, `AMRestorePerformRecoveryModeRestore`, `AMRestoreRegisterForDeviceNotifications`
- **Cài app (IPA):** `AMDeviceInstallApplication/UninstallApplication/ArchiveApplication/TransferApplication/LookupApplications/LookupApplicationArchives`
- **Activation:** `AMDeviceActivate/Deactivate/CreateActivationInfoWithOptions`
- **Service/Socket:** `AMDeviceStartService/SecureStartService`, `AMDServiceConnectionGetSocket/Receive/Send/GetSecureIOContext`
- **AFC (file system):** `AFCConnectionOpen/Close/IsValid/GetFSBlockSize/SetSecureContext/Invalidate`, `AFCDirectoryOpen/Read/Close/Create`, `AFCFileRefOpen/Read/Write/Close/Seek/Tell/Lock/Unlock/SetFileSize`, `AFCFileInfoOpen`, `AFCGetFileInfo`, `AFCKeyValueRead/Close`, `AFCRemovePath/RenamePath`, `AFCDeviceInfoOpen`, `AFCFlushData`
- **usbmux:** `USBMuxConnectByPort` (thực chất export qua Ws2_32 path)

### 4.2. `CoreFoundation.dll` (59 hàm)
Toàn bộ thao tác `CFString/CFData/CFArray/CFDictionary/CFNumber/CFDate/CFPropertyList*` — cần để dựng/đọc **plist** và chuyển tham số cho MobileDevice API (AMDevice* nhận CFTypeRef).

### 4.3. `AirTrafficHost.dll` (14 hàm)
`ATHostConnection*`, `ATProcessLinkSendMessage`, `ATCFMessageCreate` — kênh đồng bộ (dùng cho một số op file/media; ít vai trò với jailbreak, có thể dùng để "làm quen" thiết bị như iTunes).

### 4.4. Windows driver management (points quan trọng nhất so với Linux/macOS)

| DLL | Hàm | Vai trò |
|---|---|---|
| `newdev.dll` | `DiInstallDriver`, `DiUninstallDriver` | Cài/gỡ driver package lên một device cụ thể |
| `setupapi.dll` (15) | `SetupDiGetClassDevs/EnumDeviceInfo`, `SetupDiBuildDriverInfoList`, `SetupDiSetDeviceInstallParams`, `SetupDiGetDriverInfoDetail`, `SetupCopyOEMInf`, `SetupUninstallOEMInf`, `SetupVerifyInfFile`, `CM_Locate_DevNode`, `CM_Reenumerate_DevNode` | Liệt kê thiết bị, ép driver install params, copy INF vào DriverStore, verify chữ ký |
| `drvstore.dll` (24) | `DriverStoreImportW/PublishW/OpenW/Close`, `DriverStoreEnumW/ObjectsW`, `DriverStoreReflectW/ReflectCriticalW/UnreflectCriticalW`, `DriverStoreDeleteW`, `DriverStoreUpdateDevicesW`, `DriverPackageOpenW/EnumFilesW/GetVersionInfoW/GetPropertyW`… | Toàn bộ vòng đời driver package trong Windows DriverStore |
| `CfgMgr32.dll` (6) | `CM_Get_Device_ID_List(_Size)`, `CM_Get_DevNode_Status/Property`, `CM_Get_Class_Property`, `CM_Locate_DevNode` | Tìm devnode theo Hardware ID, kiểm tra trạng thái, lấy Device Instance ID |
| `UsbDk` (string) | — | Nhánh backend thay thế (mặc định cho CPU AMD theo release notes) |

### 4.5. Tầng process/native load
- `kernel32.dll`: `LoadLibrary(A/W)`, `GetProcAddress`, `FreeLibrary`, `GetModuleHandle` → **nạp động libusb DLL lúc runtime** (không có ModuleRef tĩnh cho libusb ⇒ xác nhận).
- `kernel32.dll`: `CreateProcess`, `CreatePipe`, `ReadFile`, `CloseHandle` → chạy tiến trình con và đọc stdout (helper/installer).
- String heap chứa `UnmanagedFunctionPointerAttribute` + `GetDelegateForFunctionPointer` → pattern chuẩn: **LoadLibrary → GetProcAddress → marshal function pointer thành delegate C#** để gọi libusb từ .NET.
- `ntdll.dll`: `NtQueryVirtualMemory` (kiểm tra memory như anti-debug/protection).
- `ws2_32.dll`: `socket/send/recv/htons/htonl/ntohl/closesocket` → tự triển khai kết nối usbmux/SSH tunnel.

### 4.6. GUI/Theme
- `user32.dll`, `uxtheme.dll` (buffered paint/animation), `gdi32 SetMapMode` — UI WinForms + custom render (Button/TreeView renderer).

---

## 5. Cơ chế hoạt động trên Windows (chi tiết)

### 5.1. Quy trình "Fix Driver" — tim của phiên bản Windows

Đây là khác biệt cốt lõi so với Linux/macOS. Trình tự suy ra từ driver pack nhúng + API:

1. **Giải nén driver pack nhúng** (trong `.text` khoảng `0x12D0000`–`0x1B70000`): cấu trúc thư mục kiểu libwdi:
   ```
   libusbK/amd64/  libusb0.sys, libusb0.dll, libusbK.sys, libusbK.dll,
                   libusbK_x86.dll, WdfCoInstaller01011.dll, winusbcoinstaller2.dll
   libusbK/x86/    (bản 32-bit)
   libusbK/winra1n_mobile_device.inf  winra1n_mobile_device.cat
   apple/x64/      usbaapl64.sys, usbaapl64.inf, USBAAPL64.CAT, usbaaplrc.dll
   apple/x86/      usbaapl.sys, usbaapl.inf, usbaapl.PNF, usbaaplrc.dll
   ```
   - URL `http://libwdi.akeo.ie` / `libwdi-cps.akeo.ie` (Certificate Provider Service) xuất hiện nguyên văn → dùng **libwdi** (Windows Driver Installer library của Pete Batard) hoặc bản port của nó, với INF đổi tên riêng `winra1n_mobile_device`.
2. **Tìm devnode Apple** qua `CM_Get_Device_ID_List` / `SetupDiGetClassDevs` (USB, VID `05AC`) và đọc trạng thái + driver hiện tại.
3. **Gỡ/ghi đè driver**: `DiUninstallDriver` hoặc import driver mới vào DriverStore (`DriverStoreImportW` → `DriverStorePublishW`) rồi `DiInstallDriver` + `SetupDiSetDeviceInstallParams` để **ép** Windows bind `libusbK`/`libusb0` cho interface DFU (không phải usbaapl64).
4. **Verify chữ ký** bằng `SetupVerifyInfFile` trước khi cài (INF tự ký kèm `.cat`).
5. Sau jailbreak, **restore driver Apple** từ `apple/x64/usbaapl64.sys` để iTunes/AMDevice hoạt động lại bình thường (đây là lý do nhúng cả hai bộ driver).
6. Với CPU **AMD**: chọn backend **USBDK** thay vì libusbK (UsbDk là filter driver cấp phát raw USB mà không cần đổi driver device — ổn định hơn trên một số chipset AMD). App kiểm tra/khuyến nghị user cài UsbDk.

> Vì sao cần đổi driver: exploit checkm8 phải gửi USB control transfer tùy ý tới cổng DFU. Driver Apple chỉ mở giao diện chuẩn (usbmux/MTP). libusbK/libusb0/UsbDk mới cho phép app "nói" raw USB từ user-mode.

### 5.2. Nạp libusb động (LoadLibrary pattern)

Vì app là .NET, không thể link libusb tĩnh:
1. Extract `libusbK.dll`/`libusb0.dll` (user-mode API libusb-1.0) ra thư mục tạm.
2. `LoadLibrary` → `GetProcAddress` cho từng hàm (`libusb_init`, `libusb_open_device_with_vid_pid`, `libusb_control_transfer`, `libusb_bulk_transfer`, `libusb_reset_device`, `libusb_close`…).
3. `Marshal.GetDelegateForFunctionPointer` → delegate C# với `UnmanagedFunctionPointerAttribute` (đã xác nhận có trong metadata).
4. Toàn bộ logic exploit checkm8 (hằng số USB, timing, state machine) được port sang C# và gọi qua delegate này. Tên hàm được sinh từ string mã hóa trong resource nên không thấy plaintext.

### 5.3. Nhận diện thiết bị theo từng chế độ

| Chế độ | Cơ chế nhận diện |
|---|---|
| Normal (iOS chạy) | `AMDeviceNotificationSubscribe` + `AMDeviceCopyValue` (đọc `ProductType`, `BuildVersion`, `UniqueDeviceID`…) |
| Recovery | `AMRecoveryModeDevice*` qua cùng notification; `AMDeviceEnterRecovery` để tự đưa máy từ Normal/Recovery |
| DFU | Không có trong MobileDevice API → **quét USB qua libusb** theo VID/PID (`05AC:1227` DFU, `05AC:1281` iBoot/Recovery…) |
| Sau pongoOS | USB device mới do pongoOS expose ("PongoOS USB Device" — string trong payload) |

### 5.4. Luồng checkm8 → pongoOS → jailbreak (trên Windows)

```
[1] User bấm Fix Driver
    → extract driver pack → ép bind libusbK (hoặc UsbDk) cho cổng USB của máy

[2] Đưa thiết bị vào DFU
    - Từ Normal/Recovery: AMDeviceEnterRecovery + tổ hợp phím hướng dẫn UI
    - Hoặc user tự bấm tổ hợp phím (UI có hướng dẫn + đếm thời gian)

[3] checkm8 exploit (C# port, gọi libusb qua delegate)
    - libusb enumerate DFU (VID 05AC), open
    - USB control transfers: lợi dụng lỗi use-after-free USB re-enumeration
    - "USB BUG: 0x..." (hash hex của thông điệp debug) — string trong payload
    - Khởi động shellcode → DFU device giờ chạy code

[4] Upload pongoOS
    - Gửi pongoOS image qua bulk/control endpoint (usbloader protocol)
    - pongoOS 2.6.2 (2 bản nhúng: build 35c54683 = checkra1n gốc, ae7d6d69 = fork plooshi)
    - Device re-enumerate thành "PongoOS USB Device"

[5] Nạp pongoOS modules (File nhỏ arm64 Mach-O nhúng sẵn)
    - shell, ramdisk, sep (SEPROM exploit/helpers), usbloader
    - checkra1n-kpf (Kernel PatchFinder) 0.1337.1  hoặc 0.12.4-beta (palera1n)

[6] Boot ramdisk
    - Upload DMG ramdisk (UDIF/koly, 64MB uncompressed / 4.9MB nén — bản checkra1n;
       8MB — palera1n rootful/rootless)
    - pongoOS command "ramdisk" + "bootux"
    - KPF vá kernel trong lúc boot:
        AMFI, Trustcache, launch constraints, dyld patch,
        APFS mount/rename (cho fakefs), DiskImages, sandbox…
        ("KPF: Patched dyld check", "KPF: Found ramdisk, appending kernelinfo/paleinfo")

[7] Khởi động iOS với kernel đã patch (jailbreak semi-tethered)
    - Trên device: loader/bootstrap giải nén (bootstrap.tar: Sileo, Zebra,
      ellekit, dropbear SSH, repo lists: repo.palera.in, ellekit.space, getzbra.com…)

[8] Restore driver Apple (usbaapl64) để iTunes/amobile device hoạt động lại
```

### 5.5. Hai nhánh engine

| | checkra1n | palera1n |
|---|---|---|
| KPF | 0.1337.1 (và 0.12.4-beta) | 0.12.4-beta (fork plooshi) |
| pongoOS | 2.6.2 `35c54683` | 2.6.2 `ae7d6d69` |
| Loader | loader trong ramdisk (checkra1n.app) | `fakedyld`, `jbloader-early`, `bakera1nd`, `sysstatuscheck`, `p1ctl` |
| Cơ chế root | Rootful (fakefs trên APFS) | Rootful (fakefs) + **Rootless** (`/var/jb`) — mới trong 2.1 |
| Payload | `payload.dylib` (DYLD_INSERT_LIBRARIES) | `payload.dylib` + `/cores/binpack` |
| Hook KPF khác | `checkra1n_flags` | `palera1n_flags`, append "paleinfo" vào ramdisk |
| SSH | — | dropbear (host key generate on device, LaunchDaemons plist) |

### 5.6. Kênh phụ trợ trên Windows

- **usbmux tunnel:** `USBMuxConnectByPort` + tự viết socket → mở port AFC/SSH (2222 với dropbear) từ Windows.
- **AFC:** đọc/ghi file device (ví dụ push IPA, đọc thông tin máy, backup/restore file).
- **AMDeviceInstallApplication + Transfer/Archive/Lookup:** sideload IPA (khả năng tích hợp cài app/loader/tweak IPA trực tiếp từ Windows).
- **AirTrafficHost:** kênh kiểu iTunes (không cốt lõi cho jailbreak).
- **CreateProcess + pipe:** chạy tool con (có thể để cài driver như `pnputil`/installer riêng, hoặc chạy các helper one-shot).
- **License/ads:** `HttpClient`/`WebClient` POST `activation.php?code=&hwid=&hash=`; HWID = hash MAC (`NetworkInterface.GetPhysicalAddress`) + SHA256/MD5; lưu registry `LocalMachine`; các trạng thái `BadHwid/Banned/Expired/DateExpired/RunningTimeOver`.

---

## 6. Kiểm kê payload nhúng (Windows-side)

| Nhóm | Offset (xấp xỉ) | Nội dung |
|---|---|---|
| checkm8/KPF pack | ~0x40.000–0x52.000 | nhóm module arm64 Mach-O nhỏ + string KPF 0.1337.1; dSYM headers |
| Ramdisk DMG #1 | ~0x521.000–0x570.E00 | UDIF/koly, data-fork 5.138.986 B → image 64 MiB (`sectorCount 131072`) |
| PongoOS/modules checkra1n | ~0x570.E00–0x632.000 | Mach-O arm64 exec/dylib (0x5D0EC0, 0x5DEEC0, 0x5ECEC0, 0x5FAEC0, 0x617EC0, 0x624EC0), pongoOS 2.6.2, checkra1n-overlay |
| palera1n pack | ~0x6B0.000–0xA50.000 | KPF 0.12.4 beta, pongoOS plooshi, loaders (fakedyld/bakera1nd/jbloader-early/sysstatuscheck/p1ctl), payload.dylib, bootstrap scripts |
| Ramdisk DMG #2/#3 | koly @0x971.768, @0xCF.73C3 | 8 MiB image (2.77 MB & 2.79 MB nén) — rootful/rootless |
| Bootstrap binpack | ~0xD50.000–0xD9xxxx | dropbear, LaunchDaemons, APFS strings, `/var/jb` helpers |
| Ramdisk DMG #4 | koly @0x12AD.21D | bản sao 64 MiB ramdisk (dùng chung cho nhánh 2) |
| Driver pack (libwdi) | ~0x12D0.000–0x1B70.000 | libusbK/libusb0 x64+x86, WdfCoInstaller, winusbcoinstaller, apple usbaapl x64/x86, `winra1n_mobile_device.inf/.cat` |
| Apple Mobile Device Support | ~0x1F00.000–0x2500.000 | `CoreFoundation.dll`, `MobileDevice.dll`, `CFNetwork.dll`, `AirTrafficHost.dll`, `SQLite3.dll`, `ASL.dll`, `objc.dll`, `libdispatch.dll`, `libicuin/ucu/icudt62`, `libxml2`, `zlib1`, `pthreadVC2`, `vcruntime140d`, `ucrtbased`, `lz4`, `libcache` |

Ghi chú: tất cả nằm plaintext trong `.text`/`.LNz` → có thể `dd`/carve ra trực tiếp để nghiên cứu sâu hơn (ví dụ extract DMG rồi mount bằng 7-Zip).

---

## 7. Vòng đời một lần jailbreak (từ góc nhìn Windows)

1. `WinRa1n.exe` chạy với quyền admin (user tự bật), check license + tải ads/guide (offline vẫn chạy được).
2. UI hiện thông tin máy (qua AMDevice) khi cắm cáp, user Trust máy.
3. **Fix Driver** → thay driver USB như mục 5.1 (chỉ cần làm 1 lần; có nút restore).
4. User chọn mode: `CheckM8 / Checkra1n 0.12.4 / Checkra1n 0.1337.1 / Palera1n` (+ rootful/rootless, ramdisk/overlay tùy chỉnh).
5. App đưa máy về Recovery/DFU (hướng dẫn tổ hợp phím + `AMDeviceEnterRecovery` + check DFU bằng libusb).
6. Chạy checkm8 + upload pongoOS + modules + ramdisk (mục 5.4) — toàn bộ nằm trong tiến trình C# gọi libusb.
7. Device boot lên với kernel patched; bootstrap/loader chạy trên máy.
8. App restore driver Apple; user mở loader trên máy → cài Sileo/Zebra; kết nối SSH dropbear qua usbmux nếu cần.

---

## 8. So sánh nhanh với hệ sinh thái Linux/macOS

| Thành phần | Linux/macOS | WinRa1n trên Windows (tương đương) |
|---|---|---|
| Raw USB | libusb + driver chuẩn | libusbK/libusb0/UsbDk sau khi **thay driver** (libwdi) |
| usbmuxd | daemon hệ thống | `MobileDevice.dll` + `USBMuxConnectByPort` |
| checkm8 engine | checkra1n/ipwndfu binary | Port C# gọi libusb động |
| pongoOS modules | file trên đĩa | Nhúng trong `.text`, upload qua USB |
| Ramdisk | tải/đóng gói lúc chạy | Nhúng sẵn DMG (offline) |
| Bootstrap | script palera1n | Nhúng bootstrap.tar + binpack |

---

## 9. Nếu muốn tự xây dựng tool tương tự trên Windows

### 9.1. Tái sử dụng mã nguồn mở (khuyến nghị mạnh)
- **openra1n** — checkm8 + pongoOS thuần Windows (đúng kiến trúc này), có sẵn code C cho exploit + libusb.
- **libwdi** (Pete Batard, BSD) — thư viện cài driver libusbK/libusb0, INF/CAT mẫu — chính là thứ WinRa1n dùng.
- **libusb** (LGPL) — bind raw USB; backend WinUSB/libusbK/UsbDk.
- **palera1n / checkra1n** (GPL) — payload device-side (KPF, loaders, bootstrap). Lấy từ repo chính thức.
- **libimobiledevice / pymobiledevice3** — thay thế MobileDevice.dll nếu muốn né phụ thuộc Apple (tự viết usbmux client + AFC).
- **Palera1nWin** (GitHub) — dự án mở tham khảo cho kiến trúc "app Windows đóng gói palera1n".

### 9.2. Kiến trúc đề xuất
```
WinForms/WPF GUI (C#)
 ├─ DriverHelper.dll  : libwdi wrapper (install/uninstall libusbK, restore usbaapl)
 ├─ UsbEngine (C/C++ native hoặc C#+P/Invoke libusb):
 │    ├─ DFU detect (VID 05AC), checkm8, pongoOS upload
 │    └─ USBDK fallback cho AMD
 ├─ DeviceComm: MobileDevice.dll P/Invoke (AMDevice/AFC) hoặc usbmux tự viết
 └─ PayloadPack: nhúng (hoặc tải) pongoOS + KPF + ramdisk + bootstrap
```

### 9.3. Lưu ý pháp lý/kỹ thuật
- **checkra1n/palera1n là GPLv3**: nếu phân phối tool kèm binary của họ phải **phát hành source** (WinRa1n có vẻ lách bằng cách nhúng binary không kèm source — rủi ro pháp lý).
- **Nhúng DLL của Apple** (MobileDevice.dll, CoreFoundation.dll…) vi phạm điều khoản Apple → nên yêu cầu user cài iTunes/Apple Mobile Device Support thay vì nhúng (nhẹ hơn ~10 MB và sạch pháp lý hơn).
- Thay driver USB có thể khiến iTunes ngừng nhận máy nếu không restore đúng — luôn có nút "Restore Driver".
- Jailbreak chỉ hợp pháp cho **máy bạn sở hữu** ở nhiều nơi, nhưng bypass iCloud/Activation Lock là bất hợp pháp tại nhiều quốc gia — tránh đưa các tính năng đó vào tool.
- Đừng tái tạo nguyên license server/ads của iKeyTools (vừa thừa vừa dính pháp lý).

---

## 10. IOC / dấu vết nhận dạng (hữu ích khi phân tích động)

**File/hash**
- `WinRa1n.exe` — sha256 `195eb3d5707ec45d372edfd00017086a977a04dbc6aad0d056078d543a2a5255`
- Driver riêng: `winra1n_mobile_device.inf`, `winra1n_mobile_device.cat`
- Thư mục làm việc kiểu libwdi: `libusbK\amd64`, `libusbK\x86`, `apple\x64`

**Registry/System** (dự đoán khi phân tích động)
- DriverStore entries cho `libusbK`/`libusb0.sys`, `usbaapl64.sys`
- Key license `HKLM\...` (LocalMachine) do iKeyUtils ghi

**Network**
- `*/activation.php` (POST `code`, `hwid`, `hash`), `*/deactivation.php`
- Giải encrypted response (JSON — dùng `JavaScriptSerializer`)
- Ads/guide URL qua `HttpClient`

**Tiến trình con:** theo dõi `CreateProcess` trong Procmon (lưu ý gọi `pnputil`/installer hoặc helper payload).

---

## 11. Phụ lục: các điểm cần phân tích động để hiểu trọn vẹn

Do IL bị obfuscate nặng, các chi tiết sau nên xác nhận bằng phân tích động (VM + Procmon/USB capture):
1. File/driver thực sự extract ra đĩa và thư mục làm việc (`GetManifestResourceStream` → decrypt → extract).
2. Chuỗi thao tác USB chính xác của checkm8 port C# (Wireshark USBPcap).
3. Nội dung encrypted resources (6 blob hex-named) — chứa string key/URL/license logic.
4. Tên tiến trình con chạy qua `CreateProcess`.
5. Endpoint license server thật (bị mã hóa trong resource).
