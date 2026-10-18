# extract_driver_kit.ps1 - Rebuild .\driver_kit from the driver pack embedded in
# WinRa1n2.1.exe (libusbK + winra1n_mobile_device.inf/.cat + exported signing cert).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\extract_driver_kit.ps1 [-Exe <WinRa1n2.1.exe>] [-Out <dir>]
#
# The kit is installed (as Administrator) by tools\fix_driver.cmd.
# Why: the INF binds libusbK to USB\VID_05AC&PID_1227 (DFU), PID_1338 and
# PID_4141 (PongoOS), so Windows auto-binds a raw-USB capable driver on every
# enumeration - no Zadig, survives reboots and USB port changes.
# Analysis of the source pack: WinRa1n2.1_analysis.md section 12.

param(
    [string]$Exe = "",
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (-not $Out) { $Out = Join-Path $PSScriptRoot "..\driver_kit" }
if (-not $Exe) {
    foreach ($cand in @(
        (Join-Path $PSScriptRoot "..\WinRa1n2.1.exe"),
        (Join-Path $PSScriptRoot "..\..\WinRa1n2.1.exe"))) {
        if (Test-Path -LiteralPath $cand) { $Exe = (Resolve-Path -LiteralPath $cand).Path; break }
    }
}
if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) {
    throw "WinRa1n2.1.exe not found. Pass -Exe <path>."
}

Write-Host "[extract_driver_kit] reading $Exe ..."
$bytes = [IO.File]::ReadAllBytes($Exe)
$text  = [Text.Encoding]::GetEncoding(28591).GetString($bytes)

# Locate embedded ZIP archives: scan for EOCD records (PK\x05\x06), derive the
# archive start from the central-directory offset, keep the one that contains
# the driver pack. Same carve logic as documented in WinRa1n2.1_analysis.md 12.1.
$eocdSig = [string]::Join('', @([char]0x50, [char]0x4B, [char]5, [char]6))
$pack = $null
$pos = 0
while (($pos = $text.IndexOf($eocdSig, $pos)) -ge 0) {
    if ($pos + 22 -le $bytes.Length) {
        $cdSize     = [BitConverter]::ToUInt32($bytes, $pos + 12)
        $cdOffset   = [BitConverter]::ToUInt32($bytes, $pos + 16)
        $commentLen = [BitConverter]::ToUInt16($bytes, $pos + 20)
        $zipLen   = [int64]$cdOffset + $cdSize + 22 + $commentLen
        $zipStart = $pos + 22 + $commentLen - $zipLen
        if ($zipStart -ge 0 -and ($zipStart + $zipLen) -le $bytes.Length) {
            if ([BitConverter]::ToString($bytes[$zipStart..($zipStart + 3)]) -eq "50-4B-03-04") {
                $tmp = Join-Path $env:TEMP ("winra1n_pack_" + $zipStart + ".zip")
                $slice = New-Object byte[] $zipLen
                [Array]::Copy($bytes, $zipStart, $slice, 0, $zipLen)
                [IO.File]::WriteAllBytes($tmp, $slice)
                try {
                    $zip = [IO.Compression.ZipFile]::OpenRead($tmp)
                    $isPack = ($zip.Entries | Where-Object { $_.FullName -eq "libusbK/winra1n_mobile_device.inf" }).Count -gt 0
                    $zip.Dispose()
                    if ($isPack) { $pack = @{ File = $tmp; Offset = $zipStart; Length = $zipLen }; break }
                } catch { }
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    }
    $pos++
}
if (-not $pack) { throw "Driver pack not found inside $Exe (untouched WinRa1n 2.1 required)" }

Write-Host ("[extract_driver_kit] driver pack @ {0} ({1} bytes)" -f $pack.Offset, $pack.Length)
if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Recurse -Force }
[IO.Compression.ZipFile]::ExtractToDirectory($pack.File, $Out)

$cat = Join-Path $Out "libusbK\winra1n_mobile_device.cat"
$sig = Get-AuthenticodeSignature -LiteralPath $cat
if (-not $sig.SignerCertificate) { throw "Could not read the signing certificate from $cat" }
$trust = Join-Path $Out "trust"
New-Item -ItemType Directory -Force -Path $trust | Out-Null
$cer = Join-Path $trust "winra1n_mobile_device.cer"
[IO.File]::WriteAllBytes($cer, $sig.SignerCertificate.Export("Cert"))
Write-Host ("[extract_driver_kit] cert: {0} -> {1}" -f $sig.SignerCertificate.Subject, $cer)
Write-Host "[extract_driver_kit] done. Next (as Administrator):  tools\fix_driver.cmd"
