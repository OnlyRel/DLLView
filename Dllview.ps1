# ================= GLOBAL SAFETY =================
$ErrorActionPreference = "Stop"
trap {
    Write-Host "`n[!] ERROR DETECTADO:" -ForegroundColor Red
    Write-Host $_
    Write-Host "`nPresiona ENTER para salir..."
    Read-Host
    break
}

# ================= ADMIN CHECK =================
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Ejecutar como Administrador." -ForegroundColor Red
    Read-Host
    exit
}

Clear-Host

# ================= BANNER =================
$banner = @"
██████╗ ██╗     ██╗     ██╗   ██╗██╗███████╗██╗    ██╗
██╔══██╗██║     ██║     ██║   ██║██║██╔════╝██║    ██║
██║  ██║██║     ██║     ██║   ██║██║█████╗  ██║ █╗ ██║
██║  ██║██║     ██║     ██║   ██║██║██╔══╝  ██║███╗██║
██████╔╝███████╗███████╗╚██████╔╝██║███████╗╚███╔███╔╝
╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═╝╚══════╝ ╚══╝╚══╝

        DLLVIEW – SSA
                made by rel
"@

Write-Host $banner -ForegroundColor Cyan
Start-Sleep 1

# ================= JOURNAL CONFIG =================
$drive      = "C:"
$daysBack   = 7
$since      = (Get-Date).AddDays(-$daysBack)
$journalOut = "$env:USERPROFILE\Desktop\DLLVIEW_Journal_Report.txt"

Write-Host "[*] Scanning USN Journal (optimized)..." -ForegroundColor Yellow

$journalEvents = @()

$journalRaw = fsutil usn readjournal $drive csv 2>$null
if ($journalRaw) {

    $entries = $journalRaw |
        Select-String ".dll" |
        ConvertFrom-Csv

    foreach ($e in $entries) {

        if (-not $e.FileName) { continue }
        if ($e.FileName.Length -lt 4) { continue }
        if (($e.FileName[-4..-1] -join "") -ne ".dll") { continue }

        try { $time = [DateTime]::Parse($e.TimeStamp) } catch { continue }
        if ($time -lt $since) { continue }

        if ($e.Reason -match "RENAME|OVERWRITE|DATA_EXTEND|DATA_TRUNCATION|FILE_DELETE") {
            $journalEvents += [PSCustomObject]@{
                TimeStamp = $time
                DLL       = $e.FileName
                Reason    = $e.Reason
                Path      = if ($e.FullPath) { $e.FullPath } else { "N/A" }
            }
        }
    }

    if ($journalEvents.Count -gt 0) {
        $journalEvents | Sort-Object TimeStamp | ForEach-Object {
@"
====================================
Time: $($_.TimeStamp)
DLL: $($_.DLL)
Change: $($_.Reason)
Path: $($_.Path)
====================================
"@
        } | Out-File $journalOut -Encoding UTF8

        Write-Host "[+] Journal report generado:" -ForegroundColor Green
        Write-Host "    $journalOut" -ForegroundColor Yellow
    } else {
        Write-Host "[*] No recent DLL edits in NTFS journal." -ForegroundColor Green
    }
} else {
    Write-Host "[!] Could not read USN Journal." -ForegroundColor Red
}

# ================= DLL BEHAVIOR SCAN =================
Write-Host "`n[*] Scanning loaded DLLs (optimized)..." -ForegroundColor Yellow

$suspiciousKeywords = @(
    "inject","hook","detour","patch","bypass",
    "aim","esp","wall","cheat","hack",
    "overlay","present","swapchain","dxgi",
    "directx","d3d","opengl","gl",
    "mouse","keyboard","input"
)

$dlls = Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath } |
    ForEach-Object {
        try { (Get-Process -Id $_.ProcessId).Modules } catch {}
    } |
    Group-Object FileName |
    ForEach-Object { $_.Group[0] }

function Get-DllExports {
    param ($Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)[0..500000]
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        $ascii -split "`0" |
        Where-Object {
            $_.Length -ge 5 -and
            $_.Length -le 64 -and
            $_ -match "^[a-zA-Z_][a-zA-Z0-9_@\-]+$"
        } | Select-Object -Unique
    } catch { @() }
}

$results = foreach ($dll in $dlls) {

    if (-not (Test-Path $dll.FileName)) { continue }

    $exports = Get-DllExports $dll.FileName
    $exportCount = $exports.Count

    $matched = foreach ($fn in $exports) {
        foreach ($kw in $suspiciousKeywords) {
            if ($fn -like "*$kw*") { $kw }
        }
    } | Select-Object -Unique

    $score = 0
    $reasons = @()

    if ($exportCount -gt 120) { $score++; $reasons += "High export count" }
    if ($exportCount -gt 0 -and $exportCount -lt 5) { $score++; $reasons += "Very low export count" }
    if ($matched.Count -gt 0) { $score++; $reasons += "Suspicious exports ($($matched -join ','))" }
    if ($journalEvents.Count -gt 0) { $score++; $reasons += "Recent DLL modification (Journal)" }

    [PSCustomObject]@{
        DLL        = [IO.Path]::GetFileName($dll.FileName)
        Exports    = $exportCount
        Keywords   = if ($matched) { $matched -join "," } else { "-" }
        Score      = $score
        Suspicious = ($score -ge 2)
        Reason     = if ($reasons) { $reasons -join " | " } else { "Normal behavior" }
        Path       = $dll.FileName
    }
}

# ================= OUTPUT =================
Write-Host "`n========== DLLVIEW RESULTS ==========" -ForegroundColor Cyan
$results | Format-Table DLL, Exports, Keywords, Score, Suspicious -AutoSize

Write-Host "`n========== FLAGGED DLLs ==========" -ForegroundColor Red
$results | Where-Object { $_.Suspicious } |
Format-Table DLL, Reason, Path -AutoSize

Write-Host "`n[+] DLLVIEW full scan finished." -ForegroundColor Green
Write-Host "Press enter to exit.." -ForegroundColor DarkGray
Read-Host