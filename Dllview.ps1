# ================= ADMIN CHECK =================
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Ejecutar como Administrador." -ForegroundColor Red
    exit
}

Clear-Host

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

Write-Host "[*] Scanning USN JOURNAL..." -ForegroundColor Yellow

# ================= READ JOURNAL =================
$journalRaw = fsutil usn readjournal $drive csv 2>$null
$journalEvents = @()

if ($journalRaw) {

    $entries = $journalRaw | ConvertFrom-Csv

    $journalEvents = foreach ($e in $entries) {

        if (-not $e.FileName) { continue }
        if (-not $e.FileName.ToLower().EndsWith(".dll")) { continue }

        try { $time = [DateTime]::Parse($e.TimeStamp) } catch { continue }
        if ($time -lt $since) { continue }

        if ($e.Reason -match "RENAME|OVERWRITE|DATA_EXTEND|DATA_TRUNCATION|FILE_DELETE") {

            [PSCustomObject]@{
                TimeStamp = $time
                DLL       = $e.FileName
                Reason    = $e.Reason
                Path      = if ($e.FullPath) { $e.FullPath } else { "N/A" }
            }
        }
    }

    if ($journalEvents.Count -gt 0) {
        $journalEvents |
        Sort-Object TimeStamp |
        ForEach-Object {
@"
====================================
Time: $($_.TimeStamp)
DLL: $($_.DLL)
Change: $($_.Reason)
Path: $($_.Path)
====================================
"@
        } | Out-File $journalOut -Encoding UTF8
    }
}

# ================= DLL BEHAVIOR SCAN =================
Write-Host "`n[*] Scanning DLLS." -ForegroundColor Yellow

$suspiciousKeywords = @(
    "inject","hook","detour","patch","bypass",
    "aim","esp","wall","cheat","hack",
    "overlay","present","swapchain","dxgi",
    "directx","d3d","opengl","gl",
    "mouse","keyboard","input"
)

$dlls = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | ForEach-Object {
    try { (Get-Process -Id $_.ProcessId -ErrorAction Stop).Modules } catch {}
} | Sort-Object FileName -Unique

function Get-DllExports {
    param ($Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
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

    # ===== FIX DEFINITIVO DEL BUG =====
    $matched = @(
        foreach ($fn in $exports) {
            foreach ($kw in $suspiciousKeywords) {
                if ($fn.ToLower().Contains($kw)) { $kw }
            }
        }
    ) | Where-Object { $_ } | Select-Object -Unique
    # =================================

    $score = 0
    $reasons = @()

    if ($exportCount -gt 120) { $score++ }
    if ($exportCount -gt 0 -and $exportCount -lt 5) { $score++ }
    if ($matched.Count -gt 0) { $score++ }
    if ($journalEvents.Count -gt 0) { $score++ }

    [PSCustomObject]@{
        DLL        = [IO.Path]::GetFileName($dll.FileName)
        Exports    = $exportCount
        Keywords   = if ($matched) { $matched -join "," } else { "-" }
        Score      = $score
        Suspicious = ($score -ge 2)
        Path       = $dll.FileName
    }
}

Write-Host "`n[+] DLLVIEW full scan finished." -ForegroundColor Green
