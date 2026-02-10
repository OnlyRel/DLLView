# =====================================================
# DLLVIEW
# DLL Viewer - made by rel
# Optimized Fast Scan
# =====================================================

Clear-Host

$banner = @"
██████╗ ██╗     ██╗     ██╗   ██╗██╗███████╗██╗    ██╗
██╔══██╗██║     ██║     ██║   ██║██║██╔════╝██║    ██║
██║  ██║██║     ██║     ██║   ██║██║█████╗  ██║ █╗ ██║
██║  ██║██║     ██║     ██║   ██║██║██╔══╝  ██║███╗██║
██████╔╝███████╗███████╗╚██████╔╝██║███████╗╚███╔███╔╝
╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═╝╚══════╝ ╚══╝╚══╝

        DLL Viewer - made by rel
"@

Write-Host $banner -ForegroundColor Cyan

# ==============================
# Logon Time
# ==============================
$logonTime = (Get-CimInstance Win32_LogonSession |
    Sort-Object StartTime |
    Select-Object -Last 1 |
    ForEach-Object {
        [Management.ManagementDateTimeConverter]::ToDateTime($_.StartTime)
    })

Write-Host "[+] Logon Time: $logonTime" -ForegroundColor Green

# ==============================
# FAST DLL COLLECTION
# ==============================
Write-Host "[+] Collecting loaded DLL paths (fast)..." -ForegroundColor Yellow

$dllPaths = Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath } |
    ForEach-Object {
        try {
            (Get-Process -Id $_.ProcessId -ErrorAction Stop).Modules |
                Select-Object -ExpandProperty FileName
        } catch {}
    } |
    Sort-Object -Unique

Write-Host "[+] Unique DLLs found: $($dllPaths.Count)" -ForegroundColor Green

# ==============================
# FAST SIGNATURE CHECK
# ==============================
Write-Host "[+] Verifying digital signatures..." -ForegroundColor Yellow

$dllResults = foreach ($dll in $dllPaths) {
    if (Test-Path $dll) {
        $sig = Get-AuthenticodeSignature $dll
        [PSCustomObject]@{
            DLL       = Split-Path $dll -Leaf
            Path      = $dll
            Signed    = $sig.Status
            Publisher = if ($sig.SignerCertificate) {
                $sig.SignerCertificate.Subject
            } else { "Unsigned" }
        }
    }
}

# ==============================
# PREFETCH SCAN (FAST)
# ==============================
Write-Host "[+] Scanning Prefetch..." -ForegroundColor Yellow

$pfResults = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "REGSVR32|RUNDLL32" } |
    Select-Object Name, FullName,
        @{n="LastRun";e={$_.LastWriteTime}},
        @{n="SizeKB";e={[math]::Round($_.Length/1KB,2)}},
        @{n="AfterLogon";e={$_.LastWriteTime -gt $logonTime}}

# ==============================
# SUSPICIOUS ANALYSIS
# ==============================
$suspiciousDlls = $dllResults | Where-Object {
    $_.Signed -ne "Valid" -or
    $_.Publisher -notmatch "Microsoft"
}

$suspiciousPF = $pfResults | Where-Object {
    $_.AfterLogon -or $_.SizeKB -gt 500
}

# ==============================
# RESULTS
# ==============================
Write-Host "`n========= DLL RESULTS =========" -ForegroundColor Cyan
$suspiciousDlls | Sort-Object Path | Format-Table -AutoSize

Write-Host "`n========= PREFETCH RESULTS =========" -ForegroundColor Cyan
$suspiciousPF | Format-Table -AutoSize

Write-Host "`n[+] DLLVIEW scan finished (FAST MODE)." -ForegroundColor Green