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
Start-Sleep 1

# ==============================
# Logon Time
# ==============================
$logon = Get-CimInstance Win32_LogonSession |
    Sort-Object StartTime |
    Select-Object -Last 1

$LogonTime = [Management.ManagementDateTimeConverter]::ToDateTime($logon.StartTime)
Write-Host "[+] Logon Time: $LogonTime" -ForegroundColor Green

# ==============================
# Loaded DLLs Scan
# ==============================
Write-Host "`n[+] Scanning loaded DLLs..." -ForegroundColor Yellow

$dllResults = @()

Get-Process | ForEach-Object {
    try {
        $_.Modules | ForEach-Object {
            if ($_.FileName -and (Test-Path $_.FileName)) {
                $sig = Get-AuthenticodeSignature $_.FileName
                $dllResults += [PSCustomObject]@{
                    DLLName   = $_.ModuleName
                    Path      = $_.FileName
                    Signed    = $sig.Status
                    Publisher = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unsigned" }
                }
            }
        }
    } catch {}
}

$dllResults = $dllResults | Sort-Object Path -Unique

# ==============================
# Prefetch Scan (regsvr32 / rundll32)
# ==============================
Write-Host "`n[+] Scanning Prefetch files..." -ForegroundColor Yellow

$pfPath = "C:\Windows\Prefetch"
$targets = @("REGSVR32", "RUNDLL32")
$pfResults = @()

Get-ChildItem $pfPath -Filter "*.pf" -ErrorAction SilentlyContinue | Where-Object {
    $targets | Where-Object { $_ -and $_ -in $_.Name }
} | ForEach-Object {

    $hash = Get-FileHash $_.FullName -Algorithm SHA256

    $pfResults += [PSCustomObject]@{
        FileName   = $_.Name
        Path       = $_.FullName
        LastRun    = $_.LastWriteTime
        SizeKB     = [math]::Round($_.Length / 1KB, 2)
        SHA256     = $hash.Hash
        AfterLogon = ($_.LastWriteTime -gt $LogonTime)
    }
}

# ==============================
# Suspicious Analysis
# ==============================
$suspiciousDlls = $dllResults | Where-Object {
    $_.Signed -ne "Valid" -or
    $_.Publisher -notmatch "Microsoft"
}

$suspiciousPF = $pfResults | Where-Object {
    $_.AfterLogon -eq $true -or $_.SizeKB -gt 500
}

# ==============================
# RESULTS
# ==============================
Write-Host "`n================ DLL RESULTS ================" -ForegroundColor Cyan
$dllResults | Format-Table -AutoSize

Write-Host "`n[!] Suspicious / Non-signed DLLs:" -ForegroundColor Red
$suspiciousDlls | Format-Table -AutoSize

Write-Host "`n================ PREFETCH RESULTS ================" -ForegroundColor Cyan
$pfResults | Format-Table -AutoSize

Write-Host "`n[!] Suspicious regsvr32 / rundll32 executions:" -ForegroundColor Red
$suspiciousPF | Format-Table -AutoSize

Write-Host "`n[+] DLLVIEW scan completed." -ForegroundColor Green