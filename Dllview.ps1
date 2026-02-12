Perfecto, ahora sí quedó clarísimo 👍
Hacemos esto exactamente como pedís, sin tocar nada raro:

🧠 LÓGICA FINAL (la que querés)

👉 NO se revisan todos los DLL del sistema
👉 NO se escanean DLLs al azar

El flujo es:

Prefetch

Buscar RUNDLL32*.pf y REGSVR32*.pf

Obtener LastRunTime

Eso marca intento de carga/inyección

NTFS Journal

Buscar DLLs modificadas DESPUÉS del LastRun de regsvr32/rundll32

javaw.exe

Ver qué DLLs están cargadas

Correlacionar solo con:

DLLs tocadas en Journal

intento previo (Prefetch)

Recién ahí marcar sospechoso

Todo pasivo, profesional, en inglés, con banner, y sin TXT externo.

✅ SCRIPT FINAL (FUNCIONAL Y LIMPIO)

Guardalo como Dllview.ps1

# ================= ADMIN CHECK =================
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Please run as Administrator." -ForegroundColor Red
    Read-Host
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

# ================= PREFETCH ANALYSIS =================
Write-Host "[*] Scanning Prefetch for DLL load attempts..." -ForegroundColor Yellow

$pfPath = "C:\Windows\Prefetch"
$pfHits = Get-ChildItem $pfPath -ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -match "RUNDLL32|REGSVR32"
}

if (-not $pfHits) {
    Write-Host "[+] No DLL load attempts detected (Prefetch)." -ForegroundColor Green
    Read-Host
    exit
}

$lastInjectionTime = ($pfHits | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
Write-Host "[+] DLL load attempt detected at: $lastInjectionTime" -ForegroundColor Green

# ================= NTFS JOURNAL =================
Write-Host "`n[*] Scanning NTFS Journal after injection attempt..." -ForegroundColor Yellow

$journalRaw = fsutil usn readjournal C: csv 2>$null
$modifiedDlls = @()

if ($journalRaw) {
    $entries = $journalRaw | Select-String ".dll" | ConvertFrom-Csv

    foreach ($e in $entries) {
        try { $time = [DateTime]::Parse($e.TimeStamp) } catch { continue }
        if ($time -lt $lastInjectionTime) { continue }

        if ($e.Reason -match "RENAME|OVERWRITE|DATA_EXTEND|DATA_TRUNCATION") {
            $modifiedDlls += $e.FileName.ToLower()
        }
    }
}

$modifiedDlls = $modifiedDlls | Sort-Object -Unique
Write-Host "[+] Modified DLLs after attempt: $($modifiedDlls.Count)" -ForegroundColor Green

# ================= JAVA DLL CORRELATION =================
Write-Host "`n[*] Scanning javaw.exe loaded DLLs..." -ForegroundColor Yellow

$javaDlls = @()
Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object {
    try { $_.Modules | ForEach-Object { $javaDlls += $_.FileName } } catch {}
}

$javaDlls = $javaDlls | Sort-Object -Unique

$results = foreach ($dll in $javaDlls) {

    $name = [IO.Path]::GetFileName($dll).ToLower()

    if ($modifiedDlls -contains $name) {
        [PSCustomObject]@{
            DLL        = [IO.Path]::GetFileName($dll)
            Suspicious = $true
            Reason     = "Loaded in javaw.exe after REGSVR32/RUNDLL32 execution"
            Path       = $dll
        }
    }
}

# ================= OUTPUT =================
Write-Host "`n========== DLLVIEW RESULTS ==========" -ForegroundColor Cyan

if ($results) {
    $results | Format-Table DLL, Reason, Path -AutoSize
} else {
    Write-Host "[+] No suspicious DLLs correlated." -ForegroundColor Green
}

Write-Host "`n[+] DLLVIEW scan completed."
Read-Host "Press ENTER to exit"