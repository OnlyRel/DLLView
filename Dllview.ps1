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

# ================= CONFIG =================
$drive      = "C:"
$daysBack   = 7
$since      = (Get-Date).AddDays(-$daysBack)
$outputFile = "$env:USERPROFILE\Desktop\DLLVIEW_Journal_Report.txt"

Write-Host "[*] Leyendo NTFS USN Journal ($drive)..." -ForegroundColor Yellow

# ================= READ JOURNAL =================
$raw = fsutil usn readjournal $drive csv 2>$null
if (-not $raw) {
    Write-Host "[!] No se pudo leer el USN Journal." -ForegroundColor Red
    exit
}

$entries = $raw | ConvertFrom-Csv

Write-Host "[*] Analizando eventos de DLL (últimos $daysBack días)..." -ForegroundColor Yellow

# ================= ANALYSIS =================
$dllEvents = foreach ($e in $entries) {

    if (-not $e.FileName) { continue }
    if (-not $e.FileName.ToLower().EndsWith(".dll")) { continue }

    try {
        $time = [DateTime]::Parse($e.TimeStamp)
    } catch { continue }

    if ($time -lt $since) { continue }

    $reason = $e.Reason

    # cambios relevantes
    if ($reason -match "RENAME|OVERWRITE|DATA_EXTEND|DATA_TRUNCATION|FILE_DELETE") {

        $oldName = "-"
        if ($reason -match "RENAME_OLD_NAME") { $oldName = "Old name detected" }
        if ($reason -match "RENAME_NEW_NAME") { $oldName = "Renamed from previous DLL" }

        [PSCustomObject]@{
            TimeStamp    = $time
            CurrentName  = $e.FileName
            PreviousName = $oldName
            Reason       = $reason
            Path         = if ($e.FullPath) { $e.FullPath } else { "N/A" }
        }
    }
}

# ================= OUTPUT =================
if (-not $dllEvents -or $dllEvents.Count -eq 0) {
    Write-Host "[+] No se detectaron modificaciones de DLL en el Journal." -ForegroundColor Green
    exit
}

Write-Host "[*] Generando reporte TXT..." -ForegroundColor Yellow

$dllEvents |
Sort-Object TimeStamp |
ForEach-Object {
@"
========================================
Time: $($_.TimeStamp)
Current DLL: $($_.CurrentName)
Previous Name: $($_.PreviousName)
Change Type: $($_.Reason)
Path: $($_.Path)
========================================
"@
} | Out-File $outputFile -Encoding UTF8

Write-Host "`n[+] DLLVIEW Journal scan finalizado." -ForegroundColor Green
Write-Host "[+] Reporte generado en:" -ForegroundColor Cyan
Write-Host "    $outputFile" -ForegroundColor Yellow