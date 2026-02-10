# ================= ADMIN CHECK =================
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Ejecutar PowerShell como Administrador" -ForegroundColor Red
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

        DLLVIEW – made by rel
"@

Write-Host $banner -ForegroundColor Cyan

# ================= DLLs CARGADAS =================
Write-Host "`n[*] Escaneando DLLs cargadas..." -ForegroundColor Yellow

$dllList = @()

Get-Process | ForEach-Object {
    try {
        $_.Modules | ForEach-Object {
            $dllList += $_.FileName
        }
    } catch {}
}

$dllList = $dllList | Sort-Object -Unique

Write-Host "[+] DLLs cargadas encontradas: $($dllList.Count)" -ForegroundColor Green

# ================= DLLs SOSPECHOSAS =================
$suspiciousWords = @(
    "inject","hook","cheat","hack","aim","esp",
    "overlay","dxgi","d3d","opengl","present"
)

Write-Host "`n[*] Analizando comportamiento..." -ForegroundColor Yellow

$results = foreach ($dll in $dllList) {

    $score = 0
    $matches = @()

    foreach ($word in $suspiciousWords) {
        if ($dll.ToLower().Contains($word)) {
            $score++
            $matches += $word
        }
    }

    [PSCustomObject]@{
        DLL        = [IO.Path]::GetFileName($dll)
        Path       = $dll
        Score      = $score
        Keywords   = if ($matches) { $matches -join "," } else { "-" }
        Suspicious = ($score -ge 2)
    }
}

# ================= RESULTADOS =================
Write-Host "`n========== RESULTADOS ==========" -ForegroundColor Cyan

$results | Format-Table DLL, Score, Keywords, Suspicious -AutoSize

Write-Host "`n========== DLLs MARCADAS ==========" -ForegroundColor Red

$results | Where-Object { $_.Suspicious } |
Format-Table DLL, Keywords, Path -AutoSize

Write-Host "`n[✓] Escaneo finalizado" -ForegroundColor Green

Write-Host "`nPresiona ENTER para salir..."
Read-Host