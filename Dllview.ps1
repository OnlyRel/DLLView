# ===============================
# DLLVIEW - made by rel
# ===============================

Clear-Host
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "        DLLVIEW - made by rel       " -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

$results = @()

# 1️⃣ Procesos + DLLs cargadas (incluye system32)
Write-Host "[*] Escaneando procesos y DLLs cargadas..."
Get-Process | ForEach-Object {
    try {
        $_.Modules | ForEach-Object {
            if ($_.FileName -match "System32") {
                $results += $_.FileName
            }
        }
    } catch {}
}

# 2️⃣ Prefetch
Write-Host "[*] Escaneando Prefetch..."
$prefetch = "C:\Windows\Prefetch"
if (Test-Path $prefetch) {
    Get-ChildItem $prefetch -Filter "*.pf" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $results += $_.Name
    }
}

# 3️⃣ Journal (básico, no pesado)
Write-Host "[*] Revisando cambios recientes (Journal simplificado)..."
Get-ChildItem C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue |
Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
ForEach-Object {
    $results += "$($_.Name) | Modificado: $($_.LastWriteTime)"
}

# 4️⃣ Output
$out = "$PSScriptRoot\Dllview_Report.txt"
$results | Sort-Object -Unique | Out-File -Encoding UTF8 $out

Write-Host ""
Write-Host "[✓] Escaneo terminado"
Write-Host "[✓] Reporte guardado en:" -NoNewline
Write-Host " $out" -ForegroundColor Green

# 🔒 FUERZA QUE NO SE CIERRE
Write-Host ""
Write-Host "Presiona ENTER para salir..."
Read-Host