# ═════════════════════════════════════════════════════════════════════════════
# install.ps1 — Instalador Windows (x64 & ARM64) de ssh-usb-unlock
# ═════════════════════════════════════════════════════════════════════════════
# Uso con curl.exe (nativo en Windows 10/11):
#   curl.exe -fsSL https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install.ps1 | powershell -NoProfile -ExecutionPolicy Bypass -Command -
#
# Uso alternativo con PowerShell:
#   irm https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install.ps1 | iex
#
# Variables opcionales:
#   $env:ZT_SSH_REPO     Repositorio GitHub (default: Kerwit/zero-trust-ssh)
#   $env:ZT_SSH_VERSION  Tag a instalar, p. ej. v0.1.0 (default: latest)
#   $env:ZT_SSH_DIR      Directorio SSH destino (default: $env:USERPROFILE\.ssh)
#   $env:ZT_SSH_NO_PATH  Si es "1", no modifica el User PATH de Windows
#   $env:GITHUB_TOKEN    Token opcional para descargas autenticadas
# ═════════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
} catch {
    # PowerShell Core ya usa TLS 1.2/1.3 por defecto
}

$Repo = if ($env:ZT_SSH_REPO) { $env:ZT_SSH_REPO } else { "Kerwit/zero-trust-ssh" }
$Version = if ($env:ZT_SSH_VERSION) { $env:ZT_SSH_VERSION } else { "latest" }
$NoPath = ($env:ZT_SSH_NO_PATH -eq "1")
$BinaryName = "ssh-usb-unlock.exe"

function Get-TargetTriple {
    $arch = $null
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        $arch = $env:PROCESSOR_ARCHITECTURE
    }

    switch -Regex ($arch) {
        "^(X64|AMD64)$" { return "x86_64-pc-windows-msvc" }
        "^(Arm64|ARM64)$" { return "aarch64-pc-windows-msvc" }
        default { throw "Arquitectura Windows no soportada: $arch" }
    }
}

function Invoke-Download {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $headers = @{}
    if ($env:GITHUB_TOKEN) {
        $headers["Authorization"] = "Bearer $($env:GITHUB_TOKEN)"
    }
    Invoke-WebRequest -Uri $Url -OutFile $Destination -Headers $headers -UseBasicParsing
}

$Target = Get-TargetTriple
$Archive = "ssh-usb-unlock-$Target.zip"
$BaseUrl = if ($Version -eq "latest") {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("zt-ssh-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $ArchivePath = Join-Path $TempDir $Archive
    $SumsPath = Join-Path $TempDir "SHA256SUMS.txt"

    Write-Host "[INFO] Detectada plataforma: $Target"
    Write-Host "[INFO] Descargando $Archive desde $Repo ($Version)..."
    Invoke-Download -Url "$BaseUrl/$Archive" -Destination $ArchivePath

    try {
        Invoke-Download -Url "$BaseUrl/SHA256SUMS.txt" -Destination $SumsPath
        $expectedLine = Get-Content $SumsPath | Where-Object { $_ -match "\s+\*?$([Regex]::Escape($Archive))$" } | Select-Object -First 1
        if ($expectedLine) {
            $expectedHash = ($expectedLine.Trim() -split "\s+")[0].ToLowerInvariant()
            $actualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($expectedHash -ne $actualHash) {
                throw "Fallo de verificación SHA-256 para $Archive (esperado: $expectedHash, obtenido: $actualHash)"
            }
            Write-Host "[OK]   Integridad SHA-256 verificada."
        }
    } catch {
        if ($_.Exception.Message -like "Fallo de verificación SHA-256*") {
            throw
        }
        Write-Warning "No se pudo descargar/verificar SHA256SUMS.txt; continuando."
    }

    Expand-Archive -Path $ArchivePath -DestinationPath $TempDir -Force
    $ExtractedBin = Join-Path $TempDir $BinaryName
    if (-not (Test-Path $ExtractedBin)) {
        throw "El archivo descargado no contiene '$BinaryName'."
    }

    Write-Host "[INFO] Ejecutando auto-instalación en el directorio SSH..."
    if ($NoPath) {
        & $ExtractedBin install --no-path
    } else {
        & $ExtractedBin install
    }
    if ($LASTEXITCODE -ne 0) {
        throw "La auto-instalación falló con código de salida $LASTEXITCODE."
    }
} finally {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
