#!/bin/sh
# ═════════════════════════════════════════════════════════════════════════════
# install.sh — Instalador multiplataforma (macOS & Linux) de ssh-usb-unlock
# ═════════════════════════════════════════════════════════════════════════════
# Uso:
#   curl -fsSL https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install.sh | sh -s -- --no-path
#
# Variables opcionales:
#   ZT_SSH_REPO     Repositorio GitHub (default: Kerwit/zero-trust-ssh)
#   ZT_SSH_VERSION  Tag a instalar, p. ej. v0.1.0 (default: latest)
#   ZT_SSH_DIR      Directorio SSH destino (default: $HOME/.ssh)
#   ZT_SSH_NO_PATH  Si es "1", no modifica los ficheros rc del shell
#   GITHUB_TOKEN    Token opcional para descargas autenticadas
# ═════════════════════════════════════════════════════════════════════════════

set -eu

REPO="${ZT_SSH_REPO:-Kerwit/zero-trust-ssh}"
VERSION="${ZT_SSH_VERSION:-latest}"
BINARY_NAME="ssh-usb-unlock"
NO_PATH="${ZT_SSH_NO_PATH:-0}"

for arg in "$@"; do
    case "$arg" in
        --no-path)
            NO_PATH="1"
            ;;
        -h|--help)
            cat <<'EOF'
Instalador de ssh-usb-unlock (Zero-Trust Stateless SSH)
Instala el binario en ~/.ssh/ssh-usb-unlock y lo añade al PATH del usuario.

Opciones:
  --no-path    Instalar solo en ~/.ssh sin modificar el PATH del shell
  -h, --help   Mostrar esta ayuda
EOF
            exit 0
            ;;
        *)
            printf '❌ Opción desconocida: %s\n' "$arg" >&2
            exit 1
            ;;
    esac
done

log()  { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[OK]   %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERR]  %s\n' "$*" >&2; exit 1; }

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Darwin)
            case "$arch" in
                arm64|aarch64) printf '%s' "aarch64-apple-darwin" ;;
                x86_64|amd64)  printf '%s' "x86_64-apple-darwin" ;;
                *) die "Arquitectura macOS no soportada: ${arch}" ;;
            esac
            ;;
        Linux)
            case "$arch" in
                x86_64|amd64)  printf '%s' "x86_64-unknown-linux-musl" ;;
                aarch64|arm64) printf '%s' "aarch64-unknown-linux-musl" ;;
                *) die "Arquitectura Linux no soportada: ${arch}" ;;
            esac
            ;;
        *)
            die "Sistema operativo no soportado por install.sh: ${os} (en Windows usa install.ps1)"
            ;;
    esac
}

download_file() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -o "$dest" "$url"
        else
            curl -fsSL -o "$dest" "$url"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            wget -q --header="Authorization: Bearer ${GITHUB_TOKEN}" -O "$dest" "$url"
        else
            wget -q -O "$dest" "$url"
        fi
    else
        die "Se requiere 'curl' o 'wget' para descargar el binario."
    fi
}

sha256_of() {
    file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | awk '{print $NF}'
    else
        printf ''
    fi
}

main() {
    target="$(detect_target)"
    archive="${BINARY_NAME}-${target}.tar.gz"

    if [ "$VERSION" = "latest" ]; then
        base_url="https://github.com/${REPO}/releases/latest/download"
    else
        base_url="https://github.com/${REPO}/releases/download/${VERSION}"
    fi

    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/zt-ssh-install.XXXXXX")"
    trap 'rm -rf "$tmp_dir"' EXIT INT TERM

    log "Detectada plataforma: ${target}"
    log "Descargando ${archive} desde ${REPO} (${VERSION})..."
    download_file "${base_url}/${archive}" "${tmp_dir}/${archive}"

    # Verificar integridad SHA-256 si SHA256SUMS.txt está disponible
    if download_file "${base_url}/SHA256SUMS.txt" "${tmp_dir}/SHA256SUMS.txt" 2>/dev/null; then
        expected="$(awk -v f="$archive" '$2 == f || $2 == "*"f {print $1; exit}' "${tmp_dir}/SHA256SUMS.txt")"
        actual="$(sha256_of "${tmp_dir}/${archive}")"
        if [ -n "$expected" ] && [ -n "$actual" ]; then
            if [ "$expected" != "$actual" ]; then
                die "Fallo de verificación SHA-256 para ${archive} (esperado: ${expected}, obtenido: ${actual})"
            fi
            ok "Integridad SHA-256 verificada."
        else
            warn "No se pudo verificar SHA-256 automáticamente; continuando."
        fi
    else
        warn "No se encontró SHA256SUMS.txt en el release; omitiendo verificación de checksum."
    fi

    tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}"
    bin_path="${tmp_dir}/${BINARY_NAME}"
    [ -f "$bin_path" ] || die "El archivo descargado no contiene '${BINARY_NAME}'."
    chmod 755 "$bin_path"

    log "Ejecutando auto-instalación en el directorio SSH..."
    if [ "$NO_PATH" = "1" ]; then
        "$bin_path" install --no-path
    else
        "$bin_path" install
    fi
}

main
