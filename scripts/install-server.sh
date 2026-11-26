#!/bin/sh
# ═════════════════════════════════════════════════════════════════════════════
# install-server.sh — Instalador Linux (x86_64 & ARM64) del daemon servidor
#                     sshd-epoch-auth (Zero-Trust Stateless SSH)
# ═════════════════════════════════════════════════════════════════════════════
# Uso:
#   # Descarga binario + aprovisiona sshd-trezor, /etc/ssh/trezor_master.key y sshd:
#   curl -fsSL https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install-server.sh | sudo sh -s -- <SERVER_MASTER_HEX_64>
#
#   # Solo descargar/actualizar el binario /usr/local/bin/sshd-epoch-auth:
#   curl -fsSL https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install-server.sh | sudo sh -s -- --binary-only
#
# Variables opcionales:
#   ZT_SSH_REPO        Repositorio GitHub (default: Kerwit/zero-trust-ssh)
#   ZT_SSH_VERSION     Tag a instalar, p. ej. v0.1.0 (default: latest)
#   SERVER_MASTER_HEX  Clave maestra hexadecimal de 64 chars (alternativa al argumento)
#   GITHUB_TOKEN       Token opcional para descargas autenticadas
# ═════════════════════════════════════════════════════════════════════════════

set -eu

REPO="${ZT_SSH_REPO:-Kerwit/zero-trust-ssh}"
VERSION="${ZT_SSH_VERSION:-latest}"
BINARY_NAME="sshd-epoch-auth"
BINARY_ONLY="0"
HOST_ID=""
MASTER_HEX="${SERVER_MASTER_HEX:-}"

AUTH_USER="sshd-trezor"
BIN_DEST="/usr/local/bin/sshd-epoch-auth"
KEY_FILE="/etc/ssh/trezor_master.key"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN_FILE="${SSHD_DROPIN_DIR}/00-zero-trust-epoch.conf"

usage() {
    cat <<'EOF'
Instalador del servidor sshd-epoch-auth (Zero-Trust Stateless SSH para Linux)
Descarga el binario estático musl desde GitHub Releases, verifica SHA-256,
instala /usr/local/bin/sshd-epoch-auth y opcionalmente aprovisiona OpenSSH.

Uso:
  sudo sh install-server.sh [OPCIONES] [<SERVER_MASTER_HEX_64>]

Opciones:
  --master-key <HEX64>  Clave maestra de 64 caracteres hex (32 bytes)
  --host-id <ID>        Identificador de host para el comentario de clave (default: /etc/hostname)
  --binary-only         Solo descargar e instalar /usr/local/bin/sshd-epoch-auth
  -h, --help            Mostrar esta ayuda
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary-only)
            BINARY_ONLY="1"
            shift
            ;;
        --master-key)
            [ "$#" -ge 2 ] || { printf '[ERR]  Falta el valor para --master-key\n' >&2; exit 1; }
            MASTER_HEX="$2"
            shift 2
            ;;
        --host-id)
            [ "$#" -ge 2 ] || { printf '[ERR]  Falta el valor para --host-id\n' >&2; exit 1; }
            HOST_ID="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            printf '[ERR]  Opción desconocida: %s\n' "$1" >&2
            exit 1
            ;;
        *)
            if [ -z "$MASTER_HEX" ]; then
                MASTER_HEX="$1"
                shift
            else
                printf '[ERR]  Argumento inesperado: %s\n' "$1" >&2
                exit 1
            fi
            ;;
    esac
done

log()  { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[OK]   %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERR]  %s\n' "$*" >&2; exit 1; }

is_valid_hex64() {
    val="$1"
    [ "${#val}" -eq 64 ] || return 1
    case "$val" in
        *[!0-9a-fA-F]*) return 1 ;;
        *) return 0 ;;
    esac
}

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    [ "$os" = "Linux" ] || die "sshd-epoch-auth solo se instala en servidores Linux (detectado: ${os}). Para el cliente usa install.sh o install.ps1."

    case "$arch" in
        x86_64|amd64)  printf '%s' "x86_64-unknown-linux-musl" ;;
        aarch64|arm64) printf '%s' "aarch64-unknown-linux-musl" ;;
        *) die "Arquitectura Linux no soportada: ${arch}" ;;
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

provision_sshd() {
    tmp_dir="$1"
    master_hex="$2"

    is_valid_hex64 "$master_hex" || die "SERVER_MASTER_HEX debe tener exactamente 64 caracteres hexadecimales (32 bytes)."

    if [ -z "$HOST_ID" ] && [ -r /etc/hostname ]; then
        HOST_ID="$(tr '[:upper:]' '[:lower:]' < /etc/hostname | tr -d '[:space:]')"
    fi
    [ -n "$HOST_ID" ] || HOST_ID="$(hostname | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"

    log "Configurando Zero-Trust SSH Stateless para host_id: '${HOST_ID}'..."

    if ! id -u "${AUTH_USER}" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "${AUTH_USER}"
        ok "Usuario sin privilegios '${AUTH_USER}' creado."
    fi

    if [ -f "${KEY_FILE}" ]; then
        chattr -i "${KEY_FILE}" 2>/dev/null || true
    fi

    cat <<EOF > "${KEY_FILE}"
# Zero-Trust SSH ServerMaster (Host: ${HOST_ID})
# Formato: 1 clave hexadecimal de 64 chars por línea (soporta múltiples slots para rotación)
${master_hex}
EOF

    chown "root:${AUTH_USER}" "${KEY_FILE}"
    chmod 0440 "${KEY_FILE}"
    chattr +i "${KEY_FILE}" 2>/dev/null || true
    ok "${KEY_FILE} aprovisionado y blindado (0440 + chattr +i)."

    log "Verificando ejecución de ${BIN_DEST} como usuario '${AUTH_USER}'..."
    test_output="$(su -s /bin/sh "${AUTH_USER}" -c "${BIN_DEST} root")"
    case "$test_output" in
        ssh-ed25519*)
            ok "Autodiagnóstico OK."
            ;;
        *)
            die "Fallo en autodiagnóstico de ${BIN_DEST}."
            ;;
    esac

    mkdir -p "${SSHD_DROPIN_DIR}"
    cat <<EOF > "${SSHD_DROPIN_FILE}"
# Zero-Trust Stateless SSH Configuration (Managed by sshd-epoch-auth)
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthorizedKeysFile none
AuthorizedKeysCommand ${BIN_DEST} %u
AuthorizedKeysCommandUser ${AUTH_USER}
EOF

    if sshd -T 2>/dev/null | grep -q "mlkem768x25519-sha256"; then
        printf '%s\n' "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256" >> "${SSHD_DROPIN_FILE}"
    else
        printf '%s\n' "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256" >> "${SSHD_DROPIN_FILE}"
    fi

    if [ -f /etc/ssh/sshd_config ] && ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        tmp_cfg="${tmp_dir}/sshd_config.new"
        {
            printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n'
            cat /etc/ssh/sshd_config
        } > "$tmp_cfg"
        cat "$tmp_cfg" > /etc/ssh/sshd_config
    fi

    if sshd -t; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null || true
        ok "OpenSSH recargado en modo Zero-Trust Stateless para '${HOST_ID}'."
        warn "IMPORTANTE: No cierres esta sesión SSH actual hasta verificar el login en otra ventana."
    else
        rm -f "${SSHD_DROPIN_FILE}"
        die "Error en validación de sshd -t. Drop-in revertido."
    fi
}

main() {
    [ "$(id -u)" -eq 0 ] || die "Este script debe ejecutarse como root (usa sudo)."

    target="$(detect_target)"
    archive="${BINARY_NAME}-${target}.tar.gz"

    if [ "$VERSION" = "latest" ]; then
        base_url="https://github.com/${REPO}/releases/latest/download"
    else
        base_url="https://github.com/${REPO}/releases/download/${VERSION}"
    fi

    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/zt-ssh-server-install.XXXXXX")"
    trap 'rm -rf "$tmp_dir"' EXIT INT TERM

    log "Detectada plataforma servidor: ${target}"
    log "Descargando ${archive} desde ${REPO} (${VERSION})..."
    download_file "${base_url}/${archive}" "${tmp_dir}/${archive}"

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

    install -o root -g root -m 0755 "$bin_path" "${BIN_DEST}"
    ok "Binario instalado en ${BIN_DEST}."

    if [ "$BINARY_ONLY" = "1" ]; then
        log "Modo --binary-only activo: no se modificó la configuración de OpenSSH."
        return 0
    fi

    if [ -z "$MASTER_HEX" ]; then
        warn "No se proporcionó SERVER_MASTER_HEX: el binario quedó instalado pero OpenSSH no se ha modificado."
        log "Para completar el aprovisionamiento, ejecuta:"
        printf '  curl -fsSL %s/install-server.sh | sudo sh -s -- <SERVER_MASTER_HEX_64>\n' "$base_url"
        return 0
    fi

    provision_sshd "$tmp_dir" "$MASTER_HEX"
}

main
