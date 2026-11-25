#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# orchestrate_zero_trust_ssh.sh — Orquestador interactivo Zero-Trust Stateless SSH
# ═════════════════════════════════════════════════════════════════════════════
#
# Flujo interactivo en 5 pasos:
#   1. Selección ÚNICA de arquitectura objetivo (linux-x86_64 | linux-arm64) y
#      compilación local estática (musl) de `sshd-epoch-auth` vía `cargo zigbuild`.
#   2. Solicitud de datos SSH iniciales y apertura de sesión multiplexada
#      (ControlMaster) con validación de arquitectura remota y `host_id`.
#   3. Instalación de dependencias y hardening base en el servidor remoto
#      (apt, fail2ban, ufw, unattended-upgrades) con confirmación por bloque.
#   4. Configuración de `sshd` (`SERVER_MASTER_HEX`, puerto, root login) e
#      instalación remota mediante `scripts/install_sshd_zero_trust.sh`.
#   5. Configuración local para activar y validar `sshd` desde la app móvil
#      (LittleKey): compilación de `ssh-usb-unlock`, `known_hosts`, `~/.ssh/config`
#      y prueba E2E antes de cerrar la sesión SSH de respaldo.
#
# Uso:
#   ./scripts/orchestrate_zero_trust_ssh.sh
#   ./scripts/orchestrate_zero_trust_ssh.sh --list-targets
#   ./scripts/orchestrate_zero_trust_ssh.sh --help
# ═════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install_sshd_zero_trust.sh"

# Colores
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_CYAN='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'

log()     { printf '%b[INFO]%b %s\n' "${C_CYAN}" "${C_RESET}" "$*"; }
ok()      { printf '%b[OK]%b   %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn()    { printf '%b[WARN]%b %s\n' "${C_YELLOW}" "${C_RESET}" "$*"; }
die()     { printf '%b[ERR]%b  %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; exit 1; }
banner()  {
    printf '\n%b═══════════════════════════════════════════════════════════════%b\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    printf '%b  %s%b\n' "${C_BOLD}" "$*" "${C_RESET}"
    printf '%b═══════════════════════════════════════════════════════════════%b\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
}

# Estado global de sesión SSH multiplexada (para limpieza garantizada)
CONTROL_DIR=""
SSH_CONTROL_PATH=""
SSH_TARGET=""
SSH_BASE_OPTS=()
SCP_BASE_OPTS=()

cleanup() {
    if [[ -n "${SSH_CONTROL_PATH}" && -S "${SSH_CONTROL_PATH}" && -n "${SSH_TARGET}" ]]; then
        ssh -S "${SSH_CONTROL_PATH}" -O exit "${SSH_TARGET}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${CONTROL_DIR}" && -d "${CONTROL_DIR}" ]]; then
        rm -rf "${CONTROL_DIR}"
    fi
}
trap cleanup EXIT INT TERM

# ── Utilidades ───────────────────────────────────────────────────────────────

sha256_local() {
    local file="$1"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${file}" | awk '{print $1}'
    else
        sha256sum "${file}" | awk '{print $1}'
    fi
}

confirm_yn() {
    local prompt="$1"
    local default="${2:-Y}"
    local hint="[Y/n]"
    [[ "${default}" == "N" ]] && hint="[y/N]"

    local ans=""
    while true; do
        read -r -p "${prompt} ${hint}: " ans
        ans="${ans:-${default}}"
        case "${ans}" in
            [Yy]|[Yy][Ee][Ss]|[Ss]|[Ss][Ii]|[Ss][Í]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) warn "Responde 'y' (sí) o 'n' (no)." ;;
        esac
    done
}

expand_tilde() {
    local p="$1"
    if [[ "${p}" == "~" ]]; then
        printf '%s\n' "${HOME}"
    elif [[ "${p}" == "~/"* ]]; then
        printf '%s/%s\n' "${HOME}" "${p#\~/}"
    else
        printf '%s\n' "${p}"
    fi
}

print_targets() {
    echo "Arquitecturas soportadas para sshd-epoch-auth (Linux musl estático):"
    echo "  1) linux-x86_64  (x86_64-unknown-linux-musl)   — VPS / Servidores Intel/AMD 64-bit"
    echo "  2) linux-arm64   (aarch64-unknown-linux-musl)  — Raspberry Pi 4/5 / ARM64"
}

usage() {
    sed -n '2,24p' "$0"
}

# ── Parseo CLI ligero ────────────────────────────────────────────────────────

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    --list-targets)
        print_targets
        exit 0
        ;;
    "")
        ;;
    *)
        die "Argumento desconocido: $1 (usa --help)"
        ;;
esac

# Verificaciones iniciales del repositorio
[[ -f "${REPO_DIR}/Cargo.toml" ]] || die "No se encontró Cargo.toml en ${REPO_DIR}"
[[ -f "${INSTALL_SCRIPT}" ]]      || die "No se encontró ${INSTALL_SCRIPT}"
command -v ssh >/dev/null 2>&1    || die "No se encontró 'ssh' en el PATH."
command -v scp >/dev/null 2>&1    || die "No se encontró 'scp' en el PATH."

# ═════════════════════════════════════════════════════════════════════════════
# PASO 1: Selección ÚNICA de arquitectura y compilación local
# ═════════════════════════════════════════════════════════════════════════════

step_1_select_and_build() {
    banner "PASO 1/5 — Selección de Arquitectura y Compilación Local"

    command -v cargo >/dev/null 2>&1  || die "No se encontró 'cargo'. Instala Rust: https://rustup.rs"
    command -v rustup >/dev/null 2>&1 || die "No se encontró 'rustup'."
    if ! command -v cargo-zigbuild >/dev/null 2>&1; then
        die "No se encontró 'cargo-zigbuild'. Instálalo con: cargo install cargo-zigbuild (y zig vía brew install zig)."
    fi

    echo ""
    print_targets
    echo ""

    local choice=""
    SELECTED_ARCH=""
    RUST_TARGET=""
    EXPECTED_UNAME=""
    EXPECTED_ELF=""

    while true; do
        read -r -p "Selecciona UNA única arquitectura [1-2]: " choice
        case "${choice}" in
            1)
                SELECTED_ARCH="linux-x86_64"
                RUST_TARGET="x86_64-unknown-linux-musl"
                EXPECTED_UNAME="x86_64"
                EXPECTED_ELF="x86-64"
                break
                ;;
            2)
                SELECTED_ARCH="linux-arm64"
                RUST_TARGET="aarch64-unknown-linux-musl"
                EXPECTED_UNAME="aarch64"
                EXPECTED_ELF="aarch64"
                break
                ;;
            *)
                warn "Selección inválida ('${choice}'). Debes elegir exactamente UNA opción: 1 o 2."
                ;;
        esac
    done

    ok "Arquitectura seleccionada: ${SELECTED_ARCH} (${RUST_TARGET})"

    if ! rustup target list --installed | grep -qx "${RUST_TARGET}"; then
        log "Instalando target Rust '${RUST_TARGET}'..."
        rustup target add "${RUST_TARGET}"
    fi

    log "Compilando 'sshd-epoch-auth' (release, musl estático) para ${RUST_TARGET}..."
    (
        cd "${REPO_DIR}"
        cargo zigbuild --bin sshd-epoch-auth --release --target "${RUST_TARGET}"
    )

    COMPILED_BIN="${REPO_DIR}/target/${RUST_TARGET}/release/sshd-epoch-auth"
    [[ -f "${COMPILED_BIN}" ]] || die "No se encontró el binario compilado en ${COMPILED_BIN}"

    local ftype
    ftype="$(file -b "${COMPILED_BIN}")"
    if ! grep -qi "${EXPECTED_ELF}" <<<"${ftype}"; then
        die "El binario compilado no coincide con ${EXPECTED_ELF}: ${ftype}"
    fi

    LOCAL_BIN_SHA256="$(sha256_local "${COMPILED_BIN}")"
    ok "Binario verificado: ${COMPILED_BIN}"
    log "Tipo ELF: ${ftype}"
    log "SHA-256:  ${LOCAL_BIN_SHA256}"
}

# ═════════════════════════════════════════════════════════════════════════════
# PASO 2: Datos para establecer la conexión SSH inicial
# ═════════════════════════════════════════════════════════════════════════════

step_2_initial_ssh() {
    banner "PASO 2/5 — Datos de Conexión SSH Inicial"

    SSH_HOST=""
    while [[ -z "${SSH_HOST}" ]]; do
        read -r -p "Host o IP del servidor remoto (ej. 192.168.1.33): " SSH_HOST
        SSH_HOST="${SSH_HOST// /}"
        [[ -n "${SSH_HOST}" ]] || warn "El host/IP no puede estar vacío."
    done

    local default_user="${USER:-root}"
    read -r -p "Usuario SSH inicial [${default_user}]: " SSH_USER
    SSH_USER="${SSH_USER:-${default_user}}"

    SSH_PORT=""
    while true; do
        read -r -p "Puerto SSH inicial [22]: " SSH_PORT
        SSH_PORT="${SSH_PORT:-22}"
        if [[ "${SSH_PORT}" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1 && SSH_PORT <= 65535 )); then
            break
        fi
        warn "Puerto inválido. Introduce un número entre 1 y 65535."
    done

    SSH_KEY_PATH=""
    while true; do
        read -r -p "Ruta a clave privada SSH (dejar vacío para contraseña / clave por defecto): " SSH_KEY_PATH
        if [[ -z "${SSH_KEY_PATH}" ]]; then
            break
        fi
        SSH_KEY_PATH="$(expand_tilde "${SSH_KEY_PATH}")"
        if [[ -f "${SSH_KEY_PATH}" ]]; then
            break
        fi
        warn "No existe el fichero '${SSH_KEY_PATH}'. Inténtalo de nuevo o déjalo vacío."
    done

    CONTROL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zt-ssh-orch.XXXXXX")"
    chmod 700 "${CONTROL_DIR}"
    SSH_CONTROL_PATH="${CONTROL_DIR}/ctrl.sock"
    SSH_TARGET="${SSH_USER}@${SSH_HOST}"

    SSH_BASE_OPTS=(
        -p "${SSH_PORT}"
        -o "ControlPath=${SSH_CONTROL_PATH}"
        -o "ConnectTimeout=15"
        -o "ServerAliveInterval=30"
    )
    SCP_BASE_OPTS=(
        -P "${SSH_PORT}"
        -o "ControlPath=${SSH_CONTROL_PATH}"
        -o "ConnectTimeout=15"
    )
    if [[ -n "${SSH_KEY_PATH}" ]]; then
        SSH_BASE_OPTS+=(-i "${SSH_KEY_PATH}")
        SCP_BASE_OPTS+=(-i "${SSH_KEY_PATH}")
    fi

    log "Estableciendo conexión SSH maestra con ${SSH_TARGET}:${SSH_PORT}..."
    ssh -M -fN -o "ControlPersist=15m" "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" \
        || die "No se pudo establecer la conexión SSH con ${SSH_TARGET}:${SSH_PORT}."
    ok "Conexión SSH inicial establecida y multiplexada."

    # Validar arquitectura remota y detectar hostname (host_id) y privilegios
    local remote_info remote_arch remote_uid
    remote_info="$(ssh "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" 'printf "%s|%s|%s\n" "$(uname -m)" "$(tr "[:upper:]" "[:lower:]" < /etc/hostname | tr -d "[:space:]")" "$(id -u)"')" \
        || die "Error consultando información del servidor remoto."

    IFS='|' read -r remote_arch REMOTE_HOST_ID remote_uid <<<"${remote_info}"

    if [[ "${remote_arch}" != "${EXPECTED_UNAME}" ]]; then
        die "Arquitectura remota (${remote_arch}) NO coincide con la compilada (${SELECTED_ARCH} / ${EXPECTED_UNAME}). Reejecuta seleccionando la arquitectura correcta."
    fi
    ok "Arquitectura remota verificada: ${remote_arch} (coincide con ${SELECTED_ARCH})"
    ok "host_id detectado en /etc/hostname: '${REMOTE_HOST_ID}'"

    REMOTE_SUDO=""
    if [[ "${remote_uid}" != "0" ]]; then
        REMOTE_SUDO="sudo"
        log "El usuario remoto '${SSH_USER}' no es root; validando credenciales sudo..."
        ssh -t "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" "sudo -v" \
            || die "El usuario '${SSH_USER}' no dispone de privilegios sudo válidos."
        ok "Privilegios sudo confirmados."
    else
        ok "Conectado como root."
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# PASO 3: Instalación de dependencias y hardening base en el servidor remoto
# ═════════════════════════════════════════════════════════════════════════════

step_3_install_dependencies() {
    banner "PASO 3/5 — Dependencias y Hardening Base en el Servidor"

    log "Cada bloque de hardening de ZERO_TRUST_SSH_DEPLOYMENT.md requiere confirmación."
    echo ""

    # Bloque 3.1: Actualización APT + paquetes base
    if confirm_yn "¿Actualizar sistema (apt update/upgrade) e instalar paquetes base (fail2ban, ufw, unattended-upgrades, e2fsprogs, herramientas)?" "Y"; then
        log "Instalando actualizaciones y paquetes base en ${SSH_HOST}..."
        ssh -t "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" "${REMOTE_SUDO} bash -s" <<'REMOTE_APT'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    build-essential pkg-config libssl-dev \
    htop tmux tree ripgrep net-tools unzip ncdu \
    e2fsprogs ufw fail2ban unattended-upgrades
REMOTE_APT
        ok "Paquetes base instalados."
    else
        warn "Bloque APT omitido por el usuario."
    fi

    # Bloque 3.2: Fail2ban
    if confirm_yn "¿Configurar y habilitar Fail2ban para proteger sshd (/etc/fail2ban/jail.local)?" "Y"; then
        log "Configurando Fail2ban (puerto ${SSH_PORT})..."
        ssh -t "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" "${REMOTE_SUDO} bash -s" -- "${SSH_PORT}" <<'REMOTE_F2B'
set -euo pipefail
PORT="$1"
if ! command -v fail2ban-client >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq fail2ban
fi
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ${PORT}
backend = systemd
EOF
systemctl enable fail2ban
systemctl restart fail2ban
REMOTE_F2B
        ok "Fail2ban configurado y activo."
    else
        warn "Bloque Fail2ban omitido por el usuario."
    fi

    # Bloque 3.3: UFW
    if confirm_yn "¿Configurar cortafuegos UFW (deny incoming, allow ${SSH_PORT}/tcp, enable)?" "Y"; then
        log "Configurando UFW permitiendo ${SSH_PORT}/tcp..."
        ssh -t "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" "${REMOTE_SUDO} bash -s" -- "${SSH_PORT}" <<'REMOTE_UFW'
set -euo pipefail
PORT="$1"
if ! command -v ufw >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq ufw
fi
ufw default deny incoming
ufw default allow outgoing
ufw allow "${PORT}/tcp" comment 'SSH'
ufw --force enable
ufw status numbered
REMOTE_UFW
        ok "UFW activo con puerto ${SSH_PORT}/tcp permitido."
    else
        warn "Bloque UFW omitido por el usuario."
    fi

    # Bloque 3.4: Unattended upgrades
    if confirm_yn "¿Habilitar actualizaciones automáticas de seguridad (unattended-upgrades)?" "Y"; then
        log "Habilitando unattended-upgrades..."
        ssh -t "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" "${REMOTE_SUDO} bash -s" <<'REMOTE_UU'
set -euo pipefail
if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq unattended-upgrades
fi
systemctl enable unattended-upgrades
systemctl restart unattended-upgrades
REMOTE_UU
        ok "unattended-upgrades habilitado."
    else
        warn "Bloque unattended-upgrades omitido por el usuario."
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# PASO 4: Configuración de sshd e instalación del script asociado
# ═════════════════════════════════════════════════════════════════════════════

step_4_configure_sshd() {
    banner "PASO 4/5 — Configuración de sshd e Instalación de sshd-epoch-auth"

    printf '\n'
    log "En la app móvil LittleKey, registra el servidor con:"
    printf '   %bhost_id:%b %s\n' "${C_BOLD}" "${C_RESET}" "${REMOTE_HOST_ID}"
    log "y copia el secreto ServerMaster generado (64 caracteres hexadecimales)."
    printf '\n'

    local server_master_hex=""
    while true; do
        read -r -s -p "Introduce SERVER_MASTER_HEX (64 chars hex, entrada oculta): " server_master_hex
        echo ""
        server_master_hex="${server_master_hex// /}"
        if [[ "${server_master_hex}" =~ ^[0-9a-fA-F]{64}$ ]]; then
            ok "Formato de SERVER_MASTER_HEX válido (64 hex / 32 bytes)."
            break
        fi
        warn "Debe tener exactamente 64 caracteres hexadecimales (0-9, a-f). Inténtalo de nuevo."
    done

    FINAL_SSH_PORT=""
    while true; do
        read -r -p "Puerto final para sshd [${SSH_PORT}]: " FINAL_SSH_PORT
        FINAL_SSH_PORT="${FINAL_SSH_PORT:-${SSH_PORT}}"
        if [[ "${FINAL_SSH_PORT}" =~ ^[0-9]+$ ]] && (( FINAL_SSH_PORT >= 1 && FINAL_SSH_PORT <= 65535 )); then
            break
        fi
        warn "Puerto inválido. Introduce un número entre 1 y 65535."
    done

    local default_root_login="no"
    [[ "${SSH_USER}" == "root" ]] && default_root_login="prohibit-password"
    local permit_root_login=""
    while true; do
        read -r -p "Directiva PermitRootLogin (no | prohibit-password) [${default_root_login}]: " permit_root_login
        permit_root_login="${permit_root_login:-${default_root_login}}"
        case "${permit_root_login}" in
            no|prohibit-password) break ;;
            *) warn "Valores permitidos: 'no' o 'prohibit-password'." ;;
        esac
    done

    # Crear directorio temporal remoto seguro y transferir binario + script instalador
    local remote_tmp
    remote_tmp="$(ssh "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" 'mktemp -d /tmp/zt-ssh-install.XXXXXX && chmod 700 /tmp/zt-ssh-install.*')" \
        || die "No se pudo crear directorio temporal en el servidor remoto."
    # mktemp imprimió la ruta en la última línea (o única línea)
    remote_tmp="$(printf '%s\n' "${remote_tmp}" | tail -n1 | tr -d '[:space:]')"

    log "Transfiriendo 'install_sshd_zero_trust.sh' y 'sshd-epoch-auth' a ${SSH_HOST}:${remote_tmp}..."
    scp "${SCP_BASE_OPTS[@]}" "${INSTALL_SCRIPT}" "${COMPILED_BIN}" "${SSH_TARGET}:${remote_tmp}/" \
        || die "Error transfiriendo archivos por SCP."

    # Verificar integridad SHA-256 en remoto
    local remote_sha
    remote_sha="$(ssh "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" "sha256sum '${remote_tmp}/sshd-epoch-auth' | awk '{print \$1}'")" \
        || die "Error calculando SHA-256 remoto."
    if [[ "${remote_sha}" != "${LOCAL_BIN_SHA256}" ]]; then
        ssh "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" "rm -rf '${remote_tmp}'" >/dev/null 2>&1 || true
        die "SHA-256 no coincide tras transferencia SCP (local=${LOCAL_BIN_SHA256}, remoto=${remote_sha})."
    fi
    ok "Integridad SHA-256 verificada en el servidor remoto."

    # Ejecutar script asociado install_sshd_zero_trust.sh y aplicar customización segura
    log "Ejecutando install_sshd_zero_trust.sh en el servidor remoto..."
    ssh -t "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" \
        "${REMOTE_SUDO} bash -s" -- "${remote_tmp}" "${server_master_hex}" "${FINAL_SSH_PORT}" "${SSH_PORT}" "${permit_root_login}" <<'REMOTE_INSTALL'
set -euo pipefail
REMOTE_TMP="$1"
MASTER_HEX="$2"
FINAL_PORT="$3"
ORIG_PORT="$4"
ROOT_LOGIN="$5"

cleanup_remote() {
    rm -rf "${REMOTE_TMP}"
}
trap cleanup_remote EXIT

chmod 0700 "${REMOTE_TMP}/install_sshd_zero_trust.sh"
"${REMOTE_TMP}/install_sshd_zero_trust.sh" "${REMOTE_TMP}/sshd-epoch-auth" "${MASTER_HEX}"

CUSTOM_DROPIN="/etc/ssh/sshd_config.d/01-zero-trust-custom.conf"
cat <<EOF > "${CUSTOM_DROPIN}"
# Customización adicional generada por orchestrate_zero_trust_ssh.sh
Port ${FINAL_PORT}
PermitRootLogin ${ROOT_LOGIN}
EOF

# Si cambió el puerto y UFW está activo, abrir el nuevo puerto antes de recargar sshd
if [[ "${FINAL_PORT}" != "${ORIG_PORT}" ]] && command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw allow "${FINAL_PORT}/tcp" comment 'SSH Zero-Trust'
    fi
fi

if sshd -t; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh
    echo "✅ Drop-in adicional aplicado (Port=${FINAL_PORT}, PermitRootLogin=${ROOT_LOGIN})."
else
    echo "❌ Error en sshd -t tras drop-in adicional. Revirtiendo ${CUSTOM_DROPIN}..." >&2
    rm -f "${CUSTOM_DROPIN}"
    exit 1
fi
REMOTE_INSTALL

    # Limpiar el secreto de la memoria del shell
    server_master_hex=""
    unset server_master_hex

    ok "sshd configurado en modo Zero-Trust Stateless y archivos temporales eliminados."
}

# ═════════════════════════════════════════════════════════════════════════════
# PASO 5: Configuración para activar y validar sshd desde la app móvil
# ═════════════════════════════════════════════════════════════════════════════

step_5_mobile_validation_config() {
    banner "PASO 5/5 — Configuración de Validación desde la App Móvil (LittleKey)"

    local unlock_bin="${REPO_DIR}/target/release/ssh-usb-unlock"
    if [[ ! -x "${unlock_bin}" ]] || confirm_yn "¿Compilar/actualizar el binario local 'ssh-usb-unlock' (cliente USB para LittleKey)?" "Y"; then
        log "Compilando 'ssh-usb-unlock' en modo release..."
        (
            cd "${REPO_DIR}"
            cargo build --release -p ssh-usb-unlock
        )
    fi
    [[ -x "${unlock_bin}" ]] || die "No se encontró el binario ejecutable '${unlock_bin}'."
    ok "Cliente local listo: ${unlock_bin}"

    echo ""
    local default_alias="${REMOTE_HOST_ID}-server"
    read -r -p "Alias para ~/.ssh/config [${default_alias}]: " SSH_ALIAS
    SSH_ALIAS="${SSH_ALIAS:-${default_alias}}"

    read -r -p "host_id registrado en LittleKey [${REMOTE_HOST_ID}]: " MOBILE_HOST_ID
    MOBILE_HOST_ID="${MOBILE_HOST_ID:-${REMOTE_HOST_ID}}"
    MOBILE_HOST_ID="$(printf '%s' "${MOBILE_HOST_ID}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"

    read -r -p "Usuario SSH configurado en LittleKey [${SSH_USER}]: " MOBILE_SSH_USER
    MOBILE_SSH_USER="${MOBILE_SSH_USER:-${SSH_USER}}"

    local generation=""
    while true; do
        read -r -p "Número de generación (generation) en LittleKey [1]: " generation
        generation="${generation:-1}"
        if [[ "${generation}" =~ ^[0-9]+$ ]]; then
            break
        fi
        warn "La generación debe ser un entero >= 0 (ej. 0 o 1)."
    done

    # 1. Registrar huella del host en ~/.ssh/known_hosts
    mkdir -p "${HOME}/.ssh"
    chmod 700 "${HOME}/.ssh"
    touch "${HOME}/.ssh/known_hosts"
    chmod 600 "${HOME}/.ssh/known_hosts"

    if command -v ssh-keyscan >/dev/null 2>&1; then
        log "Registrando huella de ${SSH_HOST}:${FINAL_SSH_PORT} en ~/.ssh/known_hosts..."
        local scanned_keys
        scanned_keys="$(ssh-keyscan -p "${FINAL_SSH_PORT}" -H "${SSH_HOST}" 2>/dev/null || true)"
        if [[ -n "${scanned_keys}" ]]; then
            printf '%s\n' "${scanned_keys}" >> "${HOME}/.ssh/known_hosts"
            ok "Huella añadida a ~/.ssh/known_hosts."
        else
            warn "ssh-keyscan no devolvió claves (puedes añadirla manualmente al conectar)."
        fi
    fi

    # 2. Actualizar ~/.ssh/config de forma idempotente (con backup)
    local ssh_config="${HOME}/.ssh/config"
    local marker_start="# >>> zero-trust-ssh: ${SSH_ALIAS} >>>"
    local marker_end="# <<< zero-trust-ssh: ${SSH_ALIAS} <<<"

    if [[ -f "${ssh_config}" ]]; then
        local backup_file="${ssh_config}.bak.$(date +%Y%m%d-%H%M%S)"
        cp "${ssh_config}" "${backup_file}"
        chmod 600 "${backup_file}"
        log "Backup creado en ${backup_file}"

        # Si el bloque ya existía por una ejecución previa, reemplazarlo limpiamente
        if grep -Fq "${marker_start}" "${ssh_config}"; then
            local tmp_cfg
            tmp_cfg="$(mktemp "${CONTROL_DIR}/ssh_config.XXXXXX")"
            awk -v s="${marker_start}" -v e="${marker_end}" '
                $0 == s { skip = 1; next }
                $0 == e { skip = 0; next }
                !skip { print }
            ' "${ssh_config}" > "${tmp_cfg}"
            mv "${tmp_cfg}" "${ssh_config}"
            chmod 600 "${ssh_config}"
        fi
    else
        touch "${ssh_config}"
        chmod 600 "${ssh_config}"
    fi

    cat <<EOF >> "${ssh_config}"

${marker_start}
Host ${SSH_ALIAS} ${SSH_HOST}
    HostName ${SSH_HOST}
    Port ${FINAL_SSH_PORT}
    User ${MOBILE_SSH_USER}

Match host ${SSH_ALIAS},${SSH_HOST} exec "${unlock_bin} ${MOBILE_HOST_ID} ${MOBILE_SSH_USER} ${generation}"
${marker_end}
EOF
    chmod 600 "${ssh_config}"
    ok "Bloque Zero-Trust SSH añadido en ${ssh_config} para '${SSH_ALIAS}'."

    # 3. Preparar adb forward (si adb está disponible) y ofrecer prueba E2E ANTES de cerrar ControlMaster
    local adb_bin=""
    if command -v adb >/dev/null 2>&1; then
        adb_bin="$(command -v adb)"
    elif [[ -x "${HOME}/Library/Android/sdk/platform-tools/adb" ]]; then
        adb_bin="${HOME}/Library/Android/sdk/platform-tools/adb"
    fi

    if [[ -n "${adb_bin}" ]]; then
        log "Intentando activar reenvío USB (adb forward tcp:9422 tcp:9422)..."
        if "${adb_bin}" forward tcp:9422 tcp:9422 >/dev/null 2>&1; then
            ok "Túnel USB ADB activo en 127.0.0.1:9422."
        else
            warn "No se detectó dispositivo Android conectado por USB todavía."
        fi
    else
        warn "No se encontró 'adb' en PATH ni en ~/Library/Android/sdk/platform-tools/adb."
    fi

    echo ""
    warn "La sesión SSH inicial sigue abierta como red de seguridad."
    log "Conecta tu móvil por USB, abre LittleKey y desbloquea la bóveda antes de probar."

    if confirm_yn "¿Ejecutar ahora la validación E2E contra '${SSH_ALIAS}' usando LittleKey?" "Y"; then
        log "Probando conexión Zero-Trust (forzando nueva sesión sin ControlMaster)..."
        if ssh -o ControlPath=none -o IdentitiesOnly=yes -o ConnectTimeout=25 "${SSH_ALIAS}" \
            'printf "✅ Acceso Zero-Trust SSH validado en %s (%s)\n" "$(hostname)" "$(uptime -p 2>/dev/null || uptime)"'; then
            ok "¡Validación E2E completada con éxito!"
            log "Claves efímeras cargadas en ssh-agent:"
            ssh-add -l 2>/dev/null | grep "trezor-epoch:${MOBILE_HOST_ID}" || true
        else
            warn "La prueba E2E falló."
            warn "Revisa que LittleKey tenga registrado host_id='${MOBILE_HOST_ID}', user='${MOBILE_SSH_USER}', generation='${generation}' y el mismo SERVER_MASTER_HEX."
            if confirm_yn "¿Abrir una shell de rescate usando la sesión SSH inicial para diagnosticar antes de cerrar?" "Y"; then
                ssh "${SSH_BASE_OPTS[@]}" "${SSH_TARGET}" || true
            fi
        fi
    else
        log "Puedes probar manualmente en otra terminal con: ssh ${SSH_ALIAS} \"uptime\""
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Ejecución principal
# ═════════════════════════════════════════════════════════════════════════════

main() {
    banner "Orquestador Zero-Trust Stateless SSH"
    step_1_select_and_build
    step_2_initial_ssh
    step_3_install_dependencies
    step_4_configure_sshd
    step_5_mobile_validation_config
    banner "Orquestación finalizada"
    ok "Servidor '${SSH_ALIAS}' (${SSH_HOST}:${FINAL_SSH_PORT}) aprovisionado y listo."
}

main "$@"
