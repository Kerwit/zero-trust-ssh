#!/usr/bin/env bash
set -euo pipefail

# Uso: sudo ./install_sshd_zero_trust.sh <BINARY_PATH> <SERVER_MASTER_HEX_64>
BINARY_SRC="${1:-}"
SERVER_MASTER_HEX="${2:-}"

if [[ $EUID -ne 0 ]]; then
   echo "❌ Este script debe ejecutarse como root (sudo)." >&2
   exit 1
fi

if [[ -z "${BINARY_SRC}" || ! -f "${BINARY_SRC}" ]]; then
    echo "❌ Uso: sudo $0 <ruta_binario_sshd-epoch-auth> <SERVER_MASTER_HEX_64_CHARS>" >&2
    exit 1
fi

if [[ ! "${SERVER_MASTER_HEX}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "❌ Error: SERVER_MASTER_HEX debe tener exactamente 64 caracteres hexadecimales (32 bytes)." >&2
    exit 1
fi

AUTH_USER="sshd-trezor"
BIN_DEST="/usr/local/bin/sshd-epoch-auth"
KEY_FILE="/etc/ssh/trezor_master.key"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN_FILE="${SSHD_DROPIN_DIR}/00-zero-trust-epoch.conf"
HOST_ID="$(tr '[:upper:]' '[:lower:]' < /etc/hostname | tr -d '[:space:]')"

echo "🔒 Configurando Zero-Trust SSH Stateless para host_id: '${HOST_ID}'..."

# 1. Crear usuario del sistema sin privilegios ni shell para ejecutar AuthorizedKeysCommand
if ! id -u "${AUTH_USER}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${AUTH_USER}"
    echo "   -> Usuario sin privilegios '${AUTH_USER}' creado."
fi

# 2. Instalar el binario estático con permisos 0755 root:root
install -o root -g root -m 0755 "${BINARY_SRC}" "${BIN_DEST}"
echo "   -> Binario instalado en ${BIN_DEST}"

# 3. Escribir /etc/ssh/trezor_master.key con permisos estrictos 0440 root:sshd-trezor
if [[ -f "${KEY_FILE}" ]]; then
    chattr -i "${KEY_FILE}" 2>/dev/null || true
fi

cat <<EOF > "${KEY_FILE}"
# Zero-Trust SSH ServerMaster (Host: ${HOST_ID})
# Formato: 1 clave hexadecimal de 64 chars por línea (soporta múltiples slots para rotación)
${SERVER_MASTER_HEX}
EOF

chown root:"${AUTH_USER}" "${KEY_FILE}"
chmod 0440 "${KEY_FILE}"
chattr +i "${KEY_FILE}" 2>/dev/null || true
echo "   -> ${KEY_FILE} aprovisionado y blindado (0440 + chattr +i)."

# 4. Probar que el binario ejecuta correctamente bajo el usuario sshd-trezor antes de tocar sshd
echo "🧪 Verificando ejecución de ${BIN_DEST} como usuario '${AUTH_USER}'..."
TEST_OUTPUT="$(su -s /bin/sh "${AUTH_USER}" -c "${BIN_DEST} root")"
if [[ "${TEST_OUTPUT}" != ssh-ed25519* ]]; then
    echo "❌ Fallo en autodiagnóstico de ${BIN_DEST}." >&2
    exit 1
fi
echo "   -> Autodiagnóstico OK. Claves activas para esta hora:"
echo "${TEST_OUTPUT}" | sed 's/^/      /'

# 5. Configurar OpenSSH mediante drop-in (o /etc/ssh/sshd_config)
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

# Verificar si la versión de OpenSSH del servidor soporta ya KEX post-cuántico híbrido mlkem768
if sshd -T 2>/dev/null | grep -q "mlkem768x25519-sha256"; then
    echo "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256" >> "${SSHD_DROPIN_FILE}"
else
    echo "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256" >> "${SSHD_DROPIN_FILE}"
fi

# Asegurar que /etc/ssh/sshd_config incluye /etc/ssh/sshd_config.d/*.conf
if ! grep -Eq "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf" /etc/ssh/sshd_config; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf\n' /etc/ssh/sshd_config
fi

# 6. Validar sintaxis de sshd antes de recargar
if sshd -t; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh
    echo "✅ OpenSSH recargado en modo Zero-Trust Stateless para '${HOST_ID}'."
    echo "⚠️  IMPORTANTE: No cierres esta sesión SSH actual hasta verificar el login en otra ventana."
else
    echo "❌ Error en validación de sshd -t. Revirtiendo drop-in..." >&2
    rm -f "${SSHD_DROPIN_FILE}"
    exit 1
fi