# Zero-Trust Stateless SSH

Sistema de autenticación SSH sin estado (*stateless*) basado en derivación criptográfica determinista por épocas temporales (**HKDF-SHA256 + Ed25519**).

Elimina por completo la necesidad de almacenar claves públicas estáticas en los servidores (`~/.ssh/authorized_keys`) y prohíbe el uso de contraseñas. Cada clave es válida estrictamente durante una ventana temporal de 60 minutos (*epoch*) aprobada mediante hardware/biometría desde un Enclave Móvil.

---

## 🏛️ Estructura del Workspace

```
zero-trust-ssh/
├── Cargo.toml                  # Workspace Rust (sshd-epoch-auth + ssh-usb-unlock)
├── Cargo.lock
├── sshd-epoch-auth/            # Daemon del servidor OpenSSH (AuthorizedKeysCommand)
│   ├── Cargo.toml
│   └── src/main.rs
├── ssh-usb-unlock/             # CLI multiplataforma (macOS/Linux/Windows) + helper ssh-agent
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── cli.rs              # Comandos interactivos (link, list, unlink, test, install, doctor)
│       ├── ssh_config.rs       # Gestión idempotente de ~/.ssh/config, known_hosts y PATH
│       ├── agent_sync.rs       # Inyección en ssh-agent con TTL en RAM
│       ├── locked_memory.rs    # Protección de memoria (mlock Unix / VirtualLock Windows)
│       └── usb_tunnel.rs       # Comunicación ECDH cifrada por cable USB (puerto 9422)
├── scripts/
│   ├── install.sh              # Auto-instalador vía curl para macOS y Linux (~/.ssh)
│   ├── install.ps1             # Auto-instalador vía curl/PowerShell para Windows (%USERPROFILE%\.ssh)
│   ├── install_sshd_zero_trust.sh # Script de aprovisionamiento en servidor Linux
│   └── orchestrate_zero_trust_ssh.sh # Orquestador completo servidor + cliente
├── .github/workflows/
│   └── release.yml             # CI/CD multiplataforma (macOS, Linux musl, Windows x64/ARM64)
└── docs/
    └── ZERO_TRUST_SSH_DEPLOYMENT.md # Guía de despliegue paso a paso
```

---

## ⚡ Instalación Rápida del CLI (Auto-instalable en tu directorio SSH)

Instala `ssh-usb-unlock` directamente en el directorio de configuración SSH de tu sistema operativo (`~/.ssh` en macOS/Linux, `%USERPROFILE%\.ssh` en Windows) y lo añade a tu `PATH`:

### macOS y Linux
```sh
curl -fsSL https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install.sh | sh
```

### Windows (CMD / PowerShell con `curl.exe`)
```cmd
curl.exe -fsSL https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install.ps1 | powershell -NoProfile -ExecutionPolicy Bypass -Command -
```
*(Alternativa nativa en PowerShell: `irm https://github.com/Kerwit/zero-trust-ssh/releases/latest/download/install.ps1 | iex`)*

### Comandos del CLI (vinculación con LittleKey)
```sh
# Asistente interactivo para vincular un servidor con LittleKey (actualiza ~/.ssh/config y known_hosts)
ssh-usb-unlock link

# Modo no interactivo (flags)
ssh-usb-unlock link --host 192.168.1.33 --port 22 --alias lnode-server --host-id lnode --user lnode --generation 1 --no-interactive

# Gestión y diagnóstico
ssh-usb-unlock list               # Lista hosts vinculados
ssh-usb-unlock test lnode-server  # Activa adb forward y valida conexión E2E
ssh-usb-unlock unlink lnode-server
ssh-usb-unlock doctor             # Verifica ~/.ssh, PATH, adb y ssh-agent
ssh-usb-unlock install            # Auto-instala el binario actual en ~/.ssh (%USERPROFILE%\.ssh)
ssh-usb-unlock uninstall          # Desinstala el binario de ~/.ssh
```

### Publicar una nueva versión (GitHub Actions)
```bash
git tag v0.1.0
git push origin v0.1.0
```
También puedes lanzarlo manualmente desde la pestaña **Actions → Release Multi-Platform CLI → Run workflow**.

---

## 🚀 Inicio Rápido (Compilación Manual)

### 1. Compilación
```bash
# Compilar cliente (macOS)
cargo build --release -p ssh-usb-unlock

# Compilar daemon del servidor (Linux x86_64 estático musl)
cargo zigbuild --bin sshd-epoch-auth --release --target x86_64-unknown-linux-musl
```

### 2. Despliegue en el Servidor
```bash
scp scripts/install_sshd_zero_trust.sh target/x86_64-unknown-linux-musl/release/sshd-epoch-auth <user>@<host>:/tmp/
ssh <user>@<host> "sudo /tmp/install_sshd_zero_trust.sh /tmp/sshd-epoch-auth <SERVER_MASTER_HEX_64>"
```

### 3. Configuración en Cliente (`~/.ssh/config`)
```ssh
Host <nombre-host> <ip-host>
    HostName <ip-host>
    User <usuario>

Match host <nombre-host>,<ip-host> exec "/ruta/a/target/release/ssh-usb-unlock <host_id> <usuario> <generacion>"
```

Para una guía detallada del despliegue y hardening del servidor, consulta [docs/ZERO_TRUST_SSH_DEPLOYMENT.md](docs/ZERO_TRUST_SSH_DEPLOYMENT.md).

