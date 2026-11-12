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
├── ssh-usb-unlock/             # Herramienta cliente para inyección en ssh-agent
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── agent_sync.rs       # Inyección en ssh-agent con TTL en RAM
│       ├── locked_memory.rs    # Protección de memoria contra swap/dump
│       └── usb_tunnel.rs       # Comunicación ECDH cifrada por cable USB (puerto 9422)
├── scripts/
│   └── install_sshd_zero_trust.sh # Script de aprovisionamiento en servidor Linux
└── docs/
    └── ZERO_TRUST_SSH_DEPLOYMENT.md # Guía de despliegue paso a paso
```

---

## 🚀 Inicio Rápido

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

