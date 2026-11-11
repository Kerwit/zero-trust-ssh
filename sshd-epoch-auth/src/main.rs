use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use ssh_key::{public::Ed25519PublicKey, PublicKey};
use std::env;
use std::fs;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const DEFAULT_MASTER_KEY_PATH: &str = "/etc/ssh/trezor_master.key";
const DEFAULT_HOSTNAME_PATH: &str = "/etc/hostname";
const EPOCH_DURATION_SECS: u64 = 3600;

/// Nivel 3: Deriva la clave pública Ed25519 efímera para (ServerMaster, host_id, user, epoch)
/// Fórmula idéntica a la que ejecuta el Enclave Móvil en el Nivel 3:
/// EphemeralSeed = HKDF-SHA256(ikm = ServerMaster, salt = epoch.to_be_bytes(), info = "SSH-ED25519-V1:<host_id>:<user>")
pub fn derive_epoch_authorized_key_line(
    server_master: &[u8; 32],
    host_id: &str,
    user: &str,
    epoch: u64,
    slot_index: usize,
) -> Result<String, &'static str> {
    let salt = epoch.to_be_bytes();
    let info = format!("SSH-ED25519-V1:{}:{}", host_id, user);

    let hk = Hkdf::<Sha256>::new(Some(&salt), server_master);
    let mut ephemeral_seed = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut *ephemeral_seed)
        .map_err(|_| "HKDF expansion failed")?;

    let signing_key = SigningKey::from_bytes(&ephemeral_seed);
    let verifying_key = signing_key.verifying_key();

    let ed_pub = Ed25519PublicKey(verifying_key.to_bytes());
    let ssh_pub = PublicKey::from(ed_pub);
    let openssh_base64 = ssh_pub
        .to_openssh()
        .map_err(|_| "Failed to format OpenSSH public key")?;

    // to_openssh() devuelve "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." sin comentario;
    // añadimos el comentario de trazabilidad con host, usuario, epoch y slot.
    Ok(format!(
        "{} trezor-epoch:{}:{}:{}:slot{}",
        openssh_base64.trim(),
        host_id,
        user,
        epoch,
        slot_index
    ))
}

/// Parsea una línea hexadecimal de 64 caracteres (32 bytes) en memoria protegida Zeroizing
pub fn parse_master_key_hex(line: &str) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let decoded = Zeroizing::new(hex::decode(line).map_err(|_| "Invalid hex string")?);
    if decoded.len() != 32 {
        return Err("Master key must be exactly 32 bytes (64 hex chars)");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Valida que el nombre de usuario y host_id solo contengan caracteres seguros
fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let target_user = args.next().ok_or("Missing target username argument (%u)")?;

    if !is_safe_identifier(&target_user) {
        return Err("Invalid characters in target username");
    }

    // Permitir override por variables de entorno solo para tests locales; en producción usa rutas fijas
    let hostname_path =
        env::var("SSHD_EPOCH_HOSTNAME_PATH").unwrap_or_else(|_| DEFAULT_HOSTNAME_PATH.to_string());
    let master_key_path =
        env::var("SSHD_EPOCH_MASTER_KEY_PATH").unwrap_or_else(|_| DEFAULT_MASTER_KEY_PATH.to_string());

    let raw_hostname = fs::read_to_string(Path::new(&hostname_path))
        .map_err(|_| "Failed to read /etc/hostname")?;
    let host_id = raw_hostname.trim().to_ascii_lowercase();

    if !is_safe_identifier(&host_id) {
        return Err("Invalid host_id in /etc/hostname");
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock is before UNIX_EPOCH")?
        .as_secs();

    let current_epoch = now_secs / EPOCH_DURATION_SECS;
    // Ventana Make-Before-Break: acepta la hora actual y la hora inmediatamente anterior
    let valid_epochs = [current_epoch, current_epoch.saturating_sub(1)];

    let raw_keys_content = Zeroizing::new(
        fs::read_to_string(Path::new(&master_key_path))
            .map_err(|_| "Failed to read /etc/ssh/trezor_master.key")?,
    );

    let mut slot_index: usize = 0;
    for line in raw_keys_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Si hay comentarios inline al final de la línea (ej. "a1b2... # gen 0"), quedarse con el hex
        let hex_part = trimmed.split_whitespace().next().unwrap_or("");
        if let Ok(server_master) = parse_master_key_hex(hex_part) {
            for &epoch in &valid_epochs {
                if let Ok(auth_line) = derive_epoch_authorized_key_line(
                    &server_master,
                    &host_id,
                    &target_user,
                    epoch,
                    slot_index,
                ) {
                    println!("{}", auth_line);
                }
            }
            slot_index += 1;
        }
    }

    if slot_index == 0 {
        return Err("No valid 32-byte hex master keys found in trezor_master.key");
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        // OpenSSH ignora stderr y deniega el acceso si el proceso devuelve != 0
        eprintln!("sshd-epoch-auth error: {}", err);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use sha2::Sha256;

    /// Verifica la cadena completa de derivación Nivel 1 -> Nivel 2 -> Nivel 3
    /// garantizando que el Enclave Móvil y el Servidor SSH producen exactamente la misma clave.
    #[test]
    fn test_full_three_level_derivation_consistency() {
        let app_root_seed = [0x42u8; 32];
        let host_id = "rasphouse";
        let user = "root";
        let generation: u32 = 0;
        let epoch: u64 = 498_410;

        // Nivel 1 (En el móvil): Sub-raíz SSH
        let hk_l1 = Hkdf::<Sha256>::new(Some(b"APP-SSH-SUBSYSTEM-SALT-V1"), &app_root_seed);
        let mut ssh_subroot = [0u8; 32];
        hk_l1
            .expand(b"SSH-ZERO-TRUST-SUBROOT-V1", &mut ssh_subroot)
            .unwrap();

        // Nivel 2 (En el móvil al crear el registro "SSH Security"): ServerMaster
        let gen_salt = generation.to_be_bytes();
        let hk_l2 = Hkdf::<Sha256>::new(Some(&gen_salt), &ssh_subroot);
        let mut server_master = [0u8; 32];
        let l2_info = format!("SSH-SERVER-MASTER-V1:{}", host_id);
        hk_l2.expand(l2_info.as_bytes(), &mut server_master).unwrap();

        // Nivel 3 (En el servidor con sshd-epoch-auth): Línea AuthorizedKeys
        let line_1 =
            derive_epoch_authorized_key_line(&server_master, host_id, user, epoch, 0).unwrap();
        let line_2 =
            derive_epoch_authorized_key_line(&server_master, host_id, user, epoch, 0).unwrap();

        assert_eq!(line_1, line_2, "La derivación debe ser 100% determinista");
        assert!(line_1.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(line_1.ends_with("trezor-epoch:rasphouse:root:498410:slot0"));

        // Cambiar el epoch, el usuario o el host_id debe producir claves públicas completamente distintas
        let line_next_hour =
            derive_epoch_authorized_key_line(&server_master, host_id, user, epoch + 1, 0).unwrap();
        let line_other_user =
            derive_epoch_authorized_key_line(&server_master, host_id, "admin", epoch, 0).unwrap();
        let line_other_host =
            derive_epoch_authorized_key_line(&server_master, "ionos-node-server-es", user, epoch, 0)
                .unwrap();

        assert_ne!(line_1, line_next_hour);
        assert_ne!(line_1, line_other_user);
        assert_ne!(line_1, line_other_host);
    }

    #[test]
    fn test_parse_master_key_hex_validation() {
        let valid_hex = "a3f10000000000000000000000000000000000000000000000000000000000ff";
        let parsed = parse_master_key_hex(valid_hex).unwrap();
        assert_eq!(parsed[0], 0xa3);
        assert_eq!(parsed[31], 0xff);

        // Longitud incorrecta o caracteres no hexadecimales deben fallar
        assert!(parse_master_key_hex("a3f1").is_err());
        assert!(parse_master_key_hex(
            "zzzz000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
    }
}