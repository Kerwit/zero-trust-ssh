use crate::locked_memory::LockedBuffer;
use ssh_key::{
    private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData},
    LineEnding, PrivateKey,
};
use std::io::Write;
use std::process::{Command, Stdio};

/// Revisa `ssh-add -L`:
/// - Devuelve `Ok(true)` si la clave de `(host_id, user, current_epoch)` ya está activa en RAM.
/// - Elimina automáticamente cualquier clave `trezor-epoch:` de epochs antiguos.
pub fn sync_agent_epochs(host_id: &str, user: &str, current_epoch: u64) -> Result<bool, String> {
    let output = Command::new("ssh-add")
        .arg("-L")
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("No se pudo ejecutar ssh-add -L: {}", e))?;

    // Si ssh-add devuelve código != 0 (ej. el agente aún no tiene ninguna identidad cargada), no hay claves activas
    if !output.status.success() {
        return Ok(false);
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let expected_comment = format!("trezor-epoch:{}:{}:{}", host_id, user, current_epoch);
    let current_epoch_suffix = format!(":{}", current_epoch);

    let mut current_key_already_loaded = false;

    for line in stdout_str.lines() {
        let trimmed = line.trim();
        if trimmed.contains(&expected_comment) {
            current_key_already_loaded = true;
        } else if trimmed.contains("trezor-epoch:") && !trimmed.ends_with(&current_epoch_suffix) {
            // Es una clave efímera de una hora anterior -> Purgarla de la RAM del ssh-agent
            let _ = remove_public_key_from_agent(trimmed);
        }
    }

    Ok(current_key_already_loaded)
}

fn remove_public_key_from_agent(pubkey_line: &str) -> Result<(), String> {
    let mut child = Command::new("ssh-add")
        .args(["-q", "-d", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{}", pubkey_line);
    }
    let _ = child.wait();
    Ok(())
}

/// Construye la clave privada OpenSSH en memoria desde los 32 bytes del `LockedBuffer`
/// y la inyecta por pipe a `ssh-add -q -t <remaining_secs> -` sin tocar el disco.
pub fn inject_ephemeral_key_to_agent(
    seed: &LockedBuffer<32>,
    host_id: &str,
    user: &str,
    current_epoch: u64,
    now_secs: u64,
) -> Result<(), String> {
    let comment = format!("trezor-epoch:{}:{}:{}", host_id, user, current_epoch);

    let ed_priv = Ed25519PrivateKey::from_bytes(&**seed);
    let keypair = Ed25519Keypair::from(ed_priv);
    let priv_key = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
        .map_err(|e| format!("Error construyendo estructura PrivateKey OpenSSH: {}", e))?;

    // ZeroizingString: se limpia automáticamente de la RAM al salir de esta función
    let openssh_pem = priv_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("Error serializando clave OpenSSH en memoria: {}", e))?;

    // TTL sincronizado con el fin de la hora actual + 60s de solape
    let remaining_secs = 3600 - (now_secs % 3600) + 60;

    let mut child = Command::new("ssh-add")
        .args(["-q", "-t", &remaining_secs.to_string(), "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("No se pudo lanzar ssh-add: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(openssh_pem.as_bytes())
            .map_err(|e| format!("Error enviando clave por pipe a ssh-add: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Error esperando a ssh-add: {}", e))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ssh-add rechazó la clave en RAM: {}", err_msg.trim()));
    }

    eprintln!(
        "🔓 [Zero-Trust SSH] Clave efímera inyectada en RAM para '{}@{}' (expira en {} min).",
        user,
        host_id,
        remaining_secs / 60
    );

    Ok(())
}