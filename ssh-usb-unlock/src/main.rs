mod agent_sync;
mod locked_memory;
mod usb_tunnel;

use std::env;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const EPOCH_DURATION_SECS: u64 = 3600;

fn run() -> Result<(), String> {
    locked_memory::harden_process();

    // Uso desde ~/.ssh/config:
    // Match host rasphouse,ionos-* exec "/usr/local/bin/ssh-usb-unlock %n %r 0"
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return Err(format!(
            "Uso: {} <host_id> <user> [generation]",
            args.first().map(|s| s.as_str()).unwrap_or("ssh-usb-unlock")
        ));
    }

    let host_id = args[1].trim().to_ascii_lowercase();
    let user = args[2].trim();
    let generation: u32 = args
        .get(3)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "El reloj del sistema es anterior a UNIX_EPOCH".to_string())?
        .as_secs();
    let current_epoch = now_secs / EPOCH_DURATION_SECS;

    // 1. Comprobar en < 1ms si la clave de esta hora ya está en el ssh-agent
    if agent_sync::sync_agent_epochs(&host_id, user, current_epoch)? {
        return Ok(());
    }

    // 2. Si no está cargada, solicitar los 32 bytes de esta hora al Enclave Móvil por USB
    let locked_seed =
        usb_tunnel::request_ephemeral_seed_over_usb(&host_id, user, generation, current_epoch)?;

    // 3. Construir la clave en RAM e inyectarla al ssh-agent con TTL hasta fin de hora
    agent_sync::inject_ephemeral_key_to_agent(
        &locked_seed,
        &host_id,
        user,
        current_epoch,
        now_secs,
    )?;

    Ok(())
}

fn main() {
    // IMPORTANTE: Nunca imprimir nada por stdout; OpenSSH Match exec requiere stdout limpio.
    if let Err(err) = run() {
        eprintln!("❌ [Zero-Trust SSH] {}", err);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locked_memory::LockedBuffer;
    use ssh_key::{
        private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData},
        PrivateKey,
    };

    #[test]
    fn test_locked_buffer_and_openssh_keypair_generation() {
        let mut seed = LockedBuffer::<32>::new();
        seed.copy_from_slice(&[0x55u8; 32]);

        let ed_priv = Ed25519PrivateKey::from_bytes(&*seed);
        let keypair = Ed25519Keypair::from(ed_priv);
        let priv_key =
            PrivateKey::new(KeypairData::Ed25519(keypair), "trezor-epoch:rasphouse:root:498410")
                .unwrap();

        let pub_openssh = priv_key.public_key().to_openssh().unwrap();
        assert!(pub_openssh.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(pub_openssh.ends_with("trezor-epoch:rasphouse:root:498410"));
    }
}