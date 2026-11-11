use crate::locked_memory::LockedBuffer;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

const ENCLAVE_ADDR: &str = "127.0.0.1:9422";
const TUNNEL_SALT: &[u8] = b"USB-TUNNEL-SALT-V1";
const TUNNEL_INFO: &[u8] = b"CHACHA20POLY1305-SESSION-KEY";

/// Prepara el reenvío de puertos por cable USB (silencioso para no ensuciar stdout de OpenSSH)
fn ensure_usb_port_forward() {
    let mut candidates = vec!["adb".to_string()];
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!("{}/Library/Android/sdk/platform-tools/adb", home));
    }
    for candidate in candidates {
        if let Ok(status) = Command::new(&candidate)
            .args(["forward", "tcp:9422", "tcp:9422"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            if status.success() {
                break;
            }
        }
    }
}

/// Solicita al Enclave Móvil por cable USB los 32 bytes de `EphemeralSeed` para la hora actual
pub fn request_ephemeral_seed_over_usb(
    host_id: &str,
    user: &str,
    generation: u32,
    epoch: u64,
) -> Result<LockedBuffer<32>, String> {
    ensure_usb_port_forward();

    let mut stream = TcpStream::connect(ENCLAVE_ADDR).map_err(|e| {
        format!(
            "No se detectó el Enclave Móvil en {} (conecta el cable USB y abre la app): {}",
            ENCLAVE_ADDR, e
        )
    })?;

    // 60 segundos de margen para aceptar el diálogo y poner la huella en el móvil
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;

    // 1. Handshake ECDH Efímero (X25519)
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = X25519PublicKey::from(&client_secret);

    stream
        .write_all(client_pub.as_bytes())
        .map_err(|e| format!("Error enviando pubkey X25519 por USB: {}", e))?;

    let mut mobile_pub_bytes = [0u8; 32];
    stream
        .read_exact(&mut mobile_pub_bytes)
        .map_err(|e| format!("Error leyendo pubkey X25519 del móvil: {}", e))?;
    let mobile_pub = X25519PublicKey::from(mobile_pub_bytes);

    let shared_secret = client_secret.diffie_hellman(&mobile_pub);

    // 2. Derivar clave de sesión AEAD con HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(Some(TUNNEL_SALT), shared_secret.as_bytes());
    let mut session_key = Zeroizing::new([0u8; 32]);
    hk.expand(TUNNEL_INFO, &mut *session_key)
        .map_err(|_| "Fallo al expandir HKDF de sesión USB".to_string())?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*session_key));

    // 3. Cifrar solicitud: "SSH:<host_id>:<user>:<generation>:<epoch>"
    let request_str = format!("SSH:{}:{}:{}:{}", host_id, user, generation, epoch);
    let mut req_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut req_nonce_bytes);
    let req_nonce = Nonce::from_slice(&req_nonce_bytes);

    let ciphertext = cipher
        .encrypt(req_nonce, request_str.as_bytes())
        .map_err(|_| "Fallo al cifrar solicitud USB".to_string())?;

    let len_be = (ciphertext.len() as u16).to_be_bytes();
    stream
        .write_all(&req_nonce_bytes)
        .map_err(|e| e.to_string())?;
    stream.write_all(&len_be).map_err(|e| e.to_string())?;
    stream.write_all(&ciphertext).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    eprintln!(
        "📱 [Zero-Trust SSH] Confirma en tu móvil el acceso para '{}@{}' (Epoch #{})...",
        user, host_id, epoch
    );

    // 4. Recibir y descifrar respuesta: [Nonce 12B][Len u16 BE][Ciphertext]
    let mut resp_nonce_bytes = [0u8; 12];
    stream.read_exact(&mut resp_nonce_bytes).map_err(|_| {
        "Conexión cerrada por el móvil (¿Solicitud rechazada o tiempo agotado?)".to_string()
    })?;

    let mut resp_len_bytes = [0u8; 2];
    stream
        .read_exact(&mut resp_len_bytes)
        .map_err(|e| e.to_string())?;
    let resp_len = u16::from_be_bytes(resp_len_bytes) as usize;

    if resp_len > 1024 {
        return Err("Respuesta del móvil excede el tamaño máximo permitido".to_string());
    }

    let mut resp_ciphertext = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_ciphertext)
        .map_err(|e| e.to_string())?;

    let resp_nonce = Nonce::from_slice(&resp_nonce_bytes);
    let decrypted = Zeroizing::new(
        cipher
            .decrypt(resp_nonce, resp_ciphertext.as_ref())
            .map_err(|_| "Fallo de autenticación AEAD en respuesta del móvil".to_string())?,
    );

    // Si el móvil devolvió un error textual (ej. "ERR:Host not registered" o "ERR:Biometric canceled")
    if decrypted.starts_with(b"ERR:") {
        let msg = String::from_utf8_lossy(&decrypted);
        return Err(format!("El Enclave Móvil denegó la solicitud: {}", msg));
    }

    if decrypted.len() != 32 {
        return Err(format!(
            "Se esperaban exactamente 32 bytes de semilla efímera, recibidos {}",
            decrypted.len()
        ));
    }

    let mut locked_seed = LockedBuffer::<32>::new();
    locked_seed.copy_from_slice(&decrypted);
    Ok(locked_seed)
}