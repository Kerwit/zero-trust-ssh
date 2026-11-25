use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const BINARY_NAME: &str = if cfg!(windows) {
    "ssh-usb-unlock.exe"
} else {
    "ssh-usb-unlock"
};

const BLOCK_START_PREFIX: &str = "# >>> zero-trust-ssh: ";
const BLOCK_START_SUFFIX: &str = " >>>";
const BLOCK_END_PREFIX: &str = "# <<< zero-trust-ssh: ";
const BLOCK_END_SUFFIX: &str = " <<<";

const PATH_MARKER_START: &str = "# >>> zero-trust-ssh PATH >>>";
const PATH_MARKER_END: &str = "# <<< zero-trust-ssh PATH <<<";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedHost {
    pub alias: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_id: String,
    pub generation: u32,
    pub exec_bin: String,
}

#[derive(Debug, Clone)]
pub struct InstallReport {
    pub installed_path: PathBuf,
    pub already_in_place: bool,
    pub path_updated: bool,
    pub path_notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct UninstallReport {
    pub removed_binary: bool,
    pub binary_path: PathBuf,
    pub path_cleaned: Vec<String>,
    pub deferred_windows_self_delete: bool,
}

/// Resuelve el directorio de configuración SSH canónico para el OS actual:
/// - Variable de entorno `ZT_SSH_DIR` (si está definida y no vacía).
/// - macOS / Linux: `$HOME/.ssh`
/// - Windows: `%USERPROFILE%\.ssh` (fallback `%HOMEDRIVE%%HOMEPATH%\.ssh`)
pub fn resolve_ssh_dir() -> Result<PathBuf, String> {
    if let Ok(custom) = env::var("ZT_SSH_DIR") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    let home = resolve_home_dir()?;
    Ok(home.join(".ssh"))
}

pub fn resolve_home_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Ok(profile) = env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }
        if let (Ok(drive), Ok(path)) = (env::var("HOMEDRIVE"), env::var("HOMEPATH")) {
            let combined = format!("{}{}", drive.trim(), path.trim());
            if !combined.is_empty() {
                return Ok(PathBuf::from(combined));
            }
        }
        if let Ok(home) = env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }
        Err("No se pudo determinar USERPROFILE/HOME en Windows.".to_string())
    }

    #[cfg(not(windows))]
    {
        if let Ok(home) = env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }
        Err("La variable de entorno HOME no está definida.".to_string())
    }
}

pub fn installed_binary_path() -> Result<PathBuf, String> {
    Ok(resolve_ssh_dir()?.join(BINARY_NAME))
}

pub fn default_username() -> String {
    for var in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(val) = env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "root".to_string()
}

pub fn ensure_ssh_dir(ssh_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(ssh_dir)
        .map_err(|e| format!("No se pudo crear directorio SSH '{}': {}", ssh_dir.display(), e))?;
    set_dir_perms(ssh_dir);
    Ok(())
}

#[cfg(unix)]
fn set_dir_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_perms(_path: &Path) {}

#[cfg(unix)]
pub fn set_private_file_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub fn set_private_file_perms(_path: &Path) {}

#[cfg(unix)]
pub fn set_executable_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
pub fn set_executable_perms(_path: &Path) {}

fn is_reserved_keyword(word: &str) -> bool {
    matches!(
        word,
        "link"
            | "setup"
            | "init"
            | "list"
            | "ls"
            | "unlink"
            | "remove"
            | "rm"
            | "test"
            | "install"
            | "uninstall"
            | "doctor"
            | "unlock"
            | "help"
            | "version"
    ) || word.starts_with('-')
}

/// Construye el comando dentro de `Match host ... exec "<cmd>"`.
/// Si la ruta al binario contiene espacios, se escapa de forma segura según el OS.
pub fn format_exec_command(bin_path: &str, host_id: &str, user: &str, generation: u32) -> String {
    let quoted_bin = if bin_path.contains(' ') {
        if cfg!(windows) {
            format!("\\\"{}\\\"", bin_path)
        } else {
            format!("'{}'", bin_path.replace('\'', "'\\''"))
        }
    } else {
        bin_path.to_string()
    };

    if is_reserved_keyword(host_id) {
        format!("{} unlock {} {} {}", quoted_bin, host_id, user, generation)
    } else {
        format!("{} {} {} {}", quoted_bin, host_id, user, generation)
    }
}

pub fn render_host_block(entry: &LinkedHost) -> String {
    let marker_start = format!("{}{}{}", BLOCK_START_PREFIX, entry.alias, BLOCK_START_SUFFIX);
    let marker_end = format!("{}{}{}", BLOCK_END_PREFIX, entry.alias, BLOCK_END_SUFFIX);

    let host_line = if entry.alias == entry.host {
        format!("Host {}", entry.alias)
    } else {
        format!("Host {} {}", entry.alias, entry.host)
    };

    let match_hosts = if entry.alias == entry.host {
        entry.alias.clone()
    } else {
        format!("{},{}", entry.alias, entry.host)
    };

    let exec_cmd = format_exec_command(
        &entry.exec_bin,
        &entry.host_id,
        &entry.user,
        entry.generation,
    );

    format!(
        "{marker_start}\n\
{host_line}\n\
    HostName {host}\n\
    Port {port}\n\
    User {user}\n\
\n\
Match host {match_hosts} exec \"{exec_cmd}\"\n\
{marker_end}\n",
        host = entry.host,
        port = entry.port,
        user = entry.user
    )
}

fn timestamp_slug() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Conversión civil UTC (algoritmo Howard Hinnant) sin dependencias externas
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        year, m, d, hour, min, sec
    )
}

fn strip_managed_block(content: &str, alias: &str) -> (String, bool) {
    let marker_start = format!("{}{}{}", BLOCK_START_PREFIX, alias, BLOCK_START_SUFFIX);
    let marker_end = format!("{}{}{}", BLOCK_END_PREFIX, alias, BLOCK_END_SUFFIX);

    let mut out_lines: Vec<&str> = Vec::new();
    let mut skipping = false;
    let mut found = false;

    for line in content.lines() {
        if !skipping && line == marker_start {
            skipping = true;
            found = true;
            // Evitar acumular líneas en blanco extra justo antes del bloque eliminado
            if matches!(out_lines.last(), Some(&"")) {
                out_lines.pop();
            }
            continue;
        }
        if skipping && line == marker_end {
            skipping = false;
            continue;
        }
        if !skipping {
            out_lines.push(line);
        }
    }

    let mut result = out_lines.join("\n");
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }
    (result, found)
}

fn create_config_backup(config_path: &Path) -> Result<Option<PathBuf>, String> {
    if !config_path.exists() {
        return Ok(None);
    }
    let backup_name = format!("config.bak.{}", timestamp_slug());
    let backup_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(backup_name);
    fs::copy(config_path, &backup_path).map_err(|e| {
        format!(
            "No se pudo crear backup de '{}': {}",
            config_path.display(),
            e
        )
    })?;
    set_private_file_perms(&backup_path);
    Ok(Some(backup_path))
}

/// Añade o actualiza de forma idempotente el bloque `# >>> zero-trust-ssh: <alias> >>>` en `<ssh_dir>/config`.
pub fn upsert_host_block(ssh_dir: &Path, entry: &LinkedHost) -> Result<Option<PathBuf>, String> {
    ensure_ssh_dir(ssh_dir)?;
    let config_path = ssh_dir.join("config");
    let backup = create_config_backup(&config_path)?;

    let existing = if config_path.exists() {
        fs::read_to_string(&config_path)
            .map_err(|e| format!("No se pudo leer '{}': {}", config_path.display(), e))?
    } else {
        String::new()
    };

    let (mut cleaned, _) = strip_managed_block(&existing, &entry.alias);
    if !cleaned.is_empty() && !cleaned.ends_with("\n\n") {
        if !cleaned.ends_with('\n') {
            cleaned.push('\n');
        }
        cleaned.push('\n');
    }
    cleaned.push_str(&render_host_block(entry));

    fs::write(&config_path, cleaned)
        .map_err(|e| format!("No se pudo escribir '{}': {}", config_path.display(), e))?;
    set_private_file_perms(&config_path);

    Ok(backup)
}

/// Elimina el bloque gestionado para `alias` en `<ssh_dir>/config`.
pub fn remove_host_block(ssh_dir: &Path, alias: &str) -> Result<(bool, Option<PathBuf>), String> {
    let config_path = ssh_dir.join("config");
    if !config_path.exists() {
        return Ok((false, None));
    }

    let existing = fs::read_to_string(&config_path)
        .map_err(|e| format!("No se pudo leer '{}': {}", config_path.display(), e))?;
    let (cleaned, found) = strip_managed_block(&existing, alias);
    if !found {
        return Ok((false, None));
    }

    let backup = create_config_backup(&config_path)?;
    fs::write(&config_path, cleaned)
        .map_err(|e| format!("No se pudo actualizar '{}': {}", config_path.display(), e))?;
    set_private_file_perms(&config_path);

    Ok((true, backup))
}

/// Parsea todos los bloques gestionados por `zero-trust-ssh` en `<ssh_dir>/config`.
pub fn list_host_blocks(ssh_dir: &Path) -> Result<Vec<LinkedHost>, String> {
    let config_path = ssh_dir.join("config");
    if !config_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("No se pudo leer '{}': {}", config_path.display(), e))?;

    let mut results = Vec::new();
    let mut current_alias: Option<String> = None;
    let mut host = String::new();
    let mut port: u16 = 22;
    let mut user = String::new();
    let mut host_id = String::new();
    let mut generation: u32 = 0;
    let mut exec_bin = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(BLOCK_START_PREFIX) {
            if let Some(alias) = rest.strip_suffix(BLOCK_START_SUFFIX) {
                current_alias = Some(alias.trim().to_string());
                host.clear();
                port = 22;
                user.clear();
                host_id.clear();
                generation = 0;
                exec_bin.clear();
                continue;
            }
        }

        if let Some(ref alias) = current_alias {
            let expected_end = format!("{}{}{}", BLOCK_END_PREFIX, alias, BLOCK_END_SUFFIX);
            if trimmed == expected_end {
                results.push(LinkedHost {
                    alias: alias.clone(),
                    host: if host.is_empty() {
                        alias.clone()
                    } else {
                        host.clone()
                    },
                    port,
                    user: user.clone(),
                    host_id: host_id.clone(),
                    generation,
                    exec_bin: exec_bin.clone(),
                });
                current_alias = None;
                continue;
            }

            if let Some(val) = strip_key_ci(trimmed, "HostName") {
                host = val.to_string();
            } else if let Some(val) = strip_key_ci(trimmed, "Port") {
                if let Ok(p) = val.parse::<u16>() {
                    port = p;
                }
            } else if let Some(val) = strip_key_ci(trimmed, "User") {
                user = val.to_string();
            } else if let Some(exec_inner) = extract_match_exec(trimmed) {
                let (bin, h_id, u, g) = parse_exec_args(exec_inner);
                if !bin.is_empty() {
                    exec_bin = bin;
                }
                if !h_id.is_empty() {
                    host_id = h_id;
                }
                if user.is_empty() && !u.is_empty() {
                    user = u;
                }
                generation = g;
            }
        }
    }

    Ok(results)
}

fn strip_key_ci<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut parts = line.splitn(2, char::is_whitespace);
    let k = parts.next()?;
    let v = parts.next()?.trim();
    if k.eq_ignore_ascii_case(key) && !v.is_empty() {
        Some(v)
    } else {
        None
    }
}

fn extract_match_exec(line: &str) -> Option<&str> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find(" exec ")?;
    let after = line[idx + 6..].trim();
    after.strip_prefix('"')?.strip_suffix('"')
}

fn parse_exec_args(exec_inner: &str) -> (String, String, String, u32) {
    // Soporta ruta entre comillas simples o escapadas al inicio: '<bin>' ... o \"<bin>\" ...
    let (bin, rest) = if let Some(after_q) = exec_inner.strip_prefix('\'') {
        if let Some(end) = after_q.find('\'') {
            (after_q[..end].to_string(), after_q[end + 1..].trim())
        } else {
            (exec_inner.to_string(), "")
        }
    } else if let Some(after_q) = exec_inner.strip_prefix("\\\"") {
        if let Some(end) = after_q.find("\\\"") {
            (after_q[..end].to_string(), after_q[end + 2..].trim())
        } else {
            (exec_inner.to_string(), "")
        }
    } else {
        let mut parts = exec_inner.splitn(2, char::is_whitespace);
        let b = parts.next().unwrap_or("").to_string();
        let r = parts.next().unwrap_or("").trim();
        (b, r)
    };

    let mut tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.first().copied() == Some("unlock") {
        tokens.remove(0);
    }

    let host_id = tokens.first().copied().unwrap_or("").to_string();
    let user = tokens.get(1).copied().unwrap_or("").to_string();
    let generation = tokens
        .get(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    (bin, host_id, user, generation)
}

/// Registra las huellas del servidor en `<ssh_dir>/known_hosts` mediante `ssh-keyscan`.
pub fn register_known_host(ssh_dir: &Path, host: &str, port: u16) -> Result<usize, String> {
    ensure_ssh_dir(ssh_dir)?;
    let known_hosts = ssh_dir.join("known_hosts");
    if !known_hosts.exists() {
        fs::write(&known_hosts, "")
            .map_err(|e| format!("No se pudo crear '{}': {}", known_hosts.display(), e))?;
        set_private_file_perms(&known_hosts);
    }

    let output = Command::new("ssh-keyscan")
        .args(["-p", &port.to_string(), "-H", host])
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("No se pudo ejecutar ssh-keyscan: {}", e))?;

    if !output.status.success() {
        return Ok(0);
    }

    let scanned = String::from_utf8_lossy(&output.stdout);
    let existing = fs::read_to_string(&known_hosts).unwrap_or_default();

    let mut to_add = Vec::new();
    for line in scanned.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Evitar duplicados exactos por clave pública (tercer campo)
        let pubkey_token = trimmed.split_whitespace().nth(2);
        let already_present = match pubkey_token {
            Some(tok) => existing.lines().any(|l| l.contains(tok)),
            None => existing.lines().any(|l| l.trim() == trimmed),
        };
        if !already_present {
            to_add.push(trimmed.to_string());
        }
    }

    if !to_add.is_empty() {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&known_hosts)
            .map_err(|e| format!("No se pudo abrir '{}': {}", known_hosts.display(), e))?;
        for line in &to_add {
            writeln!(file, "{}", line)
                .map_err(|e| format!("No se pudo escribir en known_hosts: {}", e))?;
        }
        set_private_file_perms(&known_hosts);
    }

    Ok(to_add.len())
}

/// Auto-instala el ejecutable actual en `<ssh_dir>/ssh-usb-unlock[.exe]` y opcionalmente lo añade al PATH.
pub fn self_install(no_path: bool) -> Result<InstallReport, String> {
    let ssh_dir = resolve_ssh_dir()?;
    ensure_ssh_dir(&ssh_dir)?;
    let target_path = ssh_dir.join(BINARY_NAME);

    let current_exe = env::current_exe()
        .map_err(|e| format!("No se pudo resolver la ruta del binario actual: {}", e))?;

    let same_file = match (fs::canonicalize(&current_exe), fs::canonicalize(&target_path)) {
        (Ok(a), Ok(b)) => a == b,
        _ => current_exe == target_path,
    };

    if !same_file {
        let tmp_name = format!(".ssh-usb-unlock.install.{}.tmp", std::process::id());
        let tmp_path = ssh_dir.join(tmp_name);
        fs::copy(&current_exe, &tmp_path).map_err(|e| {
            format!(
                "No se pudo copiar '{}' a '{}': {}",
                current_exe.display(),
                tmp_path.display(),
                e
            )
        })?;
        set_executable_perms(&tmp_path);

        #[cfg(windows)]
        {
            if target_path.exists() {
                let old_path = ssh_dir.join(format!(".ssh-usb-unlock.old.{}", std::process::id()));
                let _ = fs::remove_file(&old_path);
                let _ = fs::rename(&target_path, &old_path);
                if let Err(e) = fs::rename(&tmp_path, &target_path) {
                    let _ = fs::rename(&old_path, &target_path);
                    let _ = fs::remove_file(&tmp_path);
                    return Err(format!(
                        "No se pudo reemplazar '{}': {}",
                        target_path.display(),
                        e
                    ));
                }
                let _ = fs::remove_file(&old_path);
            } else {
                fs::rename(&tmp_path, &target_path).map_err(|e| {
                    let _ = fs::remove_file(&tmp_path);
                    format!("No se pudo instalar en '{}': {}", target_path.display(), e)
                })?;
            }
        }

        #[cfg(not(windows))]
        {
            fs::rename(&tmp_path, &target_path).map_err(|e| {
                let _ = fs::remove_file(&tmp_path);
                format!("No se pudo instalar en '{}': {}", target_path.display(), e)
            })?;
            set_executable_perms(&target_path);
        }
    } else {
        set_executable_perms(&target_path);
    }

    let mut path_updated = false;
    let mut path_notes = Vec::new();
    if !no_path {
        let (updated, notes) = ensure_dir_in_user_path(&ssh_dir)?;
        path_updated = updated;
        path_notes = notes;
    }

    Ok(InstallReport {
        installed_path: target_path,
        already_in_place: same_file,
        path_updated,
        path_notes,
    })
}

pub fn self_uninstall(keep_path: bool) -> Result<UninstallReport, String> {
    let ssh_dir = resolve_ssh_dir()?;
    let target_path = ssh_dir.join(BINARY_NAME);
    let current_exe = env::current_exe().ok();

    let running_from_target = current_exe
        .as_ref()
        .map(|cur| match (fs::canonicalize(cur), fs::canonicalize(&target_path)) {
            (Ok(a), Ok(b)) => a == b,
            _ => cur == &target_path,
        })
        .unwrap_or(false);

    let mut removed_binary = false;
    let mut deferred_windows_self_delete = false;

    if target_path.exists() {
        if cfg!(windows) && running_from_target {
            // En Windows no se puede eliminar un .exe en ejecución; lanzamos un borrado diferido.
            let target_str = target_path.to_string_lossy().to_string();
            let _ = Command::new("cmd")
                .args([
                    "/C",
                    &format!("ping 127.0.0.1 -n 2 > nul && del /F /Q \"{}\"", target_str),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            deferred_windows_self_delete = true;
            removed_binary = true;
        } else {
            fs::remove_file(&target_path).map_err(|e| {
                format!("No se pudo eliminar '{}': {}", target_path.display(), e)
            })?;
            removed_binary = true;
        }
    }

    let path_cleaned = if keep_path {
        Vec::new()
    } else {
        remove_dir_from_user_path(&ssh_dir)?
    };

    Ok(UninstallReport {
        removed_binary,
        binary_path: target_path,
        path_cleaned,
        deferred_windows_self_delete,
    })
}

pub fn is_dir_in_current_path(dir: &Path) -> bool {
    let Some(path_var) = env::var_os("PATH") else {
        return false;
    };
    let canon_target = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    for entry in env::split_paths(&path_var) {
        let canon_entry = fs::canonicalize(&entry).unwrap_or(entry);
        if cfg!(windows) {
            if canon_entry
                .to_string_lossy()
                .eq_ignore_ascii_case(&canon_target.to_string_lossy())
            {
                return true;
            }
        } else if canon_entry == canon_target {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn unix_rc_targets(home: &Path) -> Vec<(PathBuf, bool)> {
    // (ruta_rc, is_fish)
    fn push_unique(targets: &mut Vec<(PathBuf, bool)>, p: PathBuf, fish: bool) {
        if !targets.iter().any(|(existing, _)| existing == &p) {
            targets.push((p, fish));
        }
    }

    let shell = env::var("SHELL").unwrap_or_default();
    let mut targets: Vec<(PathBuf, bool)> = Vec::new();

    if shell.ends_with("zsh") || cfg!(target_os = "macos") {
        push_unique(&mut targets, home.join(".zshrc"), false);
    }
    if shell.ends_with("bash") || home.join(".bashrc").exists() {
        push_unique(&mut targets, home.join(".bashrc"), false);
    }
    if shell.ends_with("fish") || home.join(".config/fish/config.fish").exists() {
        push_unique(&mut targets, home.join(".config/fish/config.fish"), true);
    }
    if targets.is_empty() || home.join(".profile").exists() {
        push_unique(&mut targets, home.join(".profile"), false);
    }
    targets
}

#[cfg(unix)]
pub fn upsert_unix_rc_path(rc_path: &Path, ssh_dir: &Path, is_fish: bool) -> Result<bool, String> {
    if let Some(parent) = rc_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("No se pudo crear '{}': {}", parent.display(), e))?;
    }

    let existing = if rc_path.exists() {
        fs::read_to_string(rc_path)
            .map_err(|e| format!("No se pudo leer '{}': {}", rc_path.display(), e))?
    } else {
        String::new()
    };

    let dir_str = ssh_dir.to_string_lossy();
    let export_line = if is_fish {
        format!("fish_add_path -p \"{}\"", dir_str)
    } else {
        format!("export PATH=\"{}:$PATH\"", dir_str)
    };

    let block = format!(
        "{}\n{}\n{}\n",
        PATH_MARKER_START, export_line, PATH_MARKER_END
    );

    if existing.contains(PATH_MARKER_START) && existing.contains(&export_line) {
        return Ok(false);
    }

    let (mut cleaned, _) = strip_path_block(&existing);
    if !cleaned.is_empty() && !cleaned.ends_with('\n') {
        cleaned.push('\n');
    }
    if !cleaned.is_empty() && !cleaned.ends_with("\n\n") {
        cleaned.push('\n');
    }
    cleaned.push_str(&block);

    fs::write(rc_path, cleaned)
        .map_err(|e| format!("No se pudo actualizar '{}': {}", rc_path.display(), e))?;
    Ok(true)
}

#[cfg(unix)]
fn strip_path_block(content: &str) -> (String, bool) {
    let mut out = Vec::new();
    let mut skipping = false;
    let mut found = false;
    for line in content.lines() {
        if !skipping && line == PATH_MARKER_START {
            skipping = true;
            found = true;
            if matches!(out.last(), Some(&"")) {
                out.pop();
            }
            continue;
        }
        if skipping && line == PATH_MARKER_END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push(line);
        }
    }
    let mut res = out.join("\n");
    if !res.is_empty() && !res.ends_with('\n') {
        res.push('\n');
    }
    (res, found)
}

fn ensure_dir_in_user_path(ssh_dir: &Path) -> Result<(bool, Vec<String>), String> {
    #[cfg(unix)]
    {
        let home = resolve_home_dir()?;
        let mut any_updated = false;
        let mut notes = Vec::new();

        for (rc_path, is_fish) in unix_rc_targets(&home) {
            if upsert_unix_rc_path(&rc_path, ssh_dir, is_fish)? {
                any_updated = true;
                notes.push(format!("PATH actualizado en {}", rc_path.display()));
            } else {
                notes.push(format!("PATH ya configurado en {}", rc_path.display()));
            }
        }
        Ok((any_updated, notes))
    }

    #[cfg(windows)]
    {
        let dir_str = ssh_dir.to_string_lossy().to_string();
        let ps_script = r#"
$dir = $env:ZT_SSH_ADD_PATH
$current = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @()
if ($current) { $parts = $current -split ';' | Where-Object { $_ -ne '' } }
$exists = $false
foreach ($p in $parts) {
    if ($p.TrimEnd('\').ToLowerInvariant() -eq $dir.TrimEnd('\').ToLowerInvariant()) {
        $exists = $true
        break
    }
}
if (-not $exists) {
    $newPath = if ($parts.Count -gt 0) { ($parts + $dir) -join ';' } else { $dir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Output 'UPDATED'
} else {
    Write-Output 'EXISTS'
}
"#;
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
            .env("ZT_SSH_ADD_PATH", &dir_str)
            .output()
            .map_err(|e| format!("No se pudo invocar PowerShell para actualizar PATH: {}", e))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Error actualizando User PATH en Windows: {}", err.trim()));
        }

        let out = String::from_utf8_lossy(&output.stdout);
        if out.contains("UPDATED") {
            Ok((
                true,
                vec![format!("Añadido '{}' al PATH de usuario de Windows", dir_str)],
            ))
        } else {
            Ok((
                false,
                vec![format!("'{}' ya estaba en el PATH de usuario de Windows", dir_str)],
            ))
        }
    }
}

fn remove_dir_from_user_path(ssh_dir: &Path) -> Result<Vec<String>, String> {
    #[cfg(unix)]
    {
        let _ = ssh_dir;
        let home = resolve_home_dir()?;
        let mut cleaned = Vec::new();
        for (rc_path, _) in unix_rc_targets(&home) {
            if !rc_path.exists() {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&rc_path) {
                let (next, found) = strip_path_block(&content);
                if found {
                    fs::write(&rc_path, next).map_err(|e| {
                        format!("No se pudo limpiar '{}': {}", rc_path.display(), e)
                    })?;
                    cleaned.push(rc_path.display().to_string());
                }
            }
        }
        Ok(cleaned)
    }

    #[cfg(windows)]
    {
        let dir_str = ssh_dir.to_string_lossy().to_string();
        let ps_script = r#"
$dir = $env:ZT_SSH_RM_PATH.TrimEnd('\').ToLowerInvariant()
$current = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $current) { exit 0 }
$parts = $current -split ';' | Where-Object { $_ -ne '' }
$filtered = $parts | Where-Object { $_.TrimEnd('\').ToLowerInvariant() -ne $dir }
if ($filtered.Count -ne $parts.Count) {
    [Environment]::SetEnvironmentVariable('Path', ($filtered -join ';'), 'User')
    Write-Output 'REMOVED'
}
"#;
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
            .env("ZT_SSH_RM_PATH", &dir_str)
            .output()
            .map_err(|e| format!("No se pudo invocar PowerShell: {}", e))?;

        if output.status.success() && String::from_utf8_lossy(&output.stdout).contains("REMOVED") {
            Ok(vec!["Windows User PATH".to_string()])
        } else {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "zt-ssh-test-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_upsert_list_and_remove_idempotent() {
        let dir = temp_test_dir("config");
        let existing_cfg = "Host github.com\n    User git\n";
        fs::write(dir.join("config"), existing_cfg).unwrap();

        let entry1 = LinkedHost {
            alias: "lnode-server".to_string(),
            host: "192.168.1.33".to_string(),
            port: 2222,
            user: "lnode".to_string(),
            host_id: "lnode".to_string(),
            generation: 1,
            exec_bin: "/Users/alice/.ssh/ssh-usb-unlock".to_string(),
        };

        let backup1 = upsert_host_block(&dir, &entry1).unwrap();
        assert!(backup1.is_some());

        // Actualizar el mismo alias no debe duplicar bloques
        let mut entry1_updated = entry1.clone();
        entry1_updated.generation = 2;
        upsert_host_block(&dir, &entry1_updated).unwrap();

        let listed = list_host_blocks(&dir).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].alias, "lnode-server");
        assert_eq!(listed[0].host, "192.168.1.33");
        assert_eq!(listed[0].port, 2222);
        assert_eq!(listed[0].user, "lnode");
        assert_eq!(listed[0].host_id, "lnode");
        assert_eq!(listed[0].generation, 2);

        // Contenido previo del usuario sigue intacto
        let raw = fs::read_to_string(dir.join("config")).unwrap();
        assert!(raw.contains("Host github.com"));
        assert_eq!(raw.matches("# >>> zero-trust-ssh: lnode-server >>>").count(), 1);

        // Eliminar el bloque
        let (removed, _) = remove_host_block(&dir, "lnode-server").unwrap();
        assert!(removed);
        assert!(list_host_blocks(&dir).unwrap().is_empty());

        let raw_after = fs::read_to_string(dir.join("config")).unwrap();
        assert!(raw_after.contains("Host github.com"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_format_exec_command_handles_spaces_and_reserved_host_id() {
        let cmd_normal = format_exec_command("/Users/a/.ssh/ssh-usb-unlock", "lnode", "root", 1);
        assert_eq!(cmd_normal, "/Users/a/.ssh/ssh-usb-unlock lnode root 1");

        let cmd_reserved = format_exec_command("/Users/a/.ssh/ssh-usb-unlock", "link", "root", 1);
        assert_eq!(cmd_reserved, "/Users/a/.ssh/ssh-usb-unlock unlock link root 1");

        let cmd_spaces = format_exec_command("/Users/John Doe/.ssh/ssh-usb-unlock", "srv1", "admin", 3);
        if cfg!(windows) {
            assert_eq!(cmd_spaces, "\\\"/Users/John Doe/.ssh/ssh-usb-unlock\\\" srv1 admin 3");
        } else {
            assert_eq!(cmd_spaces, "'/Users/John Doe/.ssh/ssh-usb-unlock' srv1 admin 3");
        }
    }

    #[test]
    fn test_same_alias_and_host_avoids_duplicate_host_pattern() {
        let entry = LinkedHost {
            alias: "10.0.0.5".to_string(),
            host: "10.0.0.5".to_string(),
            port: 22,
            user: "ubuntu".to_string(),
            host_id: "prod".to_string(),
            generation: 0,
            exec_bin: "/home/u/.ssh/ssh-usb-unlock".to_string(),
        };
        let block = render_host_block(&entry);
        assert!(block.contains("Host 10.0.0.5\n"));
        assert!(block.contains("Match host 10.0.0.5 exec \"/home/u/.ssh/ssh-usb-unlock prod ubuntu 0\""));
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_rc_path_upsert_is_idempotent() {
        let dir = temp_test_dir("rc");
        let rc = dir.join(".zshrc");
        let ssh_dir = dir.join(".ssh");
        fs::write(&rc, "# existing config\n").unwrap();

        assert!(upsert_unix_rc_path(&rc, &ssh_dir, false).unwrap());
        assert!(!upsert_unix_rc_path(&rc, &ssh_dir, false).unwrap());

        let content = fs::read_to_string(&rc).unwrap();
        assert_eq!(content.matches(PATH_MARKER_START).count(), 1);
        assert!(content.contains(&ssh_dir.to_string_lossy().to_string()));

        let _ = fs::remove_dir_all(&dir);
    }
}
