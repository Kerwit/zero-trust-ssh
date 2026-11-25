use crate::ssh_config::{self, LinkedHost};
use crate::usb_tunnel;
use std::io::{self, Write};
use std::process::{Command, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Acciones devueltas por el despachador CLI.
pub enum CliAction {
    /// Subcomando CLI ya ejecutado.
    Handled,
    /// Invocación silenciosa de `Match exec` con argumentos `<host_id> <user> [generation]`.
    Unlock {
        host_id: String,
        user: String,
        generation: u32,
    },
}

pub fn dispatch(args: &[String]) -> Result<CliAction, String> {
    if args.len() <= 1 {
        print_help();
        return Ok(CliAction::Handled);
    }

    let first = args[1].as_str();
    match first {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(CliAction::Handled)
        }
        "-V" | "--version" | "version" => {
            println!(
                "ssh-usb-unlock {} ({}/{})",
                VERSION,
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(CliAction::Handled)
        }
        "install" => {
            cmd_install(&args[2..])?;
            Ok(CliAction::Handled)
        }
        "uninstall" => {
            cmd_uninstall(&args[2..])?;
            Ok(CliAction::Handled)
        }
        "link" | "setup" | "init" => {
            cmd_link(&args[2..])?;
            Ok(CliAction::Handled)
        }
        "list" | "ls" => {
            cmd_list()?;
            Ok(CliAction::Handled)
        }
        "unlink" | "remove" | "rm" => {
            if args.len() == 2 || args[2].starts_with('-') {
                cmd_unlink(&args[2..])?;
                return Ok(CliAction::Handled);
            }
            if args.len() == 3 {
                cmd_unlink(&args[2..])?;
                return Ok(CliAction::Handled);
            }
            parse_unlock_args(&args[1..])
        }
        "test" => {
            if args.len() <= 3 {
                cmd_test(&args[2..])?;
                return Ok(CliAction::Handled);
            }
            parse_unlock_args(&args[1..])
        }
        "doctor" => {
            cmd_doctor()?;
            Ok(CliAction::Handled)
        }
        "unlock" => parse_unlock_args(&args[2..]),
        _ if first.starts_with('-') => Err(format!(
            "Opción desconocida '{}'. Usa 'ssh-usb-unlock --help' para ver la ayuda.",
            first
        )),
        _ => parse_unlock_args(&args[1..]),
    }
}

fn parse_unlock_args(args: &[String]) -> Result<CliAction, String> {
    if args.len() < 2 {
        return Err(
            "Uso: ssh-usb-unlock <host_id> <user> [generation]  (o 'ssh-usb-unlock --help')"
                .to_string(),
        );
    }

    let host_id = args[0].trim().to_ascii_lowercase();
    let user = args[1].trim().to_string();
    let generation = args
        .get(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    Ok(CliAction::Unlock {
        host_id,
        user,
        generation,
    })
}

fn print_help() {
    let ssh_dir_hint = ssh_config::resolve_ssh_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "~/.ssh".to_string());

    println!(
        "\
ssh-usb-unlock {VERSION} — CLI multiplataforma Zero-Trust Stateless SSH (LittleKey)

USO:
  ssh-usb-unlock <comando> [opciones]
  ssh-usb-unlock <host_id> <user> [generation]    (modo silencioso para OpenSSH Match exec)

COMANDOS DE ORQUESTACIÓN Y VINCULACIÓN CON LA APP:
  link, setup     Vincula un servidor con LittleKey en {ssh_dir}/config y known_hosts
  list, ls        Lista los servidores vinculados con Zero-Trust SSH
  unlink <alias>  Elimina la configuración Zero-Trust SSH de un alias
  test <alias>    Activa adb forward y valida la conexión SSH E2E con LittleKey
  doctor          Verifica directorio SSH, PATH, adb, ssh-agent y hosts vinculados

COMANDOS DE AUTO-INSTALACIÓN:
  install         Instala este binario en {ssh_dir} y lo añade al PATH del usuario
  uninstall       Elimina el binario de {ssh_dir} y limpia la entrada de PATH
  unlock          Forma explícita del desbloqueo efímero (<host_id> <user> [generation])

OPCIONES DE 'link' (modo no interactivo o valores pre-rellenados):
  --host <HOST>         Host o IP del servidor remoto (ej. 192.168.1.33)
  --port <PUERTO>       Puerto SSH remoto [por defecto: 22]
  --alias <ALIAS>       Alias en ~/.ssh/config [por defecto: <host_id>-server]
  --host-id <HOST_ID>   host_id registrado en LittleKey (en minúsculas)
  --user <USUARIO>      Usuario SSH registrado en LittleKey
  --generation <N>      Número de generación en LittleKey [por defecto: 1]
  --bin <RUTA>          Ruta al binario para Match exec [por defecto: binario en {ssh_dir}]
  --skip-keyscan        No registrar huella del servidor en known_hosts
  --skip-test           No ofrecer/ejecutar la validación E2E al terminar
  -y, --no-interactive  No preguntar interactivamente (usa flags y defaults)

OPCIONES DE 'install' / 'uninstall':
  --no-path             (install) Instala solo en {ssh_dir} sin modificar PATH
  --keep-path           (uninstall) Conserva la entrada de PATH
",
        VERSION = VERSION,
        ssh_dir = ssh_dir_hint
    );
}

fn cmd_install(args: &[String]) -> Result<(), String> {
    let mut no_path = false;
    for arg in args {
        match arg.as_str() {
            "--no-path" => no_path = true,
            "-h" | "--help" => {
                println!("Uso: ssh-usb-unlock install [--no-path]");
                return Ok(());
            }
            other => return Err(format!("Opción desconocida para 'install': {}", other)),
        }
    }

    let report = ssh_config::self_install(no_path)?;
    if report.already_in_place {
        println!(
            "✅ ssh-usb-unlock ya estaba instalado en {}",
            report.installed_path.display()
        );
    } else {
        println!(
            "✅ ssh-usb-unlock instalado en {}",
            report.installed_path.display()
        );
    }

    for note in &report.path_notes {
        println!("   -> {}", note);
    }

    if report.path_updated {
        if cfg!(windows) {
            println!("ℹ️  Abre una nueva terminal (PowerShell/CMD) para usar 'ssh-usb-unlock' directamente.");
        } else {
            println!("ℹ️  Recarga tu shell (o abre una nueva terminal) para usar 'ssh-usb-unlock' directamente.");
        }
    }
    println!("\nSiguiente paso para vincular un servidor con LittleKey:");
    println!("  ssh-usb-unlock link");
    Ok(())
}

fn cmd_uninstall(args: &[String]) -> Result<(), String> {
    let mut keep_path = false;
    for arg in args {
        match arg.as_str() {
            "--keep-path" => keep_path = true,
            "-h" | "--help" => {
                println!("Uso: ssh-usb-unlock uninstall [--keep-path]");
                return Ok(());
            }
            other => return Err(format!("Opción desconocida para 'uninstall': {}", other)),
        }
    }

    let report = ssh_config::self_uninstall(keep_path)?;
    if report.removed_binary {
        if report.deferred_windows_self_delete {
            println!(
                "✅ Eliminación programada para {} al salir del proceso.",
                report.binary_path.display()
            );
        } else {
            println!("✅ Binario eliminado: {}", report.binary_path.display());
        }
    } else {
        println!(
            "ℹ️  No se encontró binario instalado en {}",
            report.binary_path.display()
        );
    }

    for cleaned in &report.path_cleaned {
        println!("   -> PATH limpiado en {}", cleaned);
    }
    println!("ℹ️  Los bloques en tu configuración SSH se conservan; usa 'unlink <alias>' si deseas borrarlos.");
    Ok(())
}

#[derive(Default)]
struct LinkOpts {
    host: Option<String>,
    port: Option<u16>,
    alias: Option<String>,
    host_id: Option<String>,
    user: Option<String>,
    generation: Option<u32>,
    bin: Option<String>,
    skip_keyscan: bool,
    skip_test: bool,
    no_interactive: bool,
}

fn parse_link_opts(args: &[String]) -> Result<Option<LinkOpts>, String> {
    let mut opts = LinkOpts::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "--host" => {
                i += 1;
                opts.host = Some(require_arg(args, i, "--host")?);
            }
            "--port" => {
                i += 1;
                let raw = require_arg(args, i, "--port")?;
                let port = raw
                    .parse::<u16>()
                    .map_err(|_| format!("Puerto inválido: '{}'", raw))?;
                if port == 0 {
                    return Err("El puerto debe estar entre 1 y 65535.".to_string());
                }
                opts.port = Some(port);
            }
            "--alias" => {
                i += 1;
                opts.alias = Some(require_arg(args, i, "--alias")?);
            }
            "--host-id" => {
                i += 1;
                opts.host_id = Some(normalize_host_id(&require_arg(args, i, "--host-id")?));
            }
            "--user" => {
                i += 1;
                opts.user = Some(require_arg(args, i, "--user")?);
            }
            "--generation" => {
                i += 1;
                let raw = require_arg(args, i, "--generation")?;
                let gen = raw
                    .parse::<u32>()
                    .map_err(|_| format!("Generación inválida (debe ser entero >= 0): '{}'", raw))?;
                opts.generation = Some(gen);
            }
            "--bin" => {
                i += 1;
                opts.bin = Some(require_arg(args, i, "--bin")?);
            }
            "--skip-keyscan" => opts.skip_keyscan = true,
            "--skip-test" => opts.skip_test = true,
            "-y" | "--no-interactive" => opts.no_interactive = true,
            other => return Err(format!("Opción desconocida para 'link': {}", other)),
        }
        i += 1;
    }
    Ok(Some(opts))
}

fn require_arg(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("La opción '{}' requiere un valor.", flag))
}

fn normalize_host_id(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn cmd_link(args: &[String]) -> Result<(), String> {
    let Some(opts) = parse_link_opts(args)? else {
        return Ok(());
    };

    let ssh_dir = ssh_config::resolve_ssh_dir()?;
    let installed_bin = ssh_config::installed_binary_path()?;

    println!("══════════════════════════════════════════════════════════════");
    println!("  Vinculación Zero-Trust Stateless SSH con LittleKey");
    println!("══════════════════════════════════════════════════════════════");

    // Asegurar que el binario exista en el directorio SSH (auto-instalación si el usuario acepta)
    let unlock_bin = if let Some(custom_bin) = opts.bin {
        custom_bin
    } else if installed_bin.exists() {
        installed_bin.to_string_lossy().to_string()
    } else if !opts.no_interactive
        && confirm_yn(
            &format!(
                "El binario aún no está instalado en '{}'. ¿Instalarlo ahora ahí?",
                installed_bin.display()
            ),
            true,
        )?
    {
        let report = ssh_config::self_install(false)?;
        println!("✅ Instalado en {}", report.installed_path.display());
        for note in &report.path_notes {
            println!("   -> {}", note);
        }
        report.installed_path.to_string_lossy().to_string()
    } else {
        std::env::current_exe()
            .unwrap_or(installed_bin)
            .to_string_lossy()
            .to_string()
    };

    let host = match opts.host {
        Some(h) => h.replace(char::is_whitespace, ""),
        None if opts.no_interactive => {
            return Err("En modo --no-interactive debes indicar --host <HOST_O_IP>.".to_string());
        }
        None => prompt_required("Host o IP del servidor remoto (ej. 192.168.1.33)")?
            .replace(char::is_whitespace, ""),
    };

    let port = match opts.port {
        Some(p) => p,
        None if opts.no_interactive => 22,
        None => prompt_port(22)?,
    };

    let default_host_id = normalize_host_id(host.split('.').next().unwrap_or(&host));
    let host_id = match opts.host_id {
        Some(h) if !h.is_empty() => h,
        _ if opts.no_interactive => {
            if default_host_id.is_empty() {
                return Err("Debes indicar --host-id en modo --no-interactive.".to_string());
            }
            default_host_id
        }
        _ => {
            let raw = prompt_with_default(
                "host_id registrado en LittleKey (cat /etc/hostname en el servidor)",
                &default_host_id,
            )?;
            let norm = normalize_host_id(&raw);
            if norm.is_empty() {
                return Err("host_id no puede estar vacío.".to_string());
            }
            norm
        }
    };

    let default_alias = format!("{}-server", host_id);
    let alias = match opts.alias {
        Some(a) => a.replace(char::is_whitespace, ""),
        None if opts.no_interactive => default_alias,
        None => prompt_with_default("Alias para ~/.ssh/config", &default_alias)?
            .replace(char::is_whitespace, ""),
    };

    let default_user = ssh_config::default_username();
    let user = match opts.user {
        Some(u) => u,
        None if opts.no_interactive => default_user,
        None => prompt_with_default("Usuario SSH configurado en LittleKey", &default_user)?,
    };

    let generation = match opts.generation {
        Some(g) => g,
        None if opts.no_interactive => 1,
        None => prompt_generation(1)?,
    };

    // 1. Registrar huella en known_hosts
    if !opts.skip_keyscan {
        println!(
            "🔎 Registrando huella de {}:{} en {}/known_hosts...",
            host,
            port,
            ssh_dir.display()
        );
        match ssh_config::register_known_host(&ssh_dir, &host, port) {
            Ok(0) => println!("   -> Sin claves nuevas que añadir (ya registrada o host no accesible)."),
            Ok(n) => println!("   -> {} clave(s) añadida(s) a known_hosts.", n),
            Err(e) => println!("   ⚠️  {} (puedes aceptar la huella al conectar).", e),
        }
    }

    // 2. Actualizar config SSH de forma idempotente (con backup)
    let entry = LinkedHost {
        alias: alias.clone(),
        host: host.clone(),
        port,
        user: user.clone(),
        host_id: host_id.clone(),
        generation,
        exec_bin: unlock_bin,
    };

    let backup = ssh_config::upsert_host_block(&ssh_dir, &entry)?;
    if let Some(bak) = backup {
        println!("💾 Backup creado en {}", bak.display());
    }
    println!(
        "✅ Bloque Zero-Trust SSH guardado en {}/config para '{}' ({}:{}, host_id='{}', user='{}', gen={}).",
        ssh_dir.display(),
        alias,
        host,
        port,
        host_id,
        user,
        generation
    );

    // 3. Preparar adb forward
    match usb_tunnel::try_adb_forward() {
        Ok(adb_bin) => println!("🔌 Túnel USB ADB activo en 127.0.0.1:9422 ({}).", adb_bin),
        Err(msg) => println!("⚠️  {}", msg),
    }

    // 4. Ofrecer validación E2E
    if !opts.skip_test && !opts.no_interactive {
        println!("\nConecta tu móvil por USB, abre LittleKey y desbloquea la bóveda antes de probar.");
        if confirm_yn(
            &format!(
                "¿Ejecutar ahora la validación E2E contra '{}' usando LittleKey?",
                alias
            ),
            true,
        )? {
            run_e2e_test(&alias, Some(&host_id))?;
        } else {
            println!("Puedes probar manualmente con: ssh {} \"uptime\"", alias);
        }
    }

    Ok(())
}

fn cmd_list() -> Result<(), String> {
    let ssh_dir = ssh_config::resolve_ssh_dir()?;
    let hosts = ssh_config::list_host_blocks(&ssh_dir)?;

    if hosts.is_empty() {
        println!(
            "No hay servidores vinculados con Zero-Trust SSH en {}/config.",
            ssh_dir.display()
        );
        println!("Usa 'ssh-usb-unlock link' para vincular el primero.");
        return Ok(());
    }

    println!(
        "{:<22} {:<24} {:<14} {:<16} {:<5}",
        "ALIAS", "HOST:PORT", "USER", "HOST_ID", "GEN"
    );
    println!("{}", "-".repeat(85));
    for h in hosts {
        let endpoint = format!("{}:{}", h.host, h.port);
        println!(
            "{:<22} {:<24} {:<14} {:<16} {:<5}",
            h.alias, endpoint, h.user, h.host_id, h.generation
        );
    }
    Ok(())
}

fn cmd_unlink(args: &[String]) -> Result<(), String> {
    let Some(alias) = args.first().filter(|a| !a.starts_with('-')) else {
        return Err("Uso: ssh-usb-unlock unlink <alias>".to_string());
    };
    let ssh_dir = ssh_config::resolve_ssh_dir()?;
    let (removed, backup) = ssh_config::remove_host_block(&ssh_dir, alias)?;
    if removed {
        if let Some(bak) = backup {
            println!("💾 Backup creado en {}", bak.display());
        }
        println!(
            "✅ Alias '{}' eliminado de {}/config.",
            alias,
            ssh_dir.display()
        );
    } else {
        println!(
            "ℹ️  No se encontró ningún bloque gestionado para '{}' en {}/config.",
            alias,
            ssh_dir.display()
        );
    }
    Ok(())
}

fn cmd_test(args: &[String]) -> Result<(), String> {
    let Some(alias) = args.first().filter(|a| !a.starts_with('-')) else {
        return Err("Uso: ssh-usb-unlock test <alias>".to_string());
    };
    match usb_tunnel::try_adb_forward() {
        Ok(adb_bin) => println!("🔌 Túnel USB ADB activo en 127.0.0.1:9422 ({}).", adb_bin),
        Err(msg) => println!("⚠️  {}", msg),
    }
    run_e2e_test(alias, None)
}

fn run_e2e_test(alias: &str, host_id_filter: Option<&str>) -> Result<(), String> {
    println!("🧪 Probando conexión Zero-Trust contra '{}'...", alias);
    let status = Command::new("ssh")
        .args([
            "-o",
            "ControlPath=none",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=25",
            alias,
            "printf '✅ Acceso Zero-Trust SSH validado en %s\\n' \"$(hostname)\"",
        ])
        .status()
        .map_err(|e| format!("No se pudo ejecutar 'ssh': {}", e))?;

    if status.success() {
        println!("✅ ¡Validación E2E completada con éxito!");
        if let Ok(out) = Command::new("ssh-add").arg("-l").output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let needle = host_id_filter
                    .map(|h| format!("trezor-epoch:{}", h))
                    .unwrap_or_else(|| "trezor-epoch:".to_string());
                let matched: Vec<&str> = text.lines().filter(|l| l.contains(&needle)).collect();
                if !matched.is_empty() {
                    println!("🔑 Claves efímeras activas en ssh-agent:");
                    for line in matched {
                        println!("   {}", line);
                    }
                }
            }
        }
        Ok(())
    } else {
        Err(format!(
            "La validación E2E contra '{}' falló. Revisa que LittleKey tenga registrados los mismos host_id, user, generation y SERVER_MASTER_HEX.",
            alias
        ))
    }
}

fn cmd_doctor() -> Result<(), String> {
    let ssh_dir = ssh_config::resolve_ssh_dir()?;
    let installed_bin = ssh_config::installed_binary_path()?;
    let in_path = ssh_config::is_dir_in_current_path(&ssh_dir);
    let hosts = ssh_config::list_host_blocks(&ssh_dir).unwrap_or_default();

    println!(
        "🩺 Diagnóstico Zero-Trust SSH (v{} · {}/{})",
        VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("   Directorio SSH : {}", ssh_dir.display());
    println!(
        "   Binario SSH    : {} ({})",
        installed_bin.display(),
        if installed_bin.exists() {
            "OK"
        } else {
            "NO INSTALADO — ejecuta 'ssh-usb-unlock install'"
        }
    );
    println!(
        "   En PATH actual : {}",
        if in_path { "Sí" } else { "No (reinicia tu terminal o ejecuta 'install')" }
    );
    println!("   ssh            : {}", check_command_status("ssh", &["-V"]));
    println!(
        "   ssh-agent      : {}",
        check_ssh_agent_status()
    );
    println!(
        "   ssh-keyscan    : {}",
        check_command_exists("ssh-keyscan")
    );
    println!(
        "   ADB túnel USB  : {}",
        match usb_tunnel::try_adb_forward() {
            Ok(b) => format!("OK ({})", b),
            Err(e) => e,
        }
    );
    println!("   Hosts LittleKey: {} configurado(s)", hosts.len());
    Ok(())
}

fn check_command_status(cmd: &str, args: &[&str]) -> String {
    match Command::new(cmd).args(args).output() {
        Ok(out) => {
            let combined = if out.stdout.is_empty() {
                String::from_utf8_lossy(&out.stderr).trim().to_string()
            } else {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            };
            let first_line = combined.lines().next().unwrap_or("disponible");
            format!("OK ({})", first_line)
        }
        Err(_) => "NO ENCONTRADO".to_string(),
    }
}

fn check_command_exists(cmd: &str) -> String {
    match Command::new(cmd)
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(_) => "OK".to_string(),
        Err(_) => "NO ENCONTRADO".to_string(),
    }
}

fn check_ssh_agent_status() -> String {
    match Command::new("ssh-add").arg("-l").output() {
        Ok(out) if out.status.success() => {
            let count = String::from_utf8_lossy(&out.stdout).lines().count();
            format!("OK ({} identidad(es) cargada(s))", count)
        }
        Ok(out) if out.status.code() == Some(1) => "OK (activo, sin identidades cargadas)".to_string(),
        Ok(out) => format!(
            "NO DISPONIBLE ({})",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(_) => "ssh-add NO ENCONTRADO".to_string(),
    }
}

fn prompt_line(label: &str) -> Result<String, String> {
    print!("{}", label);
    io::stdout()
        .flush()
        .map_err(|e| format!("Error de E/S en stdout: {}", e))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Error leyendo entrada del usuario: {}", e))?;
    Ok(input.trim().to_string())
}

fn prompt_required(label: &str) -> Result<String, String> {
    loop {
        let val = prompt_line(&format!("{}: ", label))?;
        if !val.is_empty() {
            return Ok(val);
        }
        println!("⚠️  Este valor no puede estar vacío.");
    }
}

fn prompt_with_default(label: &str, default: &str) -> Result<String, String> {
    let val = prompt_line(&format!("{} [{}]: ", label, default))?;
    if val.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(val)
    }
}

fn prompt_port(default: u16) -> Result<u16, String> {
    loop {
        let val = prompt_with_default("Puerto SSH remoto", &default.to_string())?;
        if let Ok(port) = val.parse::<u16>() {
            if port >= 1 {
                return Ok(port);
            }
        }
        println!("⚠️  Puerto inválido. Introduce un número entre 1 y 65535.");
    }
}

fn prompt_generation(default: u32) -> Result<u32, String> {
    loop {
        let val = prompt_with_default(
            "Número de generación (generation) en LittleKey",
            &default.to_string(),
        )?;
        if let Ok(gen) = val.parse::<u32>() {
            return Ok(gen);
        }
        println!("⚠️  La generación debe ser un entero >= 0 (ej. 0 o 1).");
    }
}

fn confirm_yn(question: &str, default_yes: bool) -> Result<bool, String> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    loop {
        let ans = prompt_line(&format!("{} [{}]: ", question, hint))?;
        if ans.is_empty() {
            return Ok(default_yes);
        }
        match ans.to_ascii_lowercase().as_str() {
            "y" | "yes" | "s" | "si" | "sí" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("⚠️  Responde 'y' o 'n'."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_preserves_positional_match_exec() {
        let args: Vec<String> = vec![
            "ssh-usb-unlock".into(),
            "lnode".into(),
            "root".into(),
            "1".into(),
        ];
        match dispatch(&args).unwrap() {
            CliAction::Unlock {
                host_id,
                user,
                generation,
            } => {
                assert_eq!(host_id, "lnode");
                assert_eq!(user, "root");
                assert_eq!(generation, 1);
            }
            CliAction::Handled => panic!("expected Unlock action"),
        }
    }

    #[test]
    fn test_dispatch_explicit_unlock_subcommand() {
        let args: Vec<String> = vec![
            "ssh-usb-unlock".into(),
            "unlock".into(),
            "Link".into(),
            "admin".into(),
            "2".into(),
        ];
        match dispatch(&args).unwrap() {
            CliAction::Unlock {
                host_id,
                user,
                generation,
            } => {
                assert_eq!(host_id, "link");
                assert_eq!(user, "admin");
                assert_eq!(generation, 2);
            }
            CliAction::Handled => panic!("expected Unlock action"),
        }
    }

    #[test]
    fn test_parse_link_opts_non_interactive() {
        let args: Vec<String> = vec![
            "--host".into(),
            "192.168.1.33".into(),
            "--port".into(),
            "2222".into(),
            "--alias".into(),
            "lnode-server".into(),
            "--host-id".into(),
            "LNode ".into(),
            "--user".into(),
            "lnode".into(),
            "--generation".into(),
            "3".into(),
            "--skip-keyscan".into(),
            "--skip-test".into(),
            "--no-interactive".into(),
        ];
        let opts = parse_link_opts(&args).unwrap().unwrap();
        assert_eq!(opts.host.as_deref(), Some("192.168.1.33"));
        assert_eq!(opts.port, Some(2222));
        assert_eq!(opts.alias.as_deref(), Some("lnode-server"));
        assert_eq!(opts.host_id.as_deref(), Some("lnode"));
        assert_eq!(opts.user.as_deref(), Some("lnode"));
        assert_eq!(opts.generation, Some(3));
        assert!(opts.skip_keyscan);
        assert!(opts.skip_test);
        assert!(opts.no_interactive);
    }
}
