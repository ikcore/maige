use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::process::Command;

use crate::cli::*;
use crate::prompt;
use crate::resolver;
use crate::store;

pub fn run_command(cmd: Commands, passphrase: Option<String>) -> Result<()> {
    match cmd {
        Commands::Init => cmd_init(),
        Commands::Realm(sub) => cmd_realm(sub, &passphrase),
        Commands::Var(sub) => cmd_var(sub, &passphrase),
        Commands::Run { realm, cmd } => cmd_run(realm, cmd, &passphrase),
        Commands::Shell { realm } => cmd_shell(realm, &passphrase),
        Commands::Import { file, realm } => cmd_import(file, realm, &passphrase),
        Commands::Convert { file, realm, delete } => cmd_convert(file, realm, delete, &passphrase),
        Commands::Export { realm, json } => cmd_export(realm, json, &passphrase),
        Commands::Check => cmd_check(&passphrase),
        Commands::Diff { realm1, realm2 } => cmd_diff(realm1, realm2, &passphrase),
        Commands::KeyRotate => cmd_key_rotate(&passphrase),
    }
}

fn require_init() -> Result<()> {
    if !store::is_initialized()? {
        bail!("Maige is not initialized. Run `maige init` first.");
    }
    Ok(())
}

/// Resolves the passphrase from: flag/env var (pre-supplied) > interactive prompt.
fn get_passphrase(pre_supplied: &Option<String>) -> Result<String> {
    let pass = match pre_supplied {
        Some(p) => p.clone(),
        None => prompt::prompt_passphrase("Enter passphrase")?,
    };
    if !store::verify_passphrase(&pass)? {
        bail!("Incorrect passphrase.");
    }
    Ok(pass)
}

// --- Init ---

fn cmd_init() -> Result<()> {
    if store::is_initialized()? {
        println!("Maige is already initialized at {}", store::maige_dir()?.display());
        return Ok(());
    }

    println!("Welcome to Maige! Let's set up your secret store.\n");
    let passphrase = prompt::prompt_new_passphrase("Choose a master passphrase")?;
    store::initialize(&passphrase)?;
    println!("\nMaige initialized at {}", store::maige_dir()?.display());
    println!("Your secrets will be encrypted with your master passphrase.");
    println!("\nGet started:");
    println!("  maige realm create <name>    Create your first realm");
    println!("  maige var set <key> <value> --realm <name>   Add a variable");
    Ok(())
}

// --- Realm ---

fn cmd_realm(sub: RealmCommands, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;
    match sub {
        RealmCommands::List => {
            let realms = store::list_realms()?;
            if realms.is_empty() {
                println!("No realms found. Create one with `maige realm create <name>`");
            } else {
                println!("Realms:");
                for name in &realms {
                    println!("  {}", name);
                }
            }
        }
        RealmCommands::Create { name } => {
            let name = prompt::prompt_realm_name(name)?;
            let path = store::realm_path(&name)?;
            if path.exists() {
                bail!("Realm '{}' already exists", name);
            }
            let passphrase = get_passphrase(pre_pass)?;
            let vars = BTreeMap::new();
            store::save_realm(&name, &vars, &passphrase)?;
            println!("Realm '{}' created.", name);
        }
        RealmCommands::Delete { name } => {
            let name = prompt::prompt_realm(name)?;
            let confirm: bool = dialoguer::Confirm::new()
                .with_prompt(format!("Delete realm '{}'? This cannot be undone", name))
                .default(false)
                .interact()?;
            if confirm {
                store::delete_realm(&name)?;
                println!("Realm '{}' deleted.", name);
            } else {
                println!("Cancelled.");
            }
        }
    }
    Ok(())
}

// --- Var ---

fn cmd_var(sub: VarCommands, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;
    match sub {
        VarCommands::List { realm } => {
            let realm = prompt::prompt_realm(realm)?;
            let passphrase = get_passphrase(pre_pass)?;
            let vars = store::load_realm(&realm, &passphrase)?;
            if vars.is_empty() {
                println!("No variables in realm '{}'.", realm);
            } else {
                println!("Variables in '{}':", realm);
                for key in vars.keys() {
                    println!("  {}", key);
                }
            }
        }
        VarCommands::Get { var, realm } => {
            let realm = prompt::prompt_realm(realm)?;
            let var = prompt::prompt_var_name(var)?;
            let passphrase = get_passphrase(pre_pass)?;
            let vars = store::load_realm(&realm, &passphrase)?;
            match vars.get(&var) {
                Some(value) => println!("{}", value),
                None => bail!("Variable '{}' not found in realm '{}'", var, realm),
            }
        }
        VarCommands::Set { var, value, realm } => {
            let realm = prompt::prompt_realm(realm)?;
            let var = prompt::prompt_var_name(var)?;
            let value = prompt::prompt_var_value(value)?;
            let passphrase = get_passphrase(pre_pass)?;
            let mut vars = match store::load_realm(&realm, &passphrase) {
                Ok(v) => v,
                Err(_) => BTreeMap::new(),
            };
            let is_update = vars.contains_key(&var);
            vars.insert(var.clone(), value);
            store::save_realm(&realm, &vars, &passphrase)?;
            if is_update {
                println!("Updated '{}' in realm '{}'.", var, realm);
            } else {
                println!("Set '{}' in realm '{}'.", var, realm);
            }
        }
        VarCommands::Delete { var, realm } => {
            let realm = prompt::prompt_realm(realm)?;
            let var = prompt::prompt_var_name(var)?;
            let passphrase = get_passphrase(pre_pass)?;
            let mut vars = store::load_realm(&realm, &passphrase)?;
            if vars.remove(&var).is_none() {
                bail!("Variable '{}' not found in realm '{}'", var, realm);
            }
            store::save_realm(&realm, &vars, &passphrase)?;
            println!("Deleted '{}' from realm '{}'.", var, realm);
        }
    }
    Ok(())
}

// --- Run ---

fn cmd_run(realm: Option<String>, cmd: Vec<String>, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;

    let vars = collect_vars(realm, pre_pass)?;

    if cmd.is_empty() {
        bail!("No command specified. Usage: maige run --realm <name> -- <command>");
    }

    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .envs(&vars)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to run '{}': {}", cmd[0], e))?;

    std::process::exit(status.code().unwrap_or(1));
}

// --- Shell ---

fn cmd_shell(realm: Option<String>, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;

    let vars = collect_vars(realm, pre_pass)?;

    let shell = std::env::var("SHELL")
        .or_else(|_| std::env::var("COMSPEC"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "cmd.exe".to_string()
            } else {
                "/bin/sh".to_string()
            }
        });

    println!("Spawning shell with {} variables injected. Type `exit` to return.", vars.len());

    let status = Command::new(&shell)
        .envs(&vars)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to spawn shell: {}", e))?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Collects variables from realm(s) or .env.maige fallback
fn collect_vars(realm: Option<String>, pre_pass: &Option<String>) -> Result<BTreeMap<String, String>> {
    let passphrase = get_passphrase(pre_pass)?;

    if let Some(realm_str) = realm {
        let mut all_vars = BTreeMap::new();
        for name in realm_str.split(',') {
            let name = name.trim();
            let vars = store::load_realm(name, &passphrase)?;
            all_vars.extend(vars);
        }
        return Ok(all_vars);
    }

    // Fallback: look for .env.maige
    let cwd = std::env::current_dir()?;
    if let Some(path) = resolver::find_env_maige(&cwd) {
        println!("Using {}", path.display());
        return resolver::resolve_env_maige(&path, &passphrase);
    }

    bail!("No --realm specified and no .env.maige found. Specify a realm or create a .env.maige file.");
}

// --- Import ---

fn cmd_import(file: String, realm: Option<String>, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;
    let realm = prompt::prompt_realm(realm)?;
    let passphrase = get_passphrase(pre_pass)?;

    let content = std::fs::read_to_string(&file)
        .map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", file, e))?;
    let imported = store::parse_env(&content);

    if imported.is_empty() {
        println!("No variables found in '{}'.", file);
        return Ok(());
    }

    let mut vars = match store::load_realm(&realm, &passphrase) {
        Ok(v) => v,
        Err(_) => {
            // Create realm if it doesn't exist
            BTreeMap::new()
        }
    };

    let count = imported.len();
    vars.extend(imported);
    store::save_realm(&realm, &vars, &passphrase)?;
    println!("Imported {} variables into realm '{}'.", count, realm);
    Ok(())
}

// --- Convert ---

fn cmd_convert(file: String, realm: Option<String>, delete: bool, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;
    let realm = prompt::prompt_realm(realm)?;
    let passphrase = get_passphrase(pre_pass)?;

    let content = std::fs::read_to_string(&file)
        .map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", file, e))?;
    let parsed = store::parse_env(&content);

    if parsed.is_empty() {
        println!("No variables found in '{}'.", file);
        return Ok(());
    }

    // Import variables into the realm
    let mut vars = match store::load_realm(&realm, &passphrase) {
        Ok(v) => v,
        Err(_) => BTreeMap::new(),
    };
    let count = parsed.len();
    vars.extend(parsed.clone());
    store::save_realm(&realm, &vars, &passphrase)?;

    // Build .env.maige content, preserving comments and blank lines
    let mut maige_lines = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            maige_lines.push(line.to_string());
            continue;
        }
        if let Some((key, _)) = trimmed.split_once('=') {
            let key = key.trim();
            if !key.is_empty() && parsed.contains_key(key) {
                maige_lines.push(format!("{}=maige(\"var:/{}/{}\")", key, realm, key));
                continue;
            }
        }
        maige_lines.push(line.to_string());
    }

    let src_path = std::path::Path::new(&file);
    let maige_path = src_path.with_file_name(
        format!("{}.maige", src_path.file_name().unwrap_or_default().to_string_lossy()),
    );
    std::fs::write(&maige_path, maige_lines.join("\n") + "\n")
        .map_err(|e| anyhow::anyhow!("Failed to write '{}': {}", maige_path.display(), e))?;

    println!("Converted {} variables into realm '{}'.", count, realm);
    println!("Created {}", maige_path.display());

    if delete {
        std::fs::remove_file(&file)
            .map_err(|e| anyhow::anyhow!("Failed to delete '{}': {}", file, e))?;
        println!("Deleted original file '{}'.", file);
    }

    Ok(())
}

// --- Export ---

fn cmd_export(realm: Option<String>, json: bool, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;
    let realm = prompt::prompt_realm(realm)?;
    let passphrase = get_passphrase(pre_pass)?;
    let vars = store::load_realm(&realm, &passphrase)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&vars)?);
    } else {
        print!("{}", store::format_env(&vars));
        if !vars.is_empty() {
            println!();
        }
    }
    Ok(())
}

// --- Check ---

fn cmd_check(pre_pass: &Option<String>) -> Result<()> {
    require_init()?;

    let cwd = std::env::current_dir()?;
    let path = match resolver::find_env_maige(&cwd) {
        Some(p) => p,
        None => bail!("No .env.maige file found in current directory or parent directories."),
    };

    println!("Checking {}...", path.display());
    let passphrase = get_passphrase(pre_pass)?;
    let missing = resolver::check_refs(&path, &passphrase)?;

    if missing.is_empty() {
        println!("All references are valid.");
    } else {
        println!("Found {} issue(s):", missing.len());
        for (realm, key, reason) in &missing {
            println!("  var:/{}/{}  — {}", realm, key, reason);
        }
        std::process::exit(1);
    }
    Ok(())
}

// --- Diff ---

fn cmd_diff(realm1: String, realm2: String, pre_pass: &Option<String>) -> Result<()> {
    require_init()?;
    let passphrase = get_passphrase(pre_pass)?;
    let vars1 = store::load_realm(&realm1, &passphrase)?;
    let vars2 = store::load_realm(&realm2, &passphrase)?;

    let keys1: std::collections::BTreeSet<_> = vars1.keys().collect();
    let keys2: std::collections::BTreeSet<_> = vars2.keys().collect();

    let only_in_1: Vec<_> = keys1.difference(&keys2).collect();
    let only_in_2: Vec<_> = keys2.difference(&keys1).collect();
    let in_both: Vec<_> = keys1.intersection(&keys2).collect();
    let different: Vec<_> = in_both
        .iter()
        .filter(|k| vars1.get(k.as_str()) != vars2.get(k.as_str()))
        .collect();

    if only_in_1.is_empty() && only_in_2.is_empty() && different.is_empty() {
        println!("Realms '{}' and '{}' are identical.", realm1, realm2);
        return Ok(());
    }

    if !only_in_1.is_empty() {
        println!("Only in '{}':", realm1);
        for k in &only_in_1 {
            println!("  {}", k);
        }
    }
    if !only_in_2.is_empty() {
        println!("Only in '{}':", realm2);
        for k in &only_in_2 {
            println!("  {}", k);
        }
    }
    if !different.is_empty() {
        println!("Different values:");
        for k in &different {
            println!("  {}", k);
        }
    }
    Ok(())
}

// --- Key Rotate ---

fn cmd_key_rotate(pre_pass: &Option<String>) -> Result<()> {
    require_init()?;
    println!("This will re-encrypt all realms with a new passphrase.");

    let old = match pre_pass {
        Some(p) => p.clone(),
        None => prompt::prompt_passphrase("Current passphrase")?,
    };
    if !store::verify_passphrase(&old)? {
        bail!("Incorrect passphrase.");
    }

    let new = prompt::prompt_new_passphrase("New passphrase")?;
    store::rotate_key(&old, &new)?;

    let count = store::list_realms()?.len();
    println!("Passphrase rotated. {} realm(s) re-encrypted.", count);
    Ok(())
}
