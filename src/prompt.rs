use anyhow::{bail, Result};
use dialoguer::{Input, Password, Select};

use crate::store;

/// Prompts for a realm name if not provided, showing a selection list
pub fn prompt_realm(realm: Option<String>) -> Result<String> {
    if let Some(name) = realm {
        return Ok(name);
    }

    let realms = store::list_realms()?;
    if realms.is_empty() {
        bail!("No realms found. Create one first with `maige realm create <name>`");
    }

    let selection = Select::new()
        .with_prompt("Select a realm")
        .items(&realms)
        .interact()?;

    Ok(realms[selection].clone())
}

/// Prompts for a variable name if not provided
pub fn prompt_var_name(var: Option<String>) -> Result<String> {
    if let Some(name) = var {
        return Ok(name);
    }
    let name: String = Input::new()
        .with_prompt("Variable name")
        .interact_text()?;
    if name.trim().is_empty() {
        bail!("Variable name cannot be empty");
    }
    Ok(name.trim().to_string())
}

/// Prompts for a variable value if not provided
pub fn prompt_var_value(value: Option<String>) -> Result<String> {
    if let Some(v) = value {
        return Ok(v);
    }
    let v: String = Input::new()
        .with_prompt("Variable value")
        .interact_text()?;
    Ok(v)
}

/// Prompts for a realm name (text input, for creation)
pub fn prompt_realm_name(name: Option<String>) -> Result<String> {
    if let Some(n) = name {
        return Ok(n);
    }
    let n: String = Input::new()
        .with_prompt("Realm name")
        .interact_text()?;
    if n.trim().is_empty() {
        bail!("Realm name cannot be empty");
    }
    Ok(n.trim().to_string())
}

/// Prompts for the master passphrase (hidden input)
pub fn prompt_passphrase(message: &str) -> Result<String> {
    let pass = Password::new()
        .with_prompt(message)
        .interact()?;
    if pass.is_empty() {
        bail!("Passphrase cannot be empty");
    }
    Ok(pass)
}

/// Prompts for a new passphrase with confirmation
pub fn prompt_new_passphrase(message: &str) -> Result<String> {
    let pass = Password::new()
        .with_prompt(message)
        .with_confirmation("Confirm passphrase", "Passphrases do not match")
        .interact()?;
    if pass.is_empty() {
        bail!("Passphrase cannot be empty");
    }
    Ok(pass)
}
