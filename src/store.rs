use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto;

/// A collection of key-value pairs representing environment variables
pub type VarMap = BTreeMap<String, String>;

/// Core store backed by a directory on disk.
/// All realm and config operations go through this.
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Create a store rooted at a specific directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Create the default store at ~/.maige (or MAIGE_HOME if set).
    pub fn default_store() -> Result<Self> {
        let root = match std::env::var("MAIGE_HOME") {
            Ok(p) => PathBuf::from(p),
            Err(_) => {
                let home = dirs::home_dir().context("Could not determine home directory")?;
                home.join(".maige")
            }
        };
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn realms_dir(&self) -> PathBuf {
        self.root.join("realms")
    }

    pub fn realm_path(&self, name: &str) -> PathBuf {
        self.realms_dir().join(format!("{}.realm", name))
    }

    pub fn verify_path(&self) -> PathBuf {
        self.root.join(".verify")
    }

    pub fn is_initialized(&self) -> bool {
        self.verify_path().exists()
    }

    /// Creates the maige directory structure and stores a verification token.
    pub fn initialize(&self, passphrase: &str) -> Result<()> {
        std::fs::create_dir_all(self.realms_dir())
            .context("Failed to create maige directory")?;

        crypto::encrypt_to_file(b"maige-verify", passphrase, &self.verify_path())
            .context("Failed to write verification file")?;

        let gitignore = self.root.join(".gitignore");
        if !gitignore.exists() {
            std::fs::write(&gitignore, "*\n")
                .context("Failed to write .gitignore")?;
        }

        Ok(())
    }

    /// Verifies that the passphrase is correct.
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<bool> {
        let verify = self.verify_path();
        if !verify.exists() {
            bail!("Maige is not initialized. Run `maige init` first.");
        }
        match crypto::decrypt_from_file(&verify, passphrase) {
            Ok(data) => Ok(data == b"maige-verify"),
            Err(_) => Ok(false),
        }
    }

    /// Loads and decrypts a realm file.
    pub fn load_realm(&self, name: &str, passphrase: &str) -> Result<VarMap> {
        let path = self.realm_path(name);
        if !path.exists() {
            bail!("Realm '{}' does not exist", name);
        }
        let data = crypto::decrypt_from_file(&path, passphrase)
            .context(format!("Failed to decrypt realm '{}'", name))?;
        let json = String::from_utf8(data)
            .context("Realm data is not valid UTF-8")?;
        let vars: VarMap = serde_json::from_str(&json)
            .context(format!("Failed to parse realm '{}'", name))?;
        Ok(vars)
    }

    /// Encrypts and saves a realm file.
    pub fn save_realm(&self, name: &str, vars: &VarMap, passphrase: &str) -> Result<()> {
        let realms = self.realms_dir();
        if !realms.exists() {
            std::fs::create_dir_all(&realms)?;
        }
        let mut json = serde_json::to_string_pretty(vars)
            .context("Failed to serialize variables")?;
        crypto::encrypt_to_file(json.as_bytes(), passphrase, &self.realm_path(name))
            .context(format!("Failed to encrypt realm '{}'", name))?;
        json.zeroize();
        Ok(())
    }

    /// Lists all realm names.
    pub fn list_realms(&self) -> Result<Vec<String>> {
        let dir = self.realms_dir();
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut realms = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("realm") {
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    realms.push(name.to_string());
                }
            }
        }
        realms.sort();
        Ok(realms)
    }

    /// Deletes a realm file.
    pub fn delete_realm(&self, name: &str) -> Result<()> {
        let path = self.realm_path(name);
        if !path.exists() {
            bail!("Realm '{}' does not exist", name);
        }
        std::fs::remove_file(&path)
            .context(format!("Failed to delete realm '{}'", name))?;
        Ok(())
    }

    /// Re-encrypts all realms with a new passphrase.
    pub fn rotate_key(&self, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        let realms = self.list_realms()?;
        let mut decrypted: Vec<(String, VarMap)> = Vec::new();
        for name in &realms {
            let vars = self.load_realm(name, old_passphrase)
                .context(format!("Failed to decrypt realm '{}' with current passphrase", name))?;
            decrypted.push((name.clone(), vars));
        }
        for (name, vars) in &decrypted {
            self.save_realm(name, vars, new_passphrase)?;
        }
        crypto::encrypt_to_file(b"maige-verify", new_passphrase, &self.verify_path())
            .context("Failed to update verification file")?;
        Ok(())
    }
}

// --- Free functions that delegate to the default store (used by commands) ---

pub fn maige_dir() -> Result<PathBuf> {
    Ok(Store::default_store()?.root().to_path_buf())
}

pub fn realms_dir() -> Result<PathBuf> {
    Ok(Store::default_store()?.realms_dir())
}

pub fn realm_path(name: &str) -> Result<PathBuf> {
    Ok(Store::default_store()?.realm_path(name))
}

pub fn verify_path() -> Result<PathBuf> {
    Ok(Store::default_store()?.verify_path())
}

pub fn is_initialized() -> Result<bool> {
    Ok(Store::default_store()?.is_initialized())
}

pub fn initialize(passphrase: &str) -> Result<()> {
    Store::default_store()?.initialize(passphrase)
}

pub fn verify_passphrase(passphrase: &str) -> Result<bool> {
    Store::default_store()?.verify_passphrase(passphrase)
}

pub fn load_realm(name: &str, passphrase: &str) -> Result<VarMap> {
    Store::default_store()?.load_realm(name, passphrase)
}

pub fn save_realm(name: &str, vars: &VarMap, passphrase: &str) -> Result<()> {
    Store::default_store()?.save_realm(name, vars, passphrase)
}

pub fn list_realms() -> Result<Vec<String>> {
    Store::default_store()?.list_realms()
}

pub fn delete_realm(name: &str) -> Result<()> {
    Store::default_store()?.delete_realm(name)
}

pub fn rotate_key(old_passphrase: &str, new_passphrase: &str) -> Result<()> {
    Store::default_store()?.rotate_key(old_passphrase, new_passphrase)
}

// --- Env parsing utilities (stateless, no store needed) ---

/// Parses a .env format string into a VarMap
pub fn parse_env(content: &str) -> VarMap {
    let mut vars = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().trim_matches('"').trim_matches('\'').to_string();
            if !key.is_empty() {
                vars.insert(key, value);
            }
        }
    }
    vars
}

/// Formats a VarMap as .env file content
pub fn format_env(vars: &VarMap) -> String {
    vars.iter()
        .map(|(k, v)| {
            if v.contains(' ') || v.contains('"') || v.contains('\'') || v.contains('#') {
                format!("{}=\"{}\"", k, v.replace('"', "\\\""))
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
