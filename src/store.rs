use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto;

/// A collection of key-value pairs representing environment variables
pub type VarMap = BTreeMap<String, String>;

/// Core store backed by a directory on disk.
/// All realm and config operations go through this.
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Hold this guard for the entire operation. Closing the file also releases
    /// the OS lock after a crash; the lock file itself must never be removed.
    pub(crate) fn lock_and_recover(&self) -> Result<std::fs::File> {
        std::fs::create_dir_all(&self.root)?;
        let lock = std::fs::OpenOptions::new()
            .read(true).write(true).create(true).truncate(false)
            .open(self.root.join(".lock"))
            .context("Failed to open store lock")?;
        fs2::FileExt::lock_exclusive(&lock).context("Failed to lock store")?;
        crate::rotation::recover(self)
            .context("Key rotation recovery failed; encrypted recovery journal retained. Resolve the filesystem error and retry")?;
        Ok(lock)
    }

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
        let _lock = self.lock_and_recover()?;
        if self.is_initialized() {
            bail!("Maige is already initialized");
        }
        std::fs::create_dir_all(self.realms_dir())
            .context("Failed to create maige directory")?;
        crate::atomic_file::sync_dir(&self.root)?;

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
        let _lock = self.lock_and_recover()?;
        self.verify_passphrase_unlocked(passphrase)
    }

    pub(crate) fn verify_passphrase_unlocked(&self, passphrase: &str) -> Result<bool> {
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
        self.load_realm_if_exists(name, passphrase)?
            .with_context(|| format!("Realm '{}' does not exist", name))
    }

    /// Returns None only when the realm file is missing. All read, decryption,
    /// and parsing failures are propagated so callers cannot overwrite bad data.
    pub fn load_realm_if_exists(&self, name: &str, passphrase: &str) -> Result<Option<VarMap>> {
        let _lock = self.lock_and_recover()?;
        validate_realm_name(name)?;
        let path = self.realm_path(name);
        let encoded = match std::fs::read_to_string(&path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("Failed to read realm '{}'", name));
            }
        };
        let data = crypto::decrypt(encoded.trim(), passphrase)
            .context(format!("Failed to decrypt realm '{}'", name))?;
        let json = String::from_utf8(data)
            .context("Realm data is not valid UTF-8")?;
        let vars: VarMap = serde_json::from_str(&json)
            .context(format!("Failed to parse realm '{}'", name))?;
        Ok(Some(vars))
    }

    /// Encrypts and saves a realm file.
    pub fn save_realm(&self, name: &str, vars: &VarMap, passphrase: &str) -> Result<()> {
        let _lock = self.lock_and_recover()?;
        validate_realm_name(name)?;
        // A caller may have read before a concurrent rotation committed.
        // Never let that stale passphrase write into the newly rotated store.
        if !self.verify_passphrase_unlocked(passphrase)? {
            bail!("Incorrect passphrase; the store may have been rotated. Retry the command.");
        }
        let realms = self.realms_dir();
        if !realms.exists() {
            std::fs::create_dir_all(&realms)?;
        }
        let json = Zeroizing::new(serde_json::to_string_pretty(vars)
            .context("Failed to serialize variables")?);
        crypto::encrypt_to_file(json.as_bytes(), passphrase, &self.realm_path(name))
            .context(format!("Failed to encrypt realm '{}'", name))?;
        Ok(())
    }

    /// Lists all realm names.
    pub fn list_realms(&self) -> Result<Vec<String>> {
        let _lock = self.lock_and_recover()?;
        self.list_realms_unlocked()
    }

    pub(crate) fn list_realms_unlocked(&self) -> Result<Vec<String>> {
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
        let _lock = self.lock_and_recover()?;
        validate_realm_name(name)?;
        let path = self.realm_path(name);
        if !path.exists() {
            bail!("Realm '{}' does not exist", name);
        }
        std::fs::remove_file(&path)
            .context(format!("Failed to delete realm '{}'", name))?;
        crate::atomic_file::sync_dir(&self.realms_dir())?;
        Ok(())
    }

    /// Re-encrypts all realms with a new passphrase.
    pub fn rotate_key(&self, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        let _lock = self.lock_and_recover()?;
        crate::rotation::rotate(self, old_passphrase, new_passphrase)
    }
}

pub(crate) fn validate_realm_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".."
        || name.contains(['/', '\\', ':', '\0']) {
        bail!("Invalid realm name: expected a single filename without path separators");
    }
    Ok(())
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
    let store = Store::default_store()?;
    let _lock = store.lock_and_recover()?;
    Ok(store.is_initialized())
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

pub fn load_realm_if_exists(name: &str, passphrase: &str) -> Result<Option<VarMap>> {
    Store::default_store()?.load_realm_if_exists(name, passphrase)
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
