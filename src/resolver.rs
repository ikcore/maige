use anyhow::{Context, Result};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::store::{Store, VarMap};

/// Searches for a .env.maige file starting from `start_dir` and walking up the tree.
pub fn find_env_maige(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(".env.maige");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Finds fallback env files (.env.schema, .env.template) in the given directory.
pub fn find_fallback_env(start_dir: &Path) -> Option<PathBuf> {
    for name in &[".env.maige", ".env.schema", ".env.template"] {
        let candidate = start_dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// A reference found in an env file: maige("var:/realm/KEY")
#[derive(Debug, Clone)]
pub struct MaigeRef {
    pub realm: String,
    pub key: String,
    pub full_match: String,
}

/// Parses all maige() references from file content
pub fn parse_maige_refs(content: &str) -> Vec<MaigeRef> {
    let re = Regex::new(r#"maige\(\s*"var:/([^/]+)/([^"]+)"\s*\)"#).unwrap();
    re.captures_iter(content)
        .map(|cap| MaigeRef {
            realm: cap[1].to_string(),
            key: cap[2].to_string(),
            full_match: cap[0].to_string(),
        })
        .collect()
}

/// Resolves a .env.maige file using the default store.
pub fn resolve_env_maige(
    path: &Path,
    passphrase: &str,
) -> Result<BTreeMap<String, String>> {
    let s = Store::default_store()?;
    resolve_env_maige_with_store(path, passphrase, &s)
}

/// Resolves a .env.maige file using a specific store.
pub fn resolve_env_maige_with_store(
    path: &Path,
    passphrase: &str,
    store: &Store,
) -> Result<BTreeMap<String, String>> {
    let content = std::fs::read_to_string(path)
        .context(format!("Failed to read {}", path.display()))?;

    let refs = parse_maige_refs(&content);

    let mut realm_cache: BTreeMap<String, VarMap> = BTreeMap::new();
    for r in &refs {
        if !realm_cache.contains_key(&r.realm) {
            let vars = store.load_realm(&r.realm, passphrase)
                .context(format!("Failed to load realm '{}' referenced in {}", r.realm, path.display()))?;
            realm_cache.insert(r.realm.clone(), vars);
        }
    }

    let mut result = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let mut value = value.trim().trim_matches('"').trim_matches('\'').to_string();

            for r in &refs {
                if value.contains(&r.full_match) {
                    let resolved = realm_cache
                        .get(&r.realm)
                        .and_then(|vars| vars.get(&r.key))
                        .with_context(|| {
                            format!("Variable '{}' not found in realm '{}'", r.key, r.realm)
                        })?;
                    value = value.replace(&r.full_match, resolved);
                }
            }

            if !key.is_empty() {
                result.insert(key, value);
            }
        }
    }

    Ok(result)
}

/// Validates all maige() references using the default store.
pub fn check_refs(
    path: &Path,
    passphrase: &str,
) -> Result<Vec<(String, String, String)>> {
    let s = Store::default_store()?;
    check_refs_with_store(path, passphrase, &s)
}

/// Validates all maige() references using a specific store.
pub fn check_refs_with_store(
    path: &Path,
    passphrase: &str,
    store: &Store,
) -> Result<Vec<(String, String, String)>> {
    let content = std::fs::read_to_string(path)
        .context(format!("Failed to read {}", path.display()))?;

    let refs = parse_maige_refs(&content);
    let mut missing = Vec::new();

    let mut realm_cache: BTreeMap<String, VarMap> = BTreeMap::new();
    for r in &refs {
        if !realm_cache.contains_key(&r.realm) {
            match store.load_realm(&r.realm, passphrase) {
                Ok(vars) => {
                    realm_cache.insert(r.realm.clone(), vars);
                }
                Err(_) => {
                    missing.push((r.realm.clone(), r.key.clone(), format!("realm '{}' not found", r.realm)));
                    continue;
                }
            }
        }
        if let Some(vars) = realm_cache.get(&r.realm) {
            if !vars.contains_key(&r.key) {
                missing.push((r.realm.clone(), r.key.clone(), format!("variable '{}' not found in realm '{}'", r.key, r.realm)));
            }
        }
    }

    Ok(missing)
}
