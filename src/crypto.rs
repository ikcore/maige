use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Failed to derive key: {0}")]
    KeyDerivation(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed — wrong passphrase or corrupted data")]
    Decryption,
    #[error("Invalid data format")]
    InvalidFormat,
}

/// Derives a 256-bit key from a passphrase using Argon2id.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Encrypts plaintext with a passphrase.
/// Returns base64-encoded string: salt || nonce || ciphertext
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<String, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(B64.encode(&combined))
}

/// Decrypts a base64-encoded ciphertext with a passphrase.
pub fn decrypt(encoded: &str, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    let data = B64.decode(encoded).map_err(|_| CryptoError::InvalidFormat)?;

    if data.len() < SALT_LEN + NONCE_LEN + 1 {
        return Err(CryptoError::InvalidFormat);
    }

    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let mut key = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;
    key.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decryption)?;

    Ok(plaintext)
}

/// Encrypts plaintext and writes it to a file.
pub fn encrypt_to_file(
    plaintext: &[u8],
    passphrase: &str,
    path: &std::path::Path,
) -> Result<(), CryptoError> {
    let encoded = encrypt(plaintext, passphrase)?;
    std::fs::write(path, encoded).map_err(|e| CryptoError::Encryption(e.to_string()))?;
    Ok(())
}

/// Reads an encrypted file and decrypts it.
pub fn decrypt_from_file(
    path: &std::path::Path,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    let encoded =
        std::fs::read_to_string(path).map_err(|e| CryptoError::Encryption(e.to_string()))?;
    decrypt(encoded.trim(), passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"SECRET_KEY=hunter2\nAPI_TOKEN=abc123";
        let passphrase = "my-strong-passphrase";

        let encrypted = encrypt(plaintext, passphrase).unwrap();
        let decrypted = decrypt(&encrypted, passphrase).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let plaintext = b"SECRET=value";
        let encrypted = encrypt(plaintext, "correct").unwrap();
        let result = decrypt(&encrypted, "wrong");
        assert!(result.is_err());
    }
}
