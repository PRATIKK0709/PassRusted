// src/crypto.rs

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{rngs::OsRng, RngCore};
use anyhow::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; KEY_LEN],
}

impl MasterKey {
    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;
        let hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

        let hash_bytes = hash.hash.ok_or_else(|| anyhow::anyhow!("Failed to extract hash"))?;
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&hash_bytes.as_bytes()[..KEY_LEN]);

        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<MasterKey> {
    MasterKey::from_password(password, salt)
}

pub fn hash_master_password(password: &str) -> Result<(String, Vec<u8>)> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

    Ok((hash.to_string(), salt.to_vec()))
}

pub fn verify_master_password(password: &str, hash_str: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(hash_str).map_err(|e| anyhow::anyhow!("Invalid hash format: {}", e))?;
    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Password verification error: {}", e)),
    }
}

pub fn encrypt_data(data: &[u8], key: &MasterKey) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_data(encrypted_data: &[u8], key: &MasterKey) -> Result<Vec<u8>> {
    if encrypted_data.len() < NONCE_LEN {
        anyhow::bail!("Invalid encrypted data length");
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    
    Ok(plaintext)
}