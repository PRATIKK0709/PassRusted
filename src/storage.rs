// src/storage.rs

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::crypto::{hash_master_password, verify_master_password, encrypt_data, decrypt_data, MasterKey};
use crate::password_entry::PasswordEntry;

#[derive(Serialize, Deserialize)]
struct DatabaseHeader {
    version: u32,
    master_hash: String,
    salt: Vec<u8>,
}

pub struct PasswordStore {
    file_path: String,
    entries: HashMap<String, PasswordEntry>,
    master_key: Option<MasterKey>,
    header: Option<DatabaseHeader>,
}

impl PasswordStore {
    pub fn new(file_path: &str) -> Result<Self> {
        let mut store = Self {
            file_path: file_path.to_string(),
            entries: HashMap::new(),
            master_key: None,
            header: None,
        };
        
        if Path::new(file_path).exists() {
            store.load_header()?;
        }
        
        Ok(store)
    }
    
    pub fn is_initialized(&self) -> Result<bool> {
        Ok(Path::new(&self.file_path).exists() && self.header.is_some())
    }
    
    pub fn initialize(&mut self, master_password: &str) -> Result<()> {
        let (hash, salt) = hash_master_password(master_password)?;
        
        let header = DatabaseHeader {
            version: 1,
            master_hash: hash,
            salt,
        };
        
        self.header = Some(header);
        self.master_key = Some(crate::crypto::derive_key(master_password, &self.header.as_ref().unwrap().salt)?);
        self.save_to_file()?;
        
        Ok(())
    }
    
    pub fn verify_master_password(&mut self, password: &str) -> Result<bool> {
        let header = self.header.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
        
        if verify_master_password(password, &header.master_hash)? {
            self.master_key = Some(crate::crypto::derive_key(password, &header.salt)?);
            self.load_entries()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    pub fn add_entry(&mut self, service: &str, username: &str, password: &str) -> Result<()> {
        let entry = PasswordEntry::new(service.to_string(), username.to_string(), password.to_string());
        self.entries.insert(service.to_string(), entry);
        self.save_to_file()?;
        Ok(())
    }
    
    pub fn get_entry(&self, service: &str) -> Result<Option<PasswordEntry>> {
        Ok(self.entries.get(service).cloned())
    }
    
    pub fn list_entries(&self) -> Result<Vec<PasswordEntry>> {
        Ok(self.entries.values().cloned().collect())
    }
    
    pub fn delete_entry(&mut self, service: &str) -> Result<()> {
        self.entries.remove(service);
        self.save_to_file()?;
        Ok(())
    }
    
    pub fn update_password(&mut self, service: &str, new_password: &str) -> Result<()> {
        if let Some(entry) = self.entries.get_mut(service) {
            entry.update_password(new_password.to_string());
            self.save_to_file()?;
        }
        Ok(())
    }
    
    fn load_header(&mut self) -> Result<()> {
        let mut file = File::open(&self.file_path)?;
        let mut header_size_bytes = [0u8; 4];
        file.read_exact(&mut header_size_bytes)?;
        let header_size = u32::from_le_bytes(header_size_bytes);
        
        let mut header_bytes = vec![0u8; header_size as usize];
        file.read_exact(&mut header_bytes)?;
        
        let header: DatabaseHeader = bincode::deserialize(&header_bytes)?;
        self.header = Some(header);
        
        Ok(())
    }
    
    fn load_entries(&mut self) -> Result<()> {
        if self.master_key.is_none() {
            anyhow::bail!("Master key not available");
        }
        
        let mut file = File::open(&self.file_path)?;
        
        // Skip header
        let mut header_size_bytes = [0u8; 4];
        file.read_exact(&mut header_size_bytes)?;
        let header_size = u32::from_le_bytes(header_size_bytes);
        file.seek(SeekFrom::Current(header_size as i64))?;
        
        let mut encrypted_data = Vec::new();
        match file.read_to_end(&mut encrypted_data) {
            Ok(0) => {
                self.entries = HashMap::new();
                return Ok(());
            },
            Ok(_) => {},
            Err(e) => return Err(e.into()),
        }
        
        if encrypted_data.is_empty() {
            self.entries = HashMap::new();
            return Ok(());
        }
        
        let key = self.master_key.as_ref().unwrap();
        let decrypted_data = decrypt_data(&encrypted_data, key)?;
        let entries: HashMap<String, PasswordEntry> = bincode::deserialize(&decrypted_data)?;
        self.entries = entries;
        
        Ok(())
    }
    
    fn save_to_file(&self) -> Result<()> {
        let header = self.header.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Header not available"))?;
        let key = self.master_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Master key not available"))?;
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.file_path)?;
        
        let header_bytes = bincode::serialize(header)?;
        let header_size = header_bytes.len() as u32;
        file.write_all(&header_size.to_le_bytes())?;
        file.write_all(&header_bytes)?;
        
        let entries_bytes = bincode::serialize(&self.entries)?;
        let encrypted_data = encrypt_data(&entries_bytes, key)?;
        file.write_all(&encrypted_data)?;
        
        file.sync_all()?;
        Ok(())
    }
}