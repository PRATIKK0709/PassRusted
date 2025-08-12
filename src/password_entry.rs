// src/password_entry.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};


#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    #[zeroize(skip)]
    pub id: Uuid,
    pub service: String,
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>,
}

impl PasswordEntry {
    pub fn new(service: String, username: String, password: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            service,
            username,
            password,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn update_password(&mut self, new_password: String) {
        self.password.zeroize();
        self.password = new_password;
        self.updated_at = Utc::now();
    }
}