use rand::{thread_rng, Rng};
use anyhow::Result;

pub struct PasswordGenerator {
    lowercase: &'static str,
    uppercase: &'static str,
    numbers: &'static str,
    symbols: &'static str,
}

impl PasswordGenerator {
    pub fn new() -> Self {
        Self {
            lowercase: "abcdefghijklmnopqrstuvwxyz",
            uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            numbers: "0123456789",
            symbols: "!@#$%^&*()-_=+[]{}|;:,.<>?",
        }
    }
    
    pub fn generate(&self, length: usize, include_symbols: bool) -> Result<String> {
        if length < 4 {
            anyhow::bail!("Password length must be at least 4 characters");
        }
        
        let mut charset = String::new();
        charset.push_str(self.lowercase);
        charset.push_str(self.uppercase);
        charset.push_str(self.numbers);
        
        if include_symbols {
            charset.push_str(self.symbols);
        }
        
        let charset: Vec<char> = charset.chars().collect();
        let mut rng = thread_rng();
        let mut password = Vec::with_capacity(length);
        
        password.push(self.lowercase.chars().nth(rng.gen_range(0..self.lowercase.len())).unwrap());
        password.push(self.uppercase.chars().nth(rng.gen_range(0..self.uppercase.len())).unwrap());
        password.push(self.numbers.chars().nth(rng.gen_range(0..self.numbers.len())).unwrap());
        
        if include_symbols {
            password.push(self.symbols.chars().nth(rng.gen_range(0..self.symbols.len())).unwrap());
        }
        
        for _ in password.len()..length {
            password.push(charset[rng.gen_range(0..charset.len())]);
        }
        
        for i in (1..password.len()).rev() {
            let j = rng.gen_range(0..=i);
            password.swap(i, j);
        }
        
        Ok(password.into_iter().collect())
    }
}