// src/main.rs

mod crypto;
mod storage;
mod password_entry;
mod password_generator;
mod cli;

use anyhow::Result;
use clap::Parser;
use colored::*;
use std::io::{self, Write};

use crate::cli::{Cli, Command};
use crate::storage::PasswordStore;
use crate::password_generator::PasswordGenerator;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match run_cli(cli) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

fn run_cli(cli: Cli) -> Result<()> {
    let mut store = PasswordStore::new(&cli.database_path)?;

    match cli.command {
        Command::Init => initialize_database(&mut store),
        Command::Add { service, username } => add_password(&mut store, &service, username.as_deref()),
        Command::Get { service } => get_password(&mut store, &service),
        Command::List => list_passwords(&mut store),
        Command::Generate { length, include_symbols } => generate_password(length, include_symbols),
        Command::Delete { service } => delete_password(&mut store, &service),
        Command::Update { service } => update_password(&mut store, &service),
    }
}

fn initialize_database(store: &mut PasswordStore) -> Result<()> {
    if store.is_initialized()? {
        println!("{}", "Database already initialized!".yellow());
        return Ok(());
    }

    println!("{}", "Initializing secure password database...".cyan().bold());

    let master_password = rpassword::prompt_password("Enter master password: ")?;
    let confirm_password = rpassword::prompt_password("Confirm master password: ")?;

    if master_password != confirm_password {
        anyhow::bail!("Passwords do not match!");
    }

    if master_password.len() < 8 {
        anyhow::bail!("Master password must be at least 8 characters long!");
    }

    store.initialize(&master_password)?;
    println!("{}", "Database initialized successfully!".green().bold());
    Ok(())
}

fn add_password(store: &mut PasswordStore, service: &str, username: Option<&str>) -> Result<()> {
    authenticate_user(store)?;

    let username = match username {
        Some(u) => u.to_string(),
        None => {
            print!("Username: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    println!("Choose password option:");
    println!("1. Generate random password");
    println!("2. Enter custom password");

    print!("Choice (1/2): ");
    io::stdout().flush()?;
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;

    let password = match choice.trim() {
        "1" => {
            let generator = PasswordGenerator::new();
            generator.generate(16, true)?
        },
        "2" => {
            rpassword::prompt_password("Enter password: ")?
        },
        _ => anyhow::bail!("Invalid choice!")
    };

    store.add_entry(service, &username, &password)?;
    println!("{} Password added for {} ({})", "✓".green().bold(), service.cyan(), username);
    Ok(())
}

fn get_password(store: &mut PasswordStore, service: &str) -> Result<()> {
    authenticate_user(store)?;

    match store.get_entry(service)? {
        Some(entry) => {
            println!("{}", "Password Entry".cyan().bold());
            println!("Service: {}", entry.service.yellow());
            println!("Username: {}", entry.username.yellow());
            println!("Password: {}", entry.password.green());
            println!("Created: {}", entry.created_at.format("%Y-%m-%d %H:%M:%S").to_string().blue());
            println!("Updated: {}", entry.updated_at.format("%Y-%m-%d %H:%M:%S").to_string().blue());
        },
        None => {
            println!("{}", format!("No entry found for service: {}", service).red());
        }
    }
    Ok(())
}

// FIX: Takes a mutable store to allow authentication
fn list_passwords(store: &mut PasswordStore) -> Result<()> {
    authenticate_user(store)?;

    let entries = store.list_entries()?;

    if entries.is_empty() {
        println!("{}", "No passwords stored yet.".yellow());
        return Ok(());
    }

    println!("{}", "Stored Passwords:".cyan().bold());
    println!("{}", "=".repeat(50));

    for entry in entries {
        println!("{} {} ({})",
            "•".green(),
            entry.service.yellow().bold(),
            entry.username.blue()
        );
        println!("  Last updated: {}",
            entry.updated_at.format("%Y-%m-%d %H:%M:%S").to_string().dimmed()
        );
    }
    Ok(())
}

fn generate_password(length: Option<usize>, include_symbols: bool) -> Result<()> {
    let generator = PasswordGenerator::new();
    let length = length.unwrap_or(16);
    let password = generator.generate(length, include_symbols)?;

    println!("{}", "Generated Password:".cyan().bold());
    println!("{}", password.green().bold());
    Ok(())
}

fn delete_password(store: &mut PasswordStore, service: &str) -> Result<()> {
    authenticate_user(store)?;

    if store.get_entry(service)?.is_none() {
        println!("{}", format!("No entry found for service: {}", service).red());
        return Ok(());
    }

    print!("Are you sure you want to delete the entry for '{}'? (y/N): ", service);
    io::stdout().flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;

    if confirmation.trim().to_lowercase() == "y" {
        store.delete_entry(service)?;
        println!("{} Entry deleted for {}", "✓".green().bold(), service.cyan());
    } else {
        println!("Deletion cancelled.");
    }
    Ok(())
}

fn update_password(store: &mut PasswordStore, service: &str) -> Result<()> {
    authenticate_user(store)?;

    if store.get_entry(service)?.is_none() {
        println!("{}", format!("No entry found for service: {}", service).red());
        return Ok(());
    }

    println!("Choose password option:");
    println!("1. Generate random password");
    println!("2. Enter custom password");

    print!("Choice (1/2): ");
    io::stdout().flush()?;
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;

    let new_password = match choice.trim() {
        "1" => {
            let generator = PasswordGenerator::new();
            generator.generate(16, true)?
        },
        "2" => {
            rpassword::prompt_password("Enter new password: ")?
        },
        _ => anyhow::bail!("Invalid choice!")
    };

    store.update_password(service, &new_password)?;
    println!("{} Password updated for {}", "✓".green().bold(), service.cyan());
    Ok(())
}

fn authenticate_user(store: &mut PasswordStore) -> Result<()> {
    if !store.is_initialized()? {
        anyhow::bail!("Database not initialized. Run 'init' command first.");
    }

    let master_password = rpassword::prompt_password("Master password: ")?;

    if !store.verify_master_password(&master_password)? {
        anyhow::bail!("Invalid master password!");
    }

    Ok(())
}