use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "secure_password_manager")]
#[command(about = "A secure password manager built in Rust")]
#[command(version = "1.0")]
pub struct Cli {
    #[arg(short, long, default_value = "passwords.db")]
    pub database_path: String,
    
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Init,
    
    Add {
        service: String,
        #[arg(short, long)]
        username: Option<String>,
    },
    
    Get {
        service: String,
    },
    
    List,
    
    Generate {
        #[arg(short, long)]
        length: Option<usize>,
        #[arg(short, long)]
        include_symbols: bool,
    },
    
    Delete {
        service: String,
    },
    
    Update {
        service: String,
    },
}
