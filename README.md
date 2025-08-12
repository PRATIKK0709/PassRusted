# PassRusted

[](https://www.google.com/search?q=https://github.com/PRATIKK0709/PassRusted)
[](https://www.google.com/search?q=https://crates.io/crates/PassRusted)
[](https://opensource.org/licenses/MIT)
[](https://www.rust-lang.org/)

**A secure, simple, and command-line based password manager written in Rust.**

`PassRusted` is a terminal-based password manager that prioritizes security and simplicity. It allows you to store your passwords in a local, encrypted database file, protected by a single master password. It uses modern, strong cryptography to ensure your sensitive data is safe.

## Features

  - 🔒 **Strong Encryption**: Your password database is encrypted using `AES-256-GCM`, providing both confidentiality and authenticity.
  - 🔑 **Secure Key Derivation**: Your master password is used to derive an encryption key via `Argon2id`, a modern, memory-hard hashing algorithm that protects against brute-force attacks.
  - 🧹 **Secure Memory Handling**: Sensitive data like your master key and passwords are automatically cleared from memory when they are no longer needed, thanks to the `zeroize` crate.
  - 💻 **CLI-First Interface**: All operations are handled through a clean and intuitive command-line interface.
  - ⚡ **Self-Contained**: Operates with a single binary and a single database file, making it portable and easy to back up.
  - 🎲 **Built-in Password Generator**: Quickly generate strong, random passwords with customizable length and character sets.
  - ✅ **Cross-Platform**: Built with Rust, it can be compiled and run on Linux, macOS, and Windows.

## Security

Security is the core design principle of `PassRusted`. Here's a breakdown of the cryptographic approach:

1.  **Master Password**: You only need to remember one master password. This password is **never stored directly**.
2.  **Key Derivation**: When you initialize the database, a random salt is generated. This salt and your master password are fed into **Argon2id** to create two things:
      * A **public hash** that is stored in the database header. This is used only to verify your master password on future logins.
      * A 32-byte **encryption key** that is kept only in memory.
3.  **Data Encryption**: All your password entries are serialized and then encrypted using **AES-256-GCM** with the derived encryption key. The encrypted data is then written to the database file.
4.  **In-Memory Protection**: The encryption key and any plaintext passwords are held in memory only for the duration of a command. The `zeroize` crate is used to securely wipe these from memory, minimizing the attack surface.

## Installation

### Prerequisites

You need to have the Rust toolchain installed. If you don't, you can install it via [rustup](https://rustup.rs/).

### From Source

1.  Clone the repository:

    ```bash
    git clone https://github.com/PRATIKK0709/PassRusted.git
    cd PassRusted
    ```

2.  You can now run the application directly using `cargo run`. For a production build, compile the project:

    ```bash
    cargo build --release
    ```

3.  The executable will be located at `target/release/PassRusted`. You can move this binary to a location in your `$PATH` for easy access.

## Usage

The following examples demonstrate how to use `PassRusted` from within the project directory using `cargo run`. The `--` is used to separate arguments for `cargo` from arguments for your program.

```
# Display the help menu
cargo run -- --help
```

### Initialize database

This is the first command you must run. It creates the database file and prompts you to set a master password.

```bash
cargo run -- init
```

### Add password (interactive)

Adds a new service and prompts you for the username and password.

```bash
cargo run -- add "service_name"
```

### Add password with username

Adds a new service with the username provided as an argument.

```bash
cargo run -- add "service_name" --username "user@example.com"
```

### Get password

Retrieves the details for a specific service.

```bash
cargo run -- get "service_name"
```

### List all services

Lists all the services and associated usernames stored in the database.

```bash
cargo run -- list
```

### Generate password

Generates a strong, random password without storing it.

```bash
cargo run -- generate --length 16 --include-symbols
```

### Update password

Updates the password for an existing service.

```bash
cargo run -- update "service_name"
```

### Delete entry

Permanently removes a password entry from the database.

```bash
cargo run -- delete "service_name"
```

### Use custom database file

You can specify a different database path using the global `--database-path` option.

```bash
cargo run -- --database-path "my_passwords.db" list
```

## On-Disk Format

The database file (`passwords.db` by default) has a simple binary structure:

`[Header Size (4 bytes)] [Serialized Header] [Encrypted Data Blob]`

  - **Header**: A `bincode`-serialized struct containing the database version, the `Argon2` hash of the master password, and the unique salt.
  - **Encrypted Data Blob**: A `bincode`-serialized `HashMap` of all password entries, encrypted with `AES-256-GCM`.

## Key Dependencies

  - [clap](https://crates.io/crates/clap) for command-line argument parsing.
  - [argon2](https://crates.io/crates/argon2) for password hashing and key derivation.
  - [aes-gcm](https://crates.io/crates/aes-gcm) for authenticated encryption.
  - [zeroize](https://crates.io/crates/zeroize) for securely clearing sensitive data from memory.
  - [serde](https://crates.io/crates/serde) & [bincode](https://crates.io/crates/bincode) for data serialization.
  - [rpassword](https://crates.io/crates/rpassword) for reading passwords from the terminal without echoing.
  - [anyhow](https://crates.io/crates/anyhow) for flexible error handling.
  - [colored](https://crates.io/crates/colored) for pretty terminal output.

## Contributing

Contributions are welcome\! Please feel free to open an issue or submit a pull request.
