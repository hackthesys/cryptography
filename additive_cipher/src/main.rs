//! This module provides a simple implementation of an additive cipher,
//! including encryption and decryption functionality, as well as a CLI
//! interface for user interaction.

use clap::{Parser, ValueEnum};

/// Command-line arguments for the additive cipher program.
#[derive(Parser, Debug)]
struct Cli {
    /// Path to the input file.
    #[arg(short,long, help = "Path to the input file")]
    file: String,

    /// Key for the cipher.
    #[arg(short,long,help = "Key for the cipher")]
    key: u8,

    /// Path to the output file.
    #[arg(short,long,help = "Path to the output file")]
    output: String,

    /// Mode of operation (encrypt or decrypt).
    #[arg(short,long,help = "Mode of operation (encrypt/decrypt)")]
    mode: OperationMode,
}

/// Enum representing the mode of operation for the cipher.
#[derive(Clone, Debug, ValueEnum)]
enum OperationMode {
    /// Encrypt mode.
    Encrypt,
    /// Decrypt mode.
    Decrypt,
}

/// Main entry point of the program.
///
/// Parses the command-line arguments and performs the requested operation
/// (encryption or decryption) on the input file.
fn main() {
    let cli: Cli = Cli::parse();
    match cli.mode {
        OperationMode::Encrypt => {
            let content: String = std::fs::read_to_string(&cli.file)
                .expect("Failed to read the input file");
            //println!("{}", content);
            let cypher = encrypt(&content, cli.key);
            std::fs::write(cli.output, cypher)
                .expect("Failed to write to the output file");
        }
        OperationMode::Decrypt => {
            let content: String = std::fs::read_to_string(&cli.file)
                .expect("Failed to read the input file");
            //println!("{}", content);
            let message: String = decrypt(&content, cli.key);
            std::fs::write(cli.output, message)
                .expect("Failed to write to the output file");
        }
    }
}

/// Encrypts the given content using a simple additive cipher.
///
/// # Arguments
///
/// * `content` - The input string to be encrypted.
/// * `key` - The encryption key.
///
/// # Returns
///
/// A `String` containing the encrypted content.
fn encrypt(content: &str, key: u8) -> String {
    // Simple additive cipher encryption logic
    content.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { 'A' } else { 'a' };
                let new_char = ((c as u8 - base as u8 + key) % 26) + base as u8;
                new_char as char
            } else {
                c
            }
        })
        .collect()
}

/// Decrypts the given content using a simple additive cipher.
///
/// # Arguments
///
/// * `content` - The input string to be decrypted.
/// * `key` - The decryption key.
///
/// # Returns
///
/// A `String` containing the decrypted content.
fn decrypt(content: &str, key: u8) -> String {
    content.chars()
        .map(|c| {
            if c.is_ascii_alphabetic(){
                let base = if c.is_ascii_uppercase() { 'A' } else { 'a' };
                let new_char = ((c as u8 - base as u8 + 26 - key) % 26) + base as u8;
                new_char as char
            } else {
                c
            }
        }).collect()
}
