use clap::{Parser, ValueEnum};

/// Command-line arguments for the Vigenère cipher program.
#[derive(Parser, Debug)]
struct Cli {
    /// Path to the input file containing text to encrypt/decrypt
    #[arg(short, long, help = "Path to the input file")]
    file: String,

    /// Key string for the Vigenère cipher
    #[arg(short, long, help = "Key string for the cipher")]
    key: String,

    /// Path to the output file where result will be saved
    #[arg(short, long, help = "Path to the output file")]
    output: String,

    /// Mode of operation (encrypt or decrypt)
    #[arg(short, long, help = "Mode of operation (encrypt/decrypt)")]
    mode: OperationMode,
}

/// Enum representing the mode of operation for the cipher.
#[derive(Clone, Debug, ValueEnum)]
enum OperationMode {
    /// Encrypt mode
    Encrypt,
    /// Decrypt mode
    Decrypt,
}

/// Main entry point for the Vigenère cipher program.
fn main() {
    // Parse command-line arguments
    let cli: Cli = Cli::parse();

    // Read input file content
    let content: String = std::fs::read_to_string(&cli.file)
        .expect("Failed to read input file");

    // Process based on selected mode
    let result = match cli.mode {
        OperationMode::Encrypt => {
            println!("Encrypting with key: {}", cli.key);
            encrypt(&content, &cli.key)
        }
        OperationMode::Decrypt => {
            println!("Decrypting with key: {}", cli.key);
            decrypt(&content, &cli.key)
        }
    };

    // Write result to output file
    std::fs::write(&cli.output, result)
        .expect("Failed to write output file");
    
    println!("Operation completed successfully! Output saved to: {}", cli.output);
}

/// Encrypts text using the Vigenère cipher algorithm.
///
/// # Arguments
///
/// * `content` - The input text to encrypt.
/// * `key` - The encryption key string.
///
/// # Returns
///
/// A `String` containing the encrypted text.
fn encrypt(content: &str, key: &str) -> String {
    let mut result: String = String::new();
    let key_bytes: &[u8] = key.as_bytes();
    let key_len: usize = key_bytes.len();
    let mut key_index: usize = 0;

    // Process each byte in the input content
    for &byte in content.as_bytes() {
        if byte.is_ascii_alphabetic() {
            // Determine base character ('A' or 'a') to preserve case
            let base: u8 = if byte.is_ascii_lowercase() { b'a' } else { b'A' };
            
            // Get the key character and convert to shift value (0-25)
            let key_char: u8 = key_bytes[key_index % key_len].to_ascii_lowercase() - b'a';
            
            // Apply Vigenère encryption: (plaintext + key) mod 26
            let encrypted_byte: u8 = (byte - base + key_char) % 26 + base;
            result.push(encrypted_byte as char);
            
            // Only advance key index for alphabetic characters
            key_index += 1;
        } else {
            // Non-alphabetic characters remain unchanged
            result.push(byte as char);
        }
    }

    result
}


/// Decrypts text using the Vigenère cipher algorithm.
///
/// # Arguments
///
/// * `content` - The input text to decrypt.
/// * `key` - The decryption key string.
///
/// # Returns
///
/// A `String` containing the decrypted text.
fn decrypt(content: &str, key: &str) -> String {
    let mut result: String = String::new();
    let key_bytes: &[u8] = key.as_bytes();
    let key_len: usize = key_bytes.len();
    let mut key_index: usize = 0;

    // Process each byte in the input content
    for &byte in content.as_bytes() {
        if byte.is_ascii_alphabetic() {
            // Determine base character ('A' or 'a') to preserve case
            let base = if byte.is_ascii_lowercase() { b'a' } else { b'A' };
            
            // Get the key character and convert to shift value (0-25)
            let key_char = key_bytes[key_index % key_len].to_ascii_lowercase() - b'a';
            
            // Apply Vigenère decryption: (ciphertext - key + 26) mod 26
            let decrypted_byte = (byte - base + 26 - key_char) % 26 + base;
            result.push(decrypted_byte as char);
            
            // Only advance key index for alphabetic characters
            key_index += 1;
        } else {
            // Non-alphabetic characters remain unchanged
            result.push(byte as char);
        }
    }

    result
}