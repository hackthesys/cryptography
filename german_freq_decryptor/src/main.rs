
use clap::Parser;

/// Command-line arguments for the German frequency decryptor program.
#[derive(Parser, Debug)]
struct Cli {
    /// Path to the input file containing encrypted text
    #[arg(short, long, help = "Path to the input file containing encrypted text")]
    file: String,

    /// Path to the output file where decrypted text will be saved
    #[arg(short, long, help = "Path to the output file for decrypted text")]
    output: String,
}


/// Main entry point for the German frequency decryptor.
fn main() {
    // Parse command-line arguments
    let cli: Cli = Cli::parse();
    
    // Read the encrypted content from the input file
    let content: String = std::fs::read_to_string(&cli.file)
        .expect("Failed to read the input file");
    
    // Analyze character frequencies in the encrypted text
    let frequencies: [u32; 26] = count_frequencies(&content);
    
    // Determine the most likely decryption key based on frequency analysis
    let key = find_best_key(&frequencies);
    println!("Detected cipher key: {}", key);
    
    // Decrypt the content using the discovered key
    let decrypted: String = decrypt(&content, key);
    
    // Write the decrypted text to the output file
    std::fs::write(&cli.output, decrypted)
        .expect("Failed to write the output file");
}

/// Counts the frequency of each letter in the given text.
///
/// # Arguments
///
/// * `content` - The input text to analyze.
///
/// # Returns
///
/// An array of 26 frequencies for letters A-Z.
fn count_frequencies(content: &str) -> [u32; 26] {
    let mut frequencies: [u32; 26] = [0; 26];
    
    // Iterate through each character in the content
    for c in content.chars() {
        // Only process alphabetic characters
        if c.is_ascii_alphabetic() {
            // Convert to lowercase and calculate array index (a=0, b=1, etc.)
            let index: usize = (c.to_ascii_lowercase() as u8 - b'a') as usize;
            frequencies[index] += 1;
        }
    }
    
    frequencies
}


/// Determines the most likely cipher key using frequency analysis.
///
/// # Arguments
///
/// * `frequencies` - Array of letter frequencies from encrypted text.
///
/// # Returns
///
/// The decryption key (0-25) for the additive cipher.
fn find_best_key(frequencies: &[u32; 26]) -> u8 {
    // Find the letter with the highest frequency in the encrypted text
    let most_frequent: usize = frequencies
        .iter()
        .enumerate()
        .max_by_key(|&(_, count)| count)
        .map(|(index, _)| index)
        .unwrap_or(0);

    // Calculate the key: how much to shift the most frequent letter to get 'e'
    // Formula: (most_frequent_position - e_position + 26) % 26
    (most_frequent as u8 + 26 - (b'e' - b'a')) % 26
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
    content
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                // Determine the base character ('A' for uppercase, 'a' for lowercase)
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                
                // Apply reverse Caesar cipher: subtract key and wrap around alphabet
                let shifted_char = ((c as u8 - base + 26 - key) % 26) + base;
                
                shifted_char as char
            } else {
                // Non-alphabetic characters remain unchanged
                c
            }
        })
        .collect()
}