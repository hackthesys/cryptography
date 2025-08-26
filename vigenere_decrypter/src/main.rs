use clap::Parser;

/// Command-line arguments for the Vigenère decryptor program.
#[derive(Parser, Debug)]
struct Cli {
    /// Path to the input file containing encrypted text
    #[arg(short, long, help = "Path to the input file containing encrypted text")]
    file: String,

    /// Path to the output file where decrypted text will be saved
    #[arg(short, long, help = "Path to the output file for decrypted text")]
    output: String,
}

/// German letter frequencies for frequency analysis
const GERMAN_FREQUENCIES: [f64; 26] = [
    0.0558, 0.0196, 0.0316, 0.0498, 0.1693, 0.0149, 0.0302, 0.0498,
    0.0802, 0.0024, 0.0132, 0.0360, 0.0255, 0.1053, 0.0224, 0.0067,
    0.0002, 0.0689, 0.0642, 0.0579, 0.0383, 0.0084, 0.0178, 0.0005,
    0.0005, 0.0121
];

const MAX_KEY_LENGTH: usize = 100;

fn main() {
    let cli: Cli = Cli::parse();
    let input: String = std::fs::read_to_string(&cli.file)
        .expect("Failed to read input file");

    // Clean text: only alphabetic characters, uppercase
    let clean_text = clean_text(&input);
    
    if clean_text.len() < 50 {
        eprintln!("Warning: Text may be too short for reliable analysis");
    }

    // Step 1: Find key length using Index of Coincidence
    let key_length = find_key_length(&clean_text);
    println!("Found key length: {}", key_length);
    
    // Step 2: Reconstruct the key using frequency analysis
    let key = reconstruct_key(&clean_text, key_length);
    
    // Step 3: Decrypt the original text
    let decrypted_text = vigenere_decrypt(&input, &key);
    
    // Output key to stdout (as required)
    println!("{}", key);
    
    // Write decrypted text to file
    std::fs::write(&cli.output, &decrypted_text)
        .expect("Failed to write output file");
}

/// Cleans text by keeping only alphabetic characters and converting to uppercase
fn clean_text(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Finds the most likely key length using Index of Coincidence analysis
fn find_key_length(text: &str) -> usize {
    let mut best_key_length: usize = 1;
    let mut best_average_ic: f64 = 0.0;
    let mut results: Vec<(usize, f64)> = Vec::new();
    
    // Test key lengths from 1 to MAX_KEY_LENGTH
    for key_length in 1..=MAX_KEY_LENGTH {
        let subtexts: Vec<String> = split_text_by_key_length(text, key_length);
        
        // Calculate IC for each subtext and compute average
        let mut total_ic = 0.0;
        let mut valid_subtexts = 0;
        
        for subtext in &subtexts {
            // Only consider subtexts with sufficient length for reliable IC
            if subtext.len() >= 2 {
                total_ic += calc_ic(subtext);
                valid_subtexts += 1;
            }
        }
        
        // Skip if no valid subtexts
        if valid_subtexts == 0 {
            continue;
        }
        
        let average_ic: f64 = total_ic / valid_subtexts as f64;
        results.push((key_length, average_ic));
        
        // Update best candidate if this one is better
        if average_ic > best_average_ic {
            best_average_ic = average_ic;
            best_key_length = key_length;
        }
        
        // Early termination if we find a very good candidate
        if average_ic > 0.07 && key_length <= 20 {
            break;
        }
    }
    
    // Prefer shorter keys if IC values are close
    let best_ic = best_average_ic;
    for (length, ic) in &results {
        // If a shorter key has IC within 5% of the best, prefer it
        if *length < best_key_length && *ic >= best_ic * 0.95 && *length <= 10 {
            return *length;
        }
    }
    
    // Fallback: if no good candidate found, try common key lengths
    if best_average_ic < 0.045 {
        let common_lengths = [2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut fallback_best = 1;
        let mut fallback_best_ic = 0.0;
        
        for &length in &common_lengths {
            let subtexts = split_text_by_key_length(text, length);
            let avg_ic: f64 = subtexts.iter()
                .map(|s| calc_ic(s))
                .sum::<f64>() / subtexts.len() as f64;
                
            if avg_ic > fallback_best_ic {
                fallback_best_ic = avg_ic;
                fallback_best = length;
            }
        }
        
        if fallback_best_ic > best_average_ic {
            return fallback_best;
        }
    }
    
    best_key_length
}

/// Splits text into subtexts based on key length
/// Each subtext contains characters encrypted with the same key character
fn split_text_by_key_length(text: &str, key_length: usize) -> Vec<String> {
    let mut subtexts = vec![String::new(); key_length];
    
    for (i, c) in text.chars().enumerate() {
        subtexts[i % key_length].push(c);
    }
    
    subtexts
}

/// Reconstructs the complete Vigenère key using frequency analysis
fn reconstruct_key(text: &str, key_length: usize) -> String {
    let subtexts = split_text_by_key_length(text, key_length);
    let mut key = String::new();

    for subtext in subtexts {
        let key_char = find_key_char_for_subtext(&subtext);
        key.push(key_char);
    }

    key
}

/// Finds the key character for a subtext using frequency analysis and chi-square test
fn find_key_char_for_subtext(subtext: &str) -> char {
    if subtext.is_empty() {
        return 'A';
    }

    let frequencies = count_frequencies(subtext);
    let mut best_shift = 0;
    let mut best_chi_squared = f64::INFINITY;
    let text_length = subtext.len() as f64;

    // Test all possible Caesar shifts (0-25)
    for shift in 0..26 {
        let mut chi_squared = 0.0;

        for i in 0..26 {
            let observed = frequencies[(i + shift) % 26] as f64;
            let expected = GERMAN_FREQUENCIES[i] * text_length;
            
            if expected > 0.0 {
                chi_squared += (observed - expected).powi(2) / expected;
            }
        }

        if chi_squared < best_chi_squared {
            best_chi_squared = chi_squared;
            best_shift = shift;
        }
    }

    (b'A' + best_shift as u8) as char
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
            // Convert to uppercase and calculate array index (A=0, B=1, etc.)
            let index: usize = (c.to_ascii_uppercase() as u8 - b'A') as usize;
            frequencies[index] += 1;
        }
    }
    
    frequencies
}

/// Decrypts Vigenère cipher text with given key, preserving original formatting and German umlauts
fn vigenere_decrypt(ciphertext: &str, key: &str) -> String {
    let mut result: String = String::new();
    let key_bytes: &[u8] = key.as_bytes();
    let key_len: usize = key_bytes.len();
    let mut key_index: usize = 0;

    // Process each character in the input content
    for c in ciphertext.chars() {
        if c.is_ascii_alphabetic() {
            // Determine base character ('A' or 'a') to preserve case
            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
            let byte = c as u8;
            
            // Get the key character and convert to shift value (0-25)
            let key_char = key_bytes[key_index % key_len].to_ascii_lowercase() - b'a';
            
            // Apply Vigenère decryption: (ciphertext - key + 26) mod 26
            let decrypted_byte = (byte - base + 26 - key_char) % 26 + base;
            result.push(decrypted_byte as char);
            
            // Only advance key index for alphabetic characters
            key_index += 1;
        } else {
            // Non-ASCII alphabetic characters (like ä, ö, ü, ß) and other characters remain unchanged
            result.push(c);
        }
    }

    result
}

/// Calculates the Index of Coincidence (IC) for the given text.
///
/// # Arguments
///
/// * `text` - The input text to analyze.
///
/// # Returns
///
/// The Index of Coincidence value (0.0 if text has < 2 alphabetic characters).
fn calc_ic(text: &str) -> f64 {
    // Use existing function to count letter frequencies
    let frequencies: [u32; 26] = count_frequencies(text);
    
    // Calculate total number of alphabetic characters
    let total: u32 = frequencies.iter().sum();

    // Return 0.0 if insufficient data for meaningful IC calculation
    if total < 2 {
        return 0.0;
    }

    // Calculate IC: sum of (frequency_i * (frequency_i - 1)) / (total * (total - 1))
    let numerator: f64 = frequencies.iter()
        .map(|&freq| (freq * (freq.saturating_sub(1))) as f64)
        .sum();
    
    let denominator = (total * (total - 1)) as f64;
    numerator / denominator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ic_calculation() {
        let uniform_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let ic = calc_ic(uniform_text);
        assert!(ic < 0.05); // Should be low for uniform distribution
    }

    #[test]
    fn test_split_text() {
        let text = "ABCDEFGH";
        let subtexts = split_text_by_key_length(text, 3);
        assert_eq!(subtexts[0], "ADG");
        assert_eq!(subtexts[1], "BEH"); 
        assert_eq!(subtexts[2], "CF");
    }

    #[test]
    fn test_decrypt() {
        let ciphertext = "RIJVS";
        let key = "KEY";
        let decrypted = vigenere_decrypt(ciphertext, key);
        assert_eq!(decrypted, "HELLO");
    }
}
