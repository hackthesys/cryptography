//! Utility functions for cipher modes

use crate::error::{Result, CipherModeError};

/// Add null padding to data
pub fn add_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    let remainder = data.len() % block_size;
    
    if remainder != 0 {
        let padding_needed = block_size - remainder;
        padded.extend(vec![0u8; padding_needed]);
    }
    
    padded
}

/// Remove null padding from data
pub fn remove_padding(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    while result.last() == Some(&0) && !result.is_empty() {
        result.pop();
    }
    result
}

/// XOR two byte arrays
pub fn xor_blocks(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != b.len() {
        return Err(CipherModeError::EncryptionError(
            "Blocks have different lengths for XOR".to_string()
        ));
    }
    
    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}
