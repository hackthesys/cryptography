//! Generic block cipher trait

use crate::error::Result;

/// Trait for a generic block cipher
pub trait BlockCipher {
    /// Encrypts a single block
    fn encrypt(&self, key: &[u8], block: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypts a single block
    fn decrypt(&self, key: &[u8], block: &[u8]) -> Result<Vec<u8>>;
    
    /// Returns the block size of the cipher
    fn block_size(&self) -> usize;
}
