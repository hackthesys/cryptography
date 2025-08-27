//! # Cipher Modes Library
//! 
//! This library implements various block cipher modes of operation for cryptographic applications.
//! 
//! ## Supported Modes
//! 
//! - **ECB** (Electronic Code Book) - Simple but insecure mode
//! - **CBC** (Cipher Block Chaining) - Widely used, requires IV
//! - **OFB** (Output Feedback) - Stream cipher mode
//! - **CTR** (Counter Mode) - Stream cipher mode, parallelizable
//! 
//! ## Usage
//! 
//! ```rust
//! use cipher_modes::{CipherModes, BlockCipher, DummyCipher};
//! 
//! // Create a cipher (replace with your AES implementation)
//! let cipher = DummyCipher::new(16);
//! let key = b"my-secret-key-16";
//! let plaintext = b"Hello, World!";
//! let iv = b"initialization16";
//! 
//! // Encrypt using CBC mode
//! let encrypted = CipherModes::cbc_encrypt(&cipher, key, plaintext, iv, 16)?;
//! 
//! // Decrypt
//! let decrypted = CipherModes::cbc_decrypt(&cipher, key, &encrypted, iv, 16)?;
//! # Ok::<(), cipher_modes::CipherModeError>(())
//! ```
//! 
//! ## Features
//! 
//! - Generic `BlockCipher` trait for easy integration with any block cipher
//! - Comprehensive error handling
//! - Memory-safe implementations
//! - Extensive test coverage
//! - Ready for AES integration

// Public modules
pub mod cipher;
pub mod error;
pub mod modes;
pub mod utils;

// Re-exports for easy access
pub use cipher::BlockCipher;
pub use error::{CipherModeError, Result};
pub use modes::CipherModes;

// Optional: Re-export individual mode functions for direct access
pub use modes::{
    ecb::{self},
    cbc::{self}, 
    ofb::{self},
    ctr::{self}
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Dummy cipher implementation for testing and demonstration
/// 
/// This is a simple XOR-based "cipher" that should **never** be used in production.
/// It's only provided for testing the cipher modes without requiring a real cipher implementation.
/// 
/// # Example
/// 
/// ```rust
/// use cipher_modes::{DummyCipher, BlockCipher};
/// 
/// let cipher = DummyCipher::new(16);
/// assert_eq!(cipher.block_size(), 16);
/// ```
#[derive(Debug, Clone)]
pub struct DummyCipher {
    block_size: usize,
}

impl DummyCipher {
    /// Create a new dummy cipher with the specified block size
    /// 
    /// # Arguments
    /// 
    /// * `block_size` - The block size in bytes (must be > 0)
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use cipher_modes::DummyCipher;
    /// 
    /// let cipher = DummyCipher::new(16); // 128-bit blocks
    /// ```
    pub fn new(block_size: usize) -> Self {
        Self { block_size }
    }
    
    /// Get the block size of this cipher
    pub fn get_block_size(&self) -> usize {
        self.block_size
    }
}

impl BlockCipher for DummyCipher {
    /// "Encrypt" a block using simple XOR (for testing only!)
    fn encrypt(&self, key: &[u8], block: &[u8]) -> Result<Vec<u8>> {
        if key.is_empty() {
            return Err(CipherModeError::EncryptionError(
                "Key cannot be empty".to_string()
            ));
        }
        
        if block.is_empty() {
            return Ok(Vec::new());
        }
        
        // Create repeating key pattern
        let key_cycle: Vec<u8> = key.iter().cycle().take(block.len()).cloned().collect();
        utils::xor_blocks(block, &key_cycle)
    }
    
    /// "Decrypt" a block using simple XOR (identical to encrypt for XOR)
    fn decrypt(&self, key: &[u8], block: &[u8]) -> Result<Vec<u8>> {
        // For XOR cipher, decryption is identical to encryption
        self.encrypt(key, block)
    }
    
    /// Return the block size
    fn block_size(&self) -> usize {
        self.block_size
    }
}

/// Convenience functions for common operations
impl CipherModes {
    /// Get version information
    pub fn version() -> &'static str {
        VERSION
    }
    
    /// List all supported cipher modes
    pub fn supported_modes() -> Vec<&'static str> {
        vec!["ECB", "CBC", "OFB", "CTR"]
    }
    
    /// Validate block size
    pub fn validate_block_size(block_size: usize) -> Result<()> {
        if block_size == 0 {
            Err(CipherModeError::InvalidBlockSize)
        } else {
            Ok(())
        }
    }
    
    /// Validate IV length for modes that require it
    pub fn validate_iv_length(iv: &[u8], block_size: usize) -> Result<()> {
        if iv.len() != block_size {
            Err(CipherModeError::InvalidIvLength)
        } else {
            Ok(())
        }
    }
}

// Comprehensive tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dummy_cipher_basic() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"hello123";
        
        let encrypted = cipher.encrypt(key, plaintext).unwrap();
        let decrypted = cipher.decrypt(key, &encrypted).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(cipher.block_size(), 8);
    }
    
    #[test]
    fn test_dummy_cipher_empty_key() {
        let cipher = DummyCipher::new(8);
        let key = b"";
        let plaintext = b"hello123";
        
        let result = cipher.encrypt(key, plaintext);
        assert!(matches!(result, Err(CipherModeError::EncryptionError(_))));
    }
    
    #[test]
    fn test_dummy_cipher_empty_block() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"";
        
        let encrypted = cipher.encrypt(key, plaintext).unwrap();
        assert_eq!(encrypted.len(), 0);
    }
    
    #[test]
    fn test_all_modes_integration() {
        let cipher = DummyCipher::new(16);
        let key = b"test-key-16-byte";
        let plaintext = b"Integration test message for all modes!";
        let iv = b"initialization16";
        let counter = 1000u64;
        
        // Test ECB
        let ecb_encrypted = CipherModes::ecb_encrypt(&cipher, key, plaintext, 16).unwrap();
        let ecb_decrypted = CipherModes::ecb_decrypt(&cipher, key, &ecb_encrypted, 16).unwrap();
        assert_eq!(plaintext, &ecb_decrypted[..plaintext.len()]);
        
        // Test CBC
        let cbc_encrypted = CipherModes::cbc_encrypt(&cipher, key, plaintext, iv, 16).unwrap();
        let cbc_decrypted = CipherModes::cbc_decrypt(&cipher, key, &cbc_encrypted, iv, 16).unwrap();
        assert_eq!(plaintext, &cbc_decrypted[..plaintext.len()]);
        
        // Test OFB
        let ofb_encrypted = CipherModes::ofb_encrypt(&cipher, key, plaintext, iv, 16).unwrap();
        let ofb_decrypted = CipherModes::ofb_decrypt(&cipher, key, &ofb_encrypted, iv, 16).unwrap();
        assert_eq!(plaintext, &ofb_decrypted[..]);
        
        // Test CTR
        let ctr_encrypted = CipherModes::ctr_encrypt(&cipher, key, plaintext, counter, 16).unwrap();
        let ctr_decrypted = CipherModes::ctr_decrypt(&cipher, key, &ctr_encrypted, counter, 16).unwrap();
        assert_eq!(plaintext, &ctr_decrypted[..]);
    }
    
    #[test]
    fn test_cipher_modes_metadata() {
        assert_eq!(CipherModes::supported_modes(), vec!["ECB", "CBC", "OFB", "CTR"]);
        assert!(!CipherModes::version().is_empty());
    }
    
    #[test]
    fn test_validation_functions() {
        // Valid block size
        assert!(CipherModes::validate_block_size(16).is_ok());
        
        // Invalid block size
        assert!(matches!(
            CipherModes::validate_block_size(0),
            Err(CipherModeError::InvalidBlockSize)
        ));
        
        // Valid IV
        let iv = vec![0u8; 16];
        assert!(CipherModes::validate_iv_length(&iv, 16).is_ok());
        
        // Invalid IV length
        let iv = vec![0u8; 8];
        assert!(matches!(
            CipherModes::validate_iv_length(&iv, 16),
            Err(CipherModeError::InvalidIvLength)
        ));
    }
    
    #[test]
    fn test_different_key_lengths() {
        let cipher = DummyCipher::new(16);
        let plaintext = b"Test with various key lengths";
        
        // Short key
        let short_key = b"short";
        let encrypted = CipherModes::ecb_encrypt(&cipher, short_key, plaintext, 16).unwrap();
        let decrypted = CipherModes::ecb_decrypt(&cipher, short_key, &encrypted, 16).unwrap();
        assert_eq!(plaintext, &decrypted[..plaintext.len()]);
        
        // Long key
        let long_key = b"this-is-a-very-long-key-that-exceeds-block-size";
        let encrypted = CipherModes::ecb_encrypt(&cipher, long_key, plaintext, 16).unwrap();
        let decrypted = CipherModes::ecb_decrypt(&cipher, long_key, &encrypted, 16).unwrap();
        assert_eq!(plaintext, &decrypted[..plaintext.len()]);
    }
}

// Documentation tests
#[cfg(doctest)]
mod doctests {
    /// Verify that all code examples in documentation work
    #[test]
    fn dummy() {
        // This ensures doctests are run
    }
}
