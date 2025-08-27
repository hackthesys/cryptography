//! CTR (Counter) mode implementation

use crate::{BlockCipher, Result, utils, error::CipherModeError};

use super::CipherModes;

impl CipherModes {
    /// CTR mode encryption
    /// 
    /// In CTR mode, a counter is used which is incremented for each block.
    /// The encryption of the counter is XORed with the plaintext.
    /// 
    /// Algorithm:
    /// 1. T_i = ctr + i - 1 mod 2^m for i = 1, ..., n
    /// 2. C_i = P_i ⊕ E(K, T_i)
    pub fn ctr_encrypt<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        plaintext: &[u8],
        counter: u64,
        block_size: usize,
    ) -> Result<Vec<u8>> {
        if block_size == 0 {
            return Err(CipherModeError::InvalidBlockSize);
        }
        
        let mut ciphertext = Vec::new();
        let mut current_counter = counter;
        
        // Process each block of plaintext
        for chunk in plaintext.chunks(block_size) {
            // Convert counter to bytes (big-endian, padded to block size)
            let counter_bytes = Self::counter_to_bytes(current_counter, block_size);
            
            // Encrypt the counter
            let encrypted_counter = cipher.encrypt(key, &counter_bytes)?;
            
            // XOR with plaintext (only as many bytes as needed)
            let keystream = &encrypted_counter[..chunk.len().min(block_size)];
            let xored = utils::xor_blocks(chunk, keystream)?;
            ciphertext.extend(xored);
            
            // Increment counter for next block
            current_counter = current_counter.wrapping_add(1);
        }
        
        Ok(ciphertext)
    }
    
    /// CTR mode decryption
    /// 
    /// Since CTR is a stream cipher mode, decryption is identical to encryption.
    pub fn ctr_decrypt<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        ciphertext: &[u8],
        counter: u64,
        block_size: usize,
    ) -> Result<Vec<u8>> {
        // CTR decryption is identical to encryption
        Self::ctr_encrypt(cipher, key, ciphertext, counter, block_size)
    }
    
    /// Convert counter value to bytes with proper padding
    /// 
    /// The counter is converted to big-endian bytes and padded to block_size.
    /// For security, the counter should occupy the rightmost bytes.
    fn counter_to_bytes(counter: u64, block_size: usize) -> Vec<u8> {
        let mut counter_bytes = vec![0u8; block_size];
        let counter_be = counter.to_be_bytes();
        
        // Place counter bytes at the end (rightmost position)
        let offset = block_size.saturating_sub(8);
        let copy_len = 8.min(block_size);
        
        counter_bytes[offset..offset + copy_len]
            .copy_from_slice(&counter_be[8 - copy_len..]);
        
        counter_bytes
    }
    
    /// Advanced CTR mode with custom nonce and counter separation
    /// 
    /// This version allows specifying both a nonce and counter value separately,
    /// which is more secure for practical applications.
    pub fn ctr_encrypt_with_nonce<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
        counter: u32,
        block_size: usize,
    ) -> Result<Vec<u8>> {
        if block_size == 0 {
            return Err(CipherModeError::InvalidBlockSize);
        }
        
        if nonce.len() > block_size - 4 {
            return Err(CipherModeError::EncryptionError(
                "Nonce too long for block size".to_string()
            ));
        }
        
        let mut ciphertext = Vec::new();
        let mut current_counter = counter;
        
        for chunk in plaintext.chunks(block_size) {
            // Construct counter block: nonce || counter
            let mut counter_block = vec![0u8; block_size];
            
            // Copy nonce to the beginning
            counter_block[..nonce.len()].copy_from_slice(nonce);
            
            // Copy counter to the end (big-endian)
            let counter_start = block_size - 4;
            counter_block[counter_start..].copy_from_slice(&current_counter.to_be_bytes());
            
            // Encrypt the counter block
            let encrypted_counter = cipher.encrypt(key, &counter_block)?;
            
            // XOR with plaintext
            let keystream = &encrypted_counter[..chunk.len().min(block_size)];
            let xored = utils::xor_blocks(chunk, keystream)?;
            ciphertext.extend(xored);
            
            // Increment counter
            current_counter = current_counter.wrapping_add(1);
        }
        
        Ok(ciphertext)
    }
    
    /// Advanced CTR mode decryption with nonce
    pub fn ctr_decrypt_with_nonce<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        counter: u32,
        block_size: usize,
    ) -> Result<Vec<u8>> {
        // CTR decryption is identical to encryption
        Self::ctr_encrypt_with_nonce(cipher, key, ciphertext, nonce, counter, block_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DummyCipher;
    
    #[test]
    fn test_ctr_encrypt_decrypt() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"Hello World! This is a test message.";
        let counter = 1000u64;
        
        // Encrypt
        let ciphertext = CipherModes::ctr_encrypt(&cipher, key, plaintext, counter, 8).unwrap();
        
        // Decrypt
        let decrypted = CipherModes::ctr_decrypt(&cipher, key, &ciphertext, counter, 8).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_ctr_with_nonce() {
        let cipher = DummyCipher::new(16);
        let key = b"test-key-16-byte";
        let plaintext = b"Hello, CTR with nonce!";
        let nonce = b"unique-nonce";
        let counter = 1u32;
        
        // Encrypt
        let ciphertext = CipherModes::ctr_encrypt_with_nonce(
            &cipher, key, plaintext, nonce, counter, 16
        ).unwrap();
        
        // Decrypt
        let decrypted = CipherModes::ctr_decrypt_with_nonce(
            &cipher, key, &ciphertext, nonce, counter, 16
        ).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_counter_to_bytes() {
        let counter = 0x123456789ABCDEFu64;
        let bytes = CipherModes::counter_to_bytes(counter, 16);
        
        // Should be padded with zeros at the beginning
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[8..], &counter.to_be_bytes());
        assert_eq!(&bytes[..8], &[0u8; 8]);
    }
    
    #[test]
    fn test_ctr_partial_block() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"Hi"; // Less than block size
        let counter = 42u64;
        
        let ciphertext = CipherModes::ctr_encrypt(&cipher, key, plaintext, counter, 8).unwrap();
        let decrypted = CipherModes::ctr_decrypt(&cipher, key, &ciphertext, counter, 8).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(ciphertext.len(), plaintext.len()); // No padding in CTR
    }
    
    #[test]
    fn test_ctr_counter_overflow() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"Test overflow";
        let counter = u64::MAX; // Will overflow
        
        // Should not panic due to wrapping_add
        let ciphertext = CipherModes::ctr_encrypt(&cipher, key, plaintext, counter, 8).unwrap();
        let decrypted = CipherModes::ctr_decrypt(&cipher, key, &ciphertext, counter, 8).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
}
