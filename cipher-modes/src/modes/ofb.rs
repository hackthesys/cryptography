//! OFB (Output Feedback) mode implementation

use crate::{BlockCipher, Result, utils, error::CipherModeError};

use super::CipherModes;

impl CipherModes {
    /// OFB mode encryption
    /// 
    /// In OFB mode, the block cipher is used to generate a pseudorandom keystream
    /// which is then XORed with the plaintext.
    /// 
    /// Algorithm:
    /// 1. O_0 = IV
    /// 2. O_i = E(K, O_{i-1}) for i = 1, 2, ..., n
    /// 3. C_i = P_i ⊕ O_i
    pub fn ofb_encrypt<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        plaintext: &[u8],
        iv: &[u8],
        block_size: usize,
    ) -> Result<Vec<u8>> {
        if block_size == 0 {
            return Err(CipherModeError::InvalidBlockSize);
        }
        
        if iv.len() != block_size {
            return Err(CipherModeError::InvalidIvLength);
        }
        
        let mut ciphertext = Vec::new();
        let mut feedback = iv.to_vec();
        
        // Process each block of plaintext
        for chunk in plaintext.chunks(block_size) {
            // Generate new feedback value by encrypting previous feedback
            feedback = cipher.encrypt(key, &feedback)?;
            
            // XOR with plaintext (only as many bytes as needed)
            let keystream = &feedback[..chunk.len().min(block_size)];
            let xored = utils::xor_blocks(chunk, keystream)?;
            ciphertext.extend(xored);
        }
        
        Ok(ciphertext)
    }
    
    /// OFB mode decryption
    /// 
    /// Since OFB is a stream cipher mode, decryption is identical to encryption.
    pub fn ofb_decrypt<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        ciphertext: &[u8],
        iv: &[u8],
        block_size: usize,
    ) -> Result<Vec<u8>> {
        // OFB decryption is identical to encryption
        Self::ofb_encrypt(cipher, key, ciphertext, iv, block_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DummyCipher;
    
    #[test]
    fn test_ofb_encrypt_decrypt() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"Hello World! This is a test message.";
        let iv = b"initialv";
        
        // Encrypt
        let ciphertext = CipherModes::ofb_encrypt(&cipher, key, plaintext, iv, 8).unwrap();
        
        // Decrypt
        let decrypted = CipherModes::ofb_decrypt(&cipher, key, &ciphertext, iv, 8).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_ofb_invalid_iv_length() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"Hello";
        let iv = b"short"; // Wrong length
        
        let result = CipherModes::ofb_encrypt(&cipher, key, plaintext, iv, 8);
        assert!(matches!(result, Err(CipherModeError::InvalidIvLength)));
    }
    
    #[test]
    fn test_ofb_partial_block() {
        let cipher = DummyCipher::new(8);
        let key = b"testkey1";
        let plaintext = b"Hi"; // Less than block size
        let iv = b"initialv";
        
        let ciphertext = CipherModes::ofb_encrypt(&cipher, key, plaintext, iv, 8).unwrap();
        let decrypted = CipherModes::ofb_decrypt(&cipher, key, &ciphertext, iv, 8).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(ciphertext.len(), plaintext.len()); // No padding in OFB
    }
}
