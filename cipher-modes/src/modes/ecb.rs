//! ECB (Electronic Code Book) mode implementation

use crate::{BlockCipher, Result, utils};

use super::CipherModes;

impl CipherModes {
    /// ECB mode encryption
    pub fn ecb_encrypt<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        plaintext: &[u8],
        block_size: usize,
    ) -> Result<Vec<u8>> {
        if block_size == 0 {
            return Err(crate::error::CipherModeError::InvalidBlockSize);
        }
        
        let padded_data: Vec<u8> = utils::add_padding(plaintext, block_size);
        let mut ciphertext: Vec<u8> = Vec::new();
        
        for chunk in padded_data.chunks(block_size) {
            let encrypted_block = cipher.encrypt(key, chunk)?;
            ciphertext.extend(encrypted_block);
        }
        
        Ok(ciphertext)
    }
    
    /// ECB mode decryption
    pub fn ecb_decrypt<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        ciphertext: &[u8],
        block_size: usize,
    ) -> Result<Vec<u8>> {
        if block_size == 0 {
            return Err(crate::error::CipherModeError::InvalidBlockSize);
        }
        
        if ciphertext.len() % block_size != 0 {
            return Err(crate::error::CipherModeError::PaddingError);
        }
        
        let mut plaintext = Vec::new();
        
        for chunk in ciphertext.chunks(block_size) {
            let decrypted_block = cipher.decrypt(key, chunk)?;
            plaintext.extend(decrypted_block);
        }
        
        Ok(utils::remove_padding(&plaintext))
    }
}
