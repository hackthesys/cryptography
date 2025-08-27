//! CBC (Cipher Block Chaining) mode implementation

use crate::{BlockCipher, Result, utils, error::CipherModeError};

use super::CipherModes;

impl CipherModes {
    /// CBC mode encryption
    pub fn cbc_encrypt<C: BlockCipher>(
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
        
        let padded_data = utils::add_padding(plaintext, block_size);
        let mut ciphertext = Vec::new();
        let mut previous_block = iv.to_vec();
        
        for chunk in padded_data.chunks(block_size) {
            let xored = utils::xor_blocks(chunk, &previous_block)?;
            let encrypted_block = cipher.encrypt(key, &xored)?;
            ciphertext.extend(&encrypted_block);
            previous_block = encrypted_block;
        }
        
        Ok(ciphertext)
    }
    
    /// CBC mode decryption
    pub fn cbc_decrypt<C: BlockCipher>(
        cipher: &C,
        key: &[u8],
        ciphertext: &[u8],
        iv: &[u8],
        block_size: usize,
    ) -> Result<Vec<u8>> {
        if block_size == 0 {
            return Err(CipherModeError::InvalidBlockSize);
        }
        
        if iv.len() != block_size {
            return Err(CipherModeError::InvalidIvLength);
        }
        
        if ciphertext.len() % block_size != 0 {
            return Err(CipherModeError::PaddingError);
        }
        
        let mut plaintext = Vec::new();
        let mut previous_block = iv.to_vec();
        
        for chunk in ciphertext.chunks(block_size) {
            let decrypted_block = cipher.decrypt(key, chunk)?;
            let xored = utils::xor_blocks(&decrypted_block, &previous_block)?;
            plaintext.extend(xored);
            previous_block = chunk.to_vec();
        }
        
        Ok(utils::remove_padding(&plaintext))
    }
}
