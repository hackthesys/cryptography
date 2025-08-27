//! Error types for cipher mode operations

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CipherModeError {
    #[error("Invalid block size (must be > 0)")]
    InvalidBlockSize,
    
    #[error("Invalid IV length (must match block size)")]
    InvalidIvLength,
    
    #[error("Padding error")]
    PaddingError,
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

pub type Result<T> = std::result::Result<T, CipherModeError>;
