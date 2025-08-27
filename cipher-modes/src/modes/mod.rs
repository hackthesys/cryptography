//! Cipher modes implementation

pub mod ecb;
pub mod cbc;
pub mod ofb;
pub mod ctr;

pub use ecb::*;
pub use cbc::*;
pub use ofb::*;
pub use ctr::*;

/// Main struct for cipher modes
pub struct CipherModes;
