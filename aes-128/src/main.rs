//! AES-128 Kryptographie-Implementierung mit 4 Betriebsmodi
//! 
//! Basierend auf den Spezifikationen aus der Kryptologie LAB
//! 
//! Unterstützte Features:
//! - AES-128 Ver- und Entschlüsselung mit vollständiger Schlüsselgenerierung
//! - 4 Betriebsmodi: ECB, CBC, CFB, CTR
//! - SubBytes, ShiftRows, MixColumns, AddRoundKey Operationen
//! - Hexadezimale Ein- und Ausgabe

use clap::{Parser, ValueEnum};
use std::fs;
use std::error::Error;
use std::fmt;

/// AES-128 Konstanten basierend auf der Spezifikation
const BLOCK_SIZE: usize = 16;        // 128 Bit = 16 Bytes
const KEY_SIZE: usize = 16;          // 128 Bit Schlüssel
const NUM_ROUNDS: usize = 10;        // 10 Runden für AES-128
const EXPANDED_KEY_SIZE: usize = 176; // 11 Rundenschlüssel × 16 Bytes

/// Verfügbare Betriebsmodi basierend auf Kryptologie LAB
#[derive(Debug, Clone, ValueEnum)]
enum OperationMode {
    /// Electronic Code Book - Jeder Block wird einzeln verschlüsselt
    Ecb,
    /// Cipher Block Chaining - Verkettung mit Initialisierungsvektor
    Cbc,
    /// Cipher Feedback - Stromchiffre-Modus
    Cfb,
    /// Counter Mode - Parallelisierbare Verschlüsselung
    Ctr,
}

/// Hauptkommandozeilen-Interface
#[derive(Parser)]
#[command(
    name = "aes-128-crypto",
    about = "AES-128 Verschlüsselung mit verschiedenen Betriebsmodi",
    long_about = "Vollständige AES-128 Implementierung für die Kryptologie LAB.\n\
                  Unterstützt ECB, CBC, CFB und CTR Betriebsmodi mit automatischer Schlüsselgenerierung."
)]
struct Cli {
    /// Betriebsmodus für die Verschlüsselung
    #[arg(long, value_enum, help = "Betriebsmodus: ECB, CBC, CFB oder CTR")]
    mode: OperationMode,
    
    /// Eingabedatei (Klartext oder Chiffretext)
    #[arg(short, long,help = "Pfad zur Eingabedatei mit hexadezimalen Daten")]
    input_file: String,
    
    /// Schlüsseldatei (128-Bit Schlüssel in Hex)
    #[arg(short, long, help = "Pfad zur Schlüsseldatei (128-Bit Schlüssel in Hexadezimal)")]
    key_file: String,
    
    /// Ausgabedatei für das Ergebnis
    #[arg(short, long,help = "Pfad zur Ausgabedatei")]
    output_file: String,
    
    /// Initialisierungsvektor (nur für CBC, CFB, CTR)
    #[arg(long, long, help = "IV in Hexadezimal (erforderlich für CBC, CFB, CTR)")]
    iv: Option<String>,
    
    /// Entschlüsselungsmodus aktivieren
    #[arg(short, long, help = "Entschlüsselung statt Verschlüsselung")]
    decrypt: bool,
}

/// Fehlertyp für AES-Operationen
#[derive(Debug)]
enum AesError {
    InvalidKeySize,
    InvalidBlockSize,
    InvalidHexData,
    MissingIv,
    FileError(String),
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AesError::InvalidKeySize => write!(f, "Ungültige Schlüsselgröße - muss 128 Bit (32 Hex-Zeichen) sein"),
            AesError::InvalidBlockSize => write!(f, "Ungültige Blockgröße - muss ein Vielfaches von 128 Bit sein"),
            AesError::InvalidHexData => write!(f, "Ungültige Hexadezimal-Daten"),
            AesError::MissingIv => write!(f, "Initialisierungsvektor (IV) erforderlich für diesen Modus"),
            AesError::FileError(msg) => write!(f, "Dateifehler: {}", msg),
        }
    }
}

impl Error for AesError {}

/// AES S-Box für SubBytes Transformation
/// Implementiert die nichtlineare Substitution basierend auf Galois-Feld F(2^8)
const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

/// Inverse S-Box für InvSubBytes Transformation
const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

/// Rcon-Konstanten für Schlüsselgenerierung
/// Diese Konstanten werden bei der AES-Schlüsselexpansion verwendet
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-Struktur für Verschlüsselungs- und Entschlüsselungsoperationen
struct Aes {
    expanded_key: [u8; EXPANDED_KEY_SIZE],
}

impl Aes {
    /// Erstelle eine neue AES-Instanz mit Schlüsselgenerierung
    /// 
    /// Der 128-Bit Schlüssel wird zu 11 Rundenschlüsseln expandiert (176 Bytes total)
    fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mut aes = Aes {
            expanded_key: [0; EXPANDED_KEY_SIZE],
        };
        aes.key_expansion(key);
        aes
    }

    /// AES-Schlüsselgenerierung (Key Expansion)
    /// 
    /// Algorithmus:
    /// 1. Kopiere ursprünglichen Schlüssel in die ersten 16 Bytes
    /// 2. Für jedes neue Wort: 
    ///    - Verwende RotWord und SubWord für jedes 4. Wort
    ///    - XOR mit Rcon-Konstante
    ///    - XOR mit dem Wort 4 Positionen früher
    fn key_expansion(&mut self, key: &[u8; KEY_SIZE]) {
        // Kopiere ursprünglichen Schlüssel
        self.expanded_key[..KEY_SIZE].copy_from_slice(key);
        
        // Generiere restliche Rundenschlüssel
        for i in (KEY_SIZE..EXPANDED_KEY_SIZE).step_by(4) {
            let mut temp = [
                self.expanded_key[i - 4],
                self.expanded_key[i - 3], 
                self.expanded_key[i - 2],
                self.expanded_key[i - 1],
            ];
            
            // Jedes 4. Wort (alle 16 Bytes) benötigt spezielle Behandlung
            if i % KEY_SIZE == 0 {
                // RotWord: Zyklische Rotation um 1 Byte nach links
                temp = [temp[1], temp[2], temp[3], temp[0]];
                
                // SubWord: Wende S-Box auf jedes Byte an
                for byte in &mut temp {
                    *byte = S_BOX[*byte as usize];
                }
                
                // XOR mit Rcon-Konstante
                temp[0] ^= RCON[i / KEY_SIZE];
            }
            
            // XOR mit dem Wort 16 Bytes früher
            for j in 0..4 {
                self.expanded_key[i + j] = self.expanded_key[i + j - KEY_SIZE] ^ temp[j];
            }
        }
    }

    /// AES-Verschlüsselung eines 128-Bit Blocks
    /// 
    /// Algorithmus:
    /// 1. Initial AddRoundKey
    /// 2. 9 Runden: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey  
    /// 3. Finale Runde: SubBytes -> ShiftRows -> AddRoundKey (ohne MixColumns)
    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // Als 4x4 Matrix für einfachere Verarbeitung
        let mut state = self.bytes_to_state(block);
        
        // Initial round
        self.add_round_key(&mut state, 0);
        
        // Main rounds (1-9)
        for round in 1..NUM_ROUNDS {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            self.add_round_key(&mut state, round);
        }
        
        // Final round (10) - ohne MixColumns
        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, NUM_ROUNDS);
        
        // Zurück zu Byte-Array
        *block = self.state_to_bytes(&state);
    }

    /// AES-Entschlüsselung eines 128-Bit Blocks
    /// 
    /// Umgekehrte Reihenfolge der Verschlüsselungsoperationen mit inversen Funktionen
    fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut state = self.bytes_to_state(block);
        
        // Erste inverse Runde
        self.add_round_key(&mut state, NUM_ROUNDS);
        self.inv_shift_rows(&mut state);
        self.inv_sub_bytes(&mut state);
        
        // Hauptrunden (9-1) in umgekehrter Reihenfolge
        for round in (1..NUM_ROUNDS).rev() {
            self.add_round_key(&mut state, round);
            self.inv_mix_columns(&mut state);
            self.inv_shift_rows(&mut state);
            self.inv_sub_bytes(&mut state);
        }
        
        // Finale Runde
        self.add_round_key(&mut state, 0);
        
        *block = self.state_to_bytes(&state);
    }

    /// SubBytes Transformation - Nichtlineare Substitution
    /// 
    /// Jedes Byte wird durch den entsprechenden S-Box Wert ersetzt
    /// Basis: Inverse im Galois-Feld F(2^8) gefolgt von affiner Transformation
    fn sub_bytes(&self, state: &mut [[u8; 4]; 4]) {
        for row in state.iter_mut() {
            for byte in row.iter_mut() {
                *byte = S_BOX[*byte as usize];
            }
        }
    }

    /// Inverse SubBytes Transformation
    fn inv_sub_bytes(&self, state: &mut [[u8; 4]; 4]) {
        for row in state.iter_mut() {
            for byte in row.iter_mut() {
                *byte = INV_S_BOX[*byte as usize];
            }
        }
    }

    /// ShiftRows Transformation - Zyklische Zeilenverschiebung
    /// 
    /// - Zeile 0: keine Verschiebung
    /// - Zeile 1: 1 Position nach links
    /// - Zeile 2: 2 Positionen nach links  
    /// - Zeile 3: 3 Positionen nach links
    fn shift_rows(&self, state: &mut [[u8; 4]; 4]) {
        // Zeile 1: 1 nach links
        let temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;
        
        // Zeile 2: 2 nach links
        let temp1 = state[2][0];
        let temp2 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = temp1;
        state[2][3] = temp2;
        
        // Zeile 3: 3 nach links (= 1 nach rechts)
        let temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
    }

    /// Inverse ShiftRows - Verschiebung in entgegengesetzte Richtung
    fn inv_shift_rows(&self, state: &mut [[u8; 4]; 4]) {
        // Zeile 1: 1 nach rechts
        let temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;
        
        // Zeile 2: 2 nach rechts
        let temp1 = state[2][2];
        let temp2 = state[2][3];
        state[2][2] = state[2][0];
        state[2][3] = state[2][1];
        state[2][0] = temp1;
        state[2][1] = temp2;
        
        // Zeile 3: 3 nach rechts (= 1 nach links)
        let temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    /// MixColumns Transformation - Spaltenweise lineare Transformation
    /// 
    /// Jede Spalte wird als Polynom im Galois-Feld F(2^8) behandelt
    /// Multiplikation mit festem Polynom: 03x³ + 01x² + 01x + 02
    fn mix_columns(&self, state: &mut [[u8; 4]; 4]) {
        for col in 0..4 {
            let s0 = state[0][col];
            let s1 = state[1][col]; 
            let s2 = state[2][col];
            let s3 = state[3][col];
            
            state[0][col] = Self::gf_mul(0x02, s0) ^ Self::gf_mul(0x03, s1) ^ s2 ^ s3;
            state[1][col] = s0 ^ Self::gf_mul(0x02, s1) ^ Self::gf_mul(0x03, s2) ^ s3;
            state[2][col] = s0 ^ s1 ^ Self::gf_mul(0x02, s2) ^ Self::gf_mul(0x03, s3);
            state[3][col] = Self::gf_mul(0x03, s0) ^ s1 ^ s2 ^ Self::gf_mul(0x02, s3);
        }
    }

    /// Inverse MixColumns Transformation
    /// Verwendet inverse Matrix: 0B 0D 09 0E
    fn inv_mix_columns(&self, state: &mut [[u8; 4]; 4]) {
        for col in 0..4 {
            let s0 = state[0][col];
            let s1 = state[1][col];
            let s2 = state[2][col]; 
            let s3 = state[3][col];
            
            state[0][col] = Self::gf_mul(0x0e, s0) ^ Self::gf_mul(0x0b, s1) ^ Self::gf_mul(0x0d, s2) ^ Self::gf_mul(0x09, s3);
            state[1][col] = Self::gf_mul(0x09, s0) ^ Self::gf_mul(0x0e, s1) ^ Self::gf_mul(0x0b, s2) ^ Self::gf_mul(0x0d, s3);
            state[2][col] = Self::gf_mul(0x0d, s0) ^ Self::gf_mul(0x09, s1) ^ Self::gf_mul(0x0e, s2) ^ Self::gf_mul(0x0b, s3);
            state[3][col] = Self::gf_mul(0x0b, s0) ^ Self::gf_mul(0x0d, s1) ^ Self::gf_mul(0x09, s2) ^ Self::gf_mul(0x0e, s3);
        }
    }

    /// AddRoundKey - XOR mit Rundenschlüssel
    /// 
    /// Jeder Byte des Zustands wird mit dem entsprechenden Rundenschlüssel-Byte XOR-verknüpft
    fn add_round_key(&self, state: &mut [[u8; 4]; 4], round: usize) {
        let round_key_start = round * BLOCK_SIZE;
        for (i, row) in state.iter_mut().enumerate() {
            for (j, byte) in row.iter_mut().enumerate() {
                *byte ^= self.expanded_key[round_key_start + i + 4 * j];
            }
        }
    }

    /// Galois-Feld Multiplikation in F(2^8)
    /// 
    /// Verwendet für MixColumns Operation
    /// Das irreduzible Polynom ist: x^8 + x^4 + x^3 + x + 1 (0x11b)
    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut result = 0;
        let mut a = a;
        let mut b = b;
        
        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }
            let high_bit = a & 0x80;
            a <<= 1;
            if high_bit != 0 {
                a ^= 0x1b; // Irreduzibles Polynom
            }
            b >>= 1;
        }
        result
    }

    /// Konvertiere Byte-Array zu 4x4 State-Matrix
    /// 
    /// AES verarbeitet Daten spaltenweise
    fn bytes_to_state(&self, bytes: &[u8; BLOCK_SIZE]) -> [[u8; 4]; 4] {
        let mut state = [[0u8; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = bytes[i + 4 * j];
            }
        }
        state
    }

    /// Konvertiere 4x4 State-Matrix zurück zu Byte-Array
    fn state_to_bytes(&self, state: &[[u8; 4]; 4]) -> [u8; BLOCK_SIZE] {
        let mut bytes = [0u8; BLOCK_SIZE];
        for i in 0..4 {
            for j in 0..4 {
                bytes[i + 4 * j] = state[i][j];
            }
        }
        bytes
    }
}

/// Betriebsmodi-Implementierungen

/// ECB (Electronic Code Book) Modus
/// 
/// Jeder Block wird unabhängig verschlüsselt
/// Nachteile: Gleiche Blöcke ergeben gleiche Chiffrate, Muster bleiben erkennbar
fn ecb_encrypt(aes: &Aes, data: &mut [u8]) {
    for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        aes.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
}

fn ecb_decrypt(aes: &Aes, data: &mut [u8]) {
    for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        aes.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
}

/// CBC (Cipher Block Chaining) Modus
/// 
/// Jeder Block wird vor der Verschlüsselung mit dem vorherigen Chiffreblock XOR-verknüpft
/// Verwendet Initialisierungsvektor (IV) für den ersten Block
fn cbc_encrypt(aes: &Aes, data: &mut [u8], iv: &[u8; BLOCK_SIZE]) {
    let mut prev_block = *iv;
    
    for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
        // XOR mit vorherigem Block
        for i in 0..BLOCK_SIZE {
            chunk[i] ^= prev_block[i];
        }
        
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        aes.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        prev_block = block;
    }
}

fn cbc_decrypt(aes: &Aes, data: &mut [u8], iv: &[u8; BLOCK_SIZE]) {
    let mut prev_block = *iv;
    
    for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
        let current_cipher = {
            let mut temp = [0u8; BLOCK_SIZE];
            temp.copy_from_slice(chunk);
            temp
        };
        
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        aes.decrypt_block(&mut block);
        
        // XOR mit vorherigem Block
        for i in 0..BLOCK_SIZE {
            block[i] ^= prev_block[i];
        }
        
        chunk.copy_from_slice(&block);
        prev_block = current_cipher;
    }
}

/// CFB (Cipher Feedback) Modus
/// 
/// Stromchiffre-Modus: Verschlüsselung des Shift-Registers, XOR mit Klartext
fn cfb_encrypt(aes: &Aes, data: &mut [u8], iv: &[u8; BLOCK_SIZE]) {
    let mut shift_register = *iv;
    
    for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
        let mut keystream = shift_register;
        aes.encrypt_block(&mut keystream);
        
        // XOR Klartext mit Keystream
        for i in 0..BLOCK_SIZE {
            chunk[i] ^= keystream[i];
        }
        
        // Shift Register = Chiffretext
        shift_register.copy_from_slice(chunk);
    }
}

fn cfb_decrypt(aes: &Aes, data: &mut [u8], iv: &[u8; BLOCK_SIZE]) {
    let mut shift_register = *iv;
    
    for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
        let mut keystream = shift_register;
        aes.encrypt_block(&mut keystream); // CFB verwendet immer Verschlüsselung
        
        // Shift Register = aktueller Chiffretext (vor Entschlüsselung)
        let current_cipher = {
            let mut temp = [0u8; BLOCK_SIZE];
            temp.copy_from_slice(chunk);
            temp
        };
        
        // XOR Chiffretext mit Keystream
        for i in 0..BLOCK_SIZE {
            chunk[i] ^= keystream[i];
        }
        
        shift_register = current_cipher;
    }
}

/// CTR (Counter) Modus
/// 
/// Verschlüsselung eines Zählers, XOR mit Klartext
/// Parallelisierbar und identisch für Ver- und Entschlüsselung
fn ctr_encrypt_decrypt(aes: &Aes, data: &mut [u8], nonce: &[u8; BLOCK_SIZE]) {
    let mut counter = u128::from_be_bytes(*nonce);
    
    for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
        let mut counter_block = counter.to_be_bytes();
        aes.encrypt_block(&mut counter_block);
        
        // XOR mit Keystream
        for i in 0..BLOCK_SIZE {
            chunk[i] ^= counter_block[i];
        }
        
        counter = counter.wrapping_add(1);
    }
}

/// Hilfsfunktionen für Datenverarbeitung

/// Parse hexadezimale Daten und ignoriere Whitespace
fn parse_hex_data(hex_str: &str) -> Result<Vec<u8>, AesError> {
    let clean_hex: String = hex_str.chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    
    hex::decode(&clean_hex).map_err(|_| AesError::InvalidHexData)
}

/// Konvertiere Bytes zu Hexadezimal-String
fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Füge PKCS#7 Padding hinzu (für ECB/CBC)
fn add_padding(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    let padding_byte = padding_len as u8;
    data.extend(vec![padding_byte; padding_len]);
}

/// Entferne PKCS#7 Padding
/// Entferne PKCS#7 Padding
fn remove_padding(data: &mut Vec<u8>) -> Result<(), AesError> {
    if data.is_empty() {
        return Err(AesError::InvalidBlockSize);
    }
    
    let padding_len = *data.last().unwrap() as usize;
    if padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > data.len() {
        return Err(AesError::InvalidBlockSize);
    }
    
    // Überprüfe, ob alle Padding-Bytes korrekt sind
    let data_len = data.len();
    for &byte in &data[data_len - padding_len..] {
        if byte != padding_len as u8 {
            return Err(AesError::InvalidBlockSize);
        }
    }
    
    data.truncate(data_len - padding_len);
    Ok(())
}

/// Hauptfunktion - Verarbeitet Command Line Arguments und führt AES-Operationen aus
fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    
    // Lade und validiere Eingabedaten
    let input_data = fs::read_to_string(&cli.input_file)
        .map_err(|e| AesError::FileError(format!("Fehler beim Lesen der Eingabedatei: {}", e)))?;
    
    let mut data = parse_hex_data(&input_data)?;
    
    // Lade und validiere Schlüssel
    let key_data = fs::read_to_string(&cli.key_file)
        .map_err(|e| AesError::FileError(format!("Fehler beim Lesen der Schlüsseldatei: {}", e)))?;
    
    let key_bytes = parse_hex_data(&key_data)?;
    if key_bytes.len() != KEY_SIZE {
        return Err(Box::new(AesError::InvalidKeySize));
    }
    
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes);
    
    // Validiere und parse IV wenn erforderlich
    let iv = match &cli.mode {
        OperationMode::Ecb => None,
        _ => {
            let iv_str = cli.iv.as_ref().ok_or(AesError::MissingIv)?;
            let iv_bytes = parse_hex_data(iv_str)?;
            if iv_bytes.len() != BLOCK_SIZE {
                return Err(Box::new(AesError::InvalidBlockSize));
            }
            let mut iv_array = [0u8; BLOCK_SIZE];
            iv_array.copy_from_slice(&iv_bytes);
            Some(iv_array)
        }
    };
    
    // Erstelle AES-Instanz mit Schlüsselgenerierung
    let aes = Aes::new(&key);
    
    // Verarbeite Daten je nach Modus und Operation
    match cli.mode {
        OperationMode::Ecb => {
            if !cli.decrypt {
                // Verschlüsselung: Füge Padding hinzu
                add_padding(&mut data, BLOCK_SIZE);
                if data.len() % BLOCK_SIZE != 0 {
                    return Err(Box::new(AesError::InvalidBlockSize));
                }
                ecb_encrypt(&aes, &mut data);
            } else {
                // Entschlüsselung: Validiere Blockgröße
                if data.len() % BLOCK_SIZE != 0 {
                    return Err(Box::new(AesError::InvalidBlockSize));
                }
                ecb_decrypt(&aes, &mut data);
                remove_padding(&mut data)?;
            }
        },
        
        OperationMode::Cbc => {
            let iv_array = iv.unwrap();
            if !cli.decrypt {
                // Verschlüsselung: Füge Padding hinzu
                add_padding(&mut data, BLOCK_SIZE);
                if data.len() % BLOCK_SIZE != 0 {
                    return Err(Box::new(AesError::InvalidBlockSize));
                }
                cbc_encrypt(&aes, &mut data, &iv_array);
            } else {
                // Entschlüsselung: Validiere Blockgröße
                if data.len() % BLOCK_SIZE != 0 {
                    return Err(Box::new(AesError::InvalidBlockSize));
                }
                cbc_decrypt(&aes, &mut data, &iv_array);
                remove_padding(&mut data)?;
            }
        },
        
        OperationMode::Cfb => {
            let iv_array = iv.unwrap();
            // CFB benötigt Padding auf Blockgröße für vollständige Blöcke
            if data.len() % BLOCK_SIZE != 0 {
                data.resize((data.len() + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE, 0);
            }
            
            if !cli.decrypt {
                cfb_encrypt(&aes, &mut data, &iv_array);
            } else {
                cfb_decrypt(&aes, &mut data, &iv_array);
            }
        },
        
        OperationMode::Ctr => {
            let nonce = iv.unwrap();
            // CTR kann mit beliebigen Datengrößen arbeiten, aber wir verwenden Blockgröße
            if data.len() % BLOCK_SIZE != 0 {
                data.resize((data.len() + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE, 0);
            }
            
            // CTR ist symmetrisch - gleiche Funktion für Ver- und Entschlüsselung
            ctr_encrypt_decrypt(&aes, &mut data, &nonce);
        },
    }
    
    // Schreibe Ergebnis in Ausgabedatei
    let output_hex = bytes_to_hex(&data);
    fs::write(&cli.output_file, &output_hex)
        .map_err(|e| AesError::FileError(format!("Fehler beim Schreiben der Ausgabedatei: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test der AES-Verschlüsselung mit bekannten Testvektoren
    #[test]
    fn test_aes_encrypt_decrypt() {
        // NIST Test Vector
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        let plaintext = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
        ];
        let expected_ciphertext = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
        ];

        let aes = Aes::new(&key);
        let mut block = plaintext;
        
        // Test Verschlüsselung
        aes.encrypt_block(&mut block);
        assert_eq!(block, expected_ciphertext);
        
        // Test Entschlüsselung
        aes.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    /// Test der S-Box Transformation
    #[test]
    fn test_s_box() {
        // Bekannte S-Box Werte testen
        assert_eq!(S_BOX[0x00], 0x63);
        assert_eq!(S_BOX[0x01], 0x7c);
        assert_eq!(S_BOX[0xff], 0x16);
        
        // Test Symmetrie mit inverser S-Box
        for i in 0..256 {
            let s_val = S_BOX[i];
            assert_eq!(INV_S_BOX[s_val as usize], i as u8);
        }
    }

    /// Test der Galois-Feld Multiplikation
    #[test]
    fn test_gf_multiplication() {
        // Bekannte GF(2^8) Multiplikationen
        assert_eq!(Aes::gf_mul(0x02, 0x01), 0x02);
        assert_eq!(Aes::gf_mul(0x02, 0x02), 0x04);
        assert_eq!(Aes::gf_mul(0x02, 0x80), 0x1b); // Überlauf-Test
        assert_eq!(Aes::gf_mul(0x03, 0x01), 0x03);
    }

    /// Test der Hex-Parsing Funktion
    #[test]
    fn test_hex_parsing() {
        let hex_str = "2b 7e 15 16\n28 ae d2 a6";
        let expected = vec![0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6];
        
        let result = parse_hex_data(hex_str).unwrap();
        assert_eq!(result, expected);
    }

    /// Test des PKCS#7 Padding
    #[test]
    fn test_padding() {
        let mut data = vec![1, 2, 3, 4, 5];
        add_padding(&mut data, 8);
        assert_eq!(data, vec![1, 2, 3, 4, 5, 3, 3, 3]);
        
        remove_padding(&mut data).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4, 5]);
    }
}
