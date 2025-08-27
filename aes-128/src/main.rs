//! AES-128 Implementierung in Rust
//! 
//! Implementiert die AES-128 Verschlüsselung und Entschlüsselung
//! gemäß den Spezifikationen aus der Kryptologie LAB Dokumentation.

use clap::{Parser, ValueEnum};
use std::fs;

// AES S-Box für SubBytes Transformation 【4-19】
const SBOX: [u8; 256] = [
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

// Inverse S-Box für Entschlüsselung
const INV_SBOX: [u8; 256] = [
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

/// Command-line arguments for the AES-128 cipher program.
#[derive(Parser, Debug)]
struct Cli {
    /// Path to the input file.
    #[arg(short, long, help = "Path to the input file")]
    file: String,

    /// Key for the cipher.
    #[arg(short, long, help = "File contains the Key for the cipher")]
    key: String,

    /// Path to the output file.
    #[arg(short, long, help = "Path to the output file")]
    output: String,

    /// Mode of operation (encrypt or decrypt).
    #[arg(short, long, help = "Mode of operation (encrypt/decrypt)")]
    mode: OperationMode,
}

/// Enum representing the mode of operation for the cipher.
#[derive(Clone, Debug, ValueEnum)]
enum OperationMode {
    /// Encrypt mode.
    Encrypt,
    /// Decrypt mode.
    Decrypt,
}

/// Repräsentiert einen AES-128 Block als 4x4 Matrix
/// Die Matrix wird spaltenweise gefüllt gemäß AES-Spezifikation 【4-13】
#[derive(Clone, Copy)]
struct AesBlock {
    data: [[u8; 4]; 4],
}

impl AesBlock {
    /// Erstellt einen neuen AES-Block aus 16 Bytes
    /// Bytes werden spaltenweise in die 4x4 Matrix eingefügt
    fn new(bytes: &[u8; 16]) -> Self {
        let mut data = [[0u8; 4]; 4];
        for col in 0..4 {
            for row in 0..4 {
                data[row][col] = bytes[col * 4 + row];
            }
        }
        AesBlock { data }
    }

    /// Konvertiert den Block zurück zu 16 Bytes
    fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for col in 0..4 {
            for row in 0..4 {
                bytes[col * 4 + row] = self.data[row][col];
            }
        }
        bytes
    }
}

/// SubBytes: Ersetzt jedes Byte durch den entsprechenden S-Box Wert 【4-6】
fn sub_bytes(block: &mut AesBlock) {
    for row in 0..4 {
        for col in 0..4 {
            block.data[row][col] = SBOX[block.data[row][col] as usize];
        }
    }
}

/// Inverse SubBytes für die Entschlüsselung
fn inv_sub_bytes(block: &mut AesBlock) {
    for row in 0..4 {
        for col in 0..4 {
            block.data[row][col] = INV_SBOX[block.data[row][col] as usize];
        }
    }
}

/// ShiftRows: Zyklische Verschiebung der Zeilen nach links 【4-8】【4-10】
/// Zeile 0: keine Verschiebung
/// Zeile 1: 1 Position nach links
/// Zeile 2: 2 Positionen nach links  
/// Zeile 3: 3 Positionen nach links
fn shift_rows(block: &mut AesBlock) {
    for row in 1..4 {
        let temp = block.data[row];
        for col in 0..4 {
            block.data[row][col] = temp[(col + row) % 4];
        }
    }
}

/// Inverse ShiftRows: Zyklische Verschiebung nach rechts 【6-7】
fn inv_shift_rows(block: &mut AesBlock) {
    for row in 1..4 {
        let temp = block.data[row];
        for col in 0..4 {
            block.data[row][col] = temp[(col + 4 - row) % 4];
        }
    }
}

/// Galois-Feld-Multiplikation in GF(2^8) 【4-18】
/// Verwendet das irreduzible Polynom x^8 + x^4 + x^3 + x + 1
fn gf_mult(a: u8, b: u8) -> u8 {
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
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1 = 0x11b, aber nur die unteren 8 Bits
        }
        b >>= 1;
    }
    result
}

/// MixColumns: Matrixmultiplikation in GF(2^8) 【4-16】
/// Verwendet die MixColumns-Matrix ohne Lookup-Tables (wie gefordert)
/// 
/// MixColumns-Matrix:
/// [2 3 1 1]
/// [1 2 3 1]
/// [1 1 2 3]
/// [3 1 1 2]
fn mix_columns(block: &mut AesBlock) {
    for col in 0..4 {
        let temp = [
            block.data[0][col],
            block.data[1][col], 
            block.data[2][col],
            block.data[3][col]
        ];
        
        // MixColumns-Matrix-Multiplikation ohne Lookup-Tables
        block.data[0][col] = gf_mult(2, temp[0]) ^ gf_mult(3, temp[1]) ^ temp[2] ^ temp[3];
        block.data[1][col] = temp[0] ^ gf_mult(2, temp[1]) ^ gf_mult(3, temp[2]) ^ temp[3];
        block.data[2][col] = temp[0] ^ temp[1] ^ gf_mult(2, temp[2]) ^ gf_mult(3, temp[3]);
        block.data[3][col] = gf_mult(3, temp[0]) ^ temp[1] ^ temp[2] ^ gf_mult(2, temp[3]);
    }
}

/// Inverse MixColumns für die Entschlüsselung
/// 
/// Inverse MixColumns-Matrix:
/// [0xE 0xB 0xD 0x9]
/// [0x9 0xE 0xB 0xD]
/// [0xD 0x9 0xE 0xB]
/// [0xB 0xD 0x9 0xE]
fn inv_mix_columns(block: &mut AesBlock) {
    for col in 0..4 {
        let temp = [
            block.data[0][col],
            block.data[1][col],
            block.data[2][col], 
            block.data[3][col]
        ];
        
        // Inverse MixColumns-Matrix-Multiplikation ohne Lookup-Tables
        block.data[0][col] = gf_mult(0x0e, temp[0]) ^ gf_mult(0x0b, temp[1]) ^ gf_mult(0x0d, temp[2]) ^ gf_mult(0x09, temp[3]);
        block.data[1][col] = gf_mult(0x09, temp[0]) ^ gf_mult(0x0e, temp[1]) ^ gf_mult(0x0b, temp[2]) ^ gf_mult(0x0d, temp[3]);
        block.data[2][col] = gf_mult(0x0d, temp[0]) ^ gf_mult(0x09, temp[1]) ^ gf_mult(0x0e, temp[2]) ^ gf_mult(0x0b, temp[3]);
        block.data[3][col] = gf_mult(0x0b, temp[0]) ^ gf_mult(0x0d, temp[1]) ^ gf_mult(0x09, temp[2]) ^ gf_mult(0x0e, temp[3]);
    }
}

/// AddRoundKey: XOR mit dem Rundenschlüssel 【4-13】
fn add_round_key(block: &mut AesBlock, round_key: &[u8; 16]) {
    let key_block = AesBlock::new(round_key);
    for row in 0..4 {
        for col in 0..4 {
            block.data[row][col] ^= key_block.data[row][col];
        }
    }
}

/// AES-128 Verschlüsselung 【4-2】【6-1】【6-2】
/// Führt 10 Runden der AES-Verschlüsselung durch:
/// 1. Initiale Rundenschlüssel-Addition
/// 2. 9 Hauptrunden (SubBytes, ShiftRows, MixColumns, AddRoundKey)
/// 3. Finale Runde ohne MixColumns (SubBytes, ShiftRows, AddRoundKey)
fn aes_encrypt(plaintext: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut block = AesBlock::new(plaintext);
    
    // Initiale Rundenschlüssel-Addition
    add_round_key(&mut block, &round_keys[0]);
    
    // 9 Hauptrunden (Runden 1-9)
    for round in 1..10 {
        sub_bytes(&mut block);
        shift_rows(&mut block);
        mix_columns(&mut block);
        add_round_key(&mut block, &round_keys[round]);
    }
    
    // Finale Runde (Runde 10) - ohne MixColumns
    sub_bytes(&mut block);
    shift_rows(&mut block);
    add_round_key(&mut block, &round_keys[10]);
    
    block.to_bytes()
}

/// AES-128 Entschlüsselung
/// Führt die inverse Reihenfolge der Transformationen durch:
/// 1. Initiale Rundenschlüssel-Addition (mit letztem Schlüssel)
/// 2. 9 Hauptrunden in umgekehrter Reihenfolge (InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns)
/// 3. Finale Runde ohne InvMixColumns (InvShiftRows, InvSubBytes, AddRoundKey)
fn aes_decrypt(ciphertext: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut block = AesBlock::new(ciphertext);
    
    // Initiale Rundenschlüssel-Addition (mit letztem Schlüssel)
    add_round_key(&mut block, &round_keys[10]);
    
    // 9 Hauptrunden in umgekehrter Reihenfolge (Runden 9-1)
    for round in (1..10).rev() {
        inv_shift_rows(&mut block);
        inv_sub_bytes(&mut block);
        add_round_key(&mut block, &round_keys[round]);
        inv_mix_columns(&mut block);
    }
    
    // Finale Runde (Runde 0) - ohne InvMixColumns
    inv_shift_rows(&mut block);
    inv_sub_bytes(&mut block);
    add_round_key(&mut block, &round_keys[0]);
    
    block.to_bytes()
}

/// Liest hexadezimale Daten aus einer Datei und ignoriert Leerzeichen und Zeilenumbrüche
fn read_hex_from_file(filename: &str) -> Vec<u8> {
    let content = fs::read_to_string(filename)
        .expect("Failed to read the input file");
    
    // Entferne Leerzeichen, Zeilenumbrüche und andere Whitespace-Zeichen
    let hex_string: String = content.chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    
    if hex_string.is_empty() {
        panic!("File is empty or contains no valid characters");
    }
    
    if hex_string.len() % 2 != 0 {
        panic!("Odd number of hexadecimal characters");
    }
    
    // Konvertiere hexadezimale Zeichen zu Bytes
    let mut bytes = Vec::new();
    for chunk in hex_string.as_bytes().chunks(2) {
        let hex_str = std::str::from_utf8(chunk)
            .expect("Invalid UTF-8 in hex string");
        let byte = u8::from_str_radix(hex_str, 16)
            .expect("Invalid hexadecimal character");
        bytes.push(byte);
    }
    
    bytes
}

/// Schreibt Bytes als hexadezimale Darstellung in eine Datei
fn write_hex_to_file(filename: &str, data: &[u8]) {
    let hex_string: String = data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ");  // ← Ein Leerzeichen zwischen Bytes
    
    fs::write(filename, hex_string)
        .expect("Failed to write the output file");
}



/// Extrahiert die 11 Rundenschlüssel aus den gegebenen Schlüsseldaten
fn extract_round_keys(key_data: &[u8]) -> [[u8; 16]; 11] {
    if key_data.len() != 176 { // 11 * 16 = 176 Bytes für 11 Rundenschlüssel
        panic!("Invalid key length: {} bytes, expected 176 bytes (11 round keys)", key_data.len());
    }
    
    let mut round_keys = [[0u8; 16]; 11];
    for i in 0..11 {
        round_keys[i].copy_from_slice(&key_data[i * 16..(i + 1) * 16]);
    }
    
    round_keys
}

fn main() {
    let cli = Cli::parse();
    
    // Eingabedatei lesen
    let text_data = read_hex_from_file(&cli.file);
    
    if text_data.len() != 16 {
        panic!("Input file must contain exactly 16 bytes (128 bit), found: {} bytes", text_data.len());
    }
    
    // Schlüsseldatei lesen
    let key_data = read_hex_from_file(&cli.key);
    let round_keys = extract_round_keys(&key_data);
    
    // Text-Block vorbereiten
    let mut text_block = [0u8; 16];
    text_block.copy_from_slice(&text_data);
    
    // Ver- oder Entschlüsselung durchführen
    let result = match cli.mode {
        OperationMode::Encrypt => aes_encrypt(&text_block, &round_keys),
        OperationMode::Decrypt => aes_decrypt(&text_block, &round_keys),
    };
    
    // Ergebnis in Datei schreiben
    write_hex_to_file(&cli.output, &result);
}
