//! SHA3-224 Implementierung in Rust mit CLI Interface
//! 
//! Diese Implementierung folgt dem NIST FIPS 202 Standard für SHA-3.
//! Sie verwendet die Keccak-Permutation mit 24 Runden und implementiert
//! die Sponge-Konstruktion für SHA3-224.

use clap::Parser;
use std::fs;

/// SHA3-224 Parameter basierend auf NIST FIPS 202
const HASH_SIZE: usize = 224; // Ausgabe-Größe in Bits
const RATE: usize = 1152;     // Blockgröße (rate) in Bits
const CAPACITY: usize = 448;  // Kapazität in Bits  
const STATE_SIZE: usize = 1600; // Gesamte Zustandsgröße b = r + c
const ROUNDS: usize = 24;     // Anzahl der Keccak-Runden

/// Round Constants für die ι (Iota) Funktion
/// Diese Konstanten stammen aus der NIST-Spezifikation【6-0】
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation-Offsets für die ρ (Rho) Funktion
/// Diese definieren die zyklischen Links-Shifts für jede Position im 5x5 Array
const RHO_OFFSETS: [[usize; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

/// CLI-Argumente für den SHA3-224 Hasher
/// 
/// Diese Struktur definiert alle Kommandozeilen-Argumente mit clap derive.
/// Das Programm arbeitet still - keine stdout-Ausgaben, nur Fehler auf stderr.
#[derive(Parser)]
#[command(
    name = "sha3",
    version = "1.0.0",
    author = "Kryptologie LAB",
    about = "SHA3-224 Hash-Berechnung für Hexadezimal-Eingaben"
)]
pub struct Cli {
    /// Eingabedatei mit Hexadezimalziffern
    /// 
    /// Die Datei sollte Hexadezimalzeichen (0-9, a-f, A-F) enthalten.
    /// Whitespace wird automatisch entfernt.
    #[arg(
        short = 'i',
        long = "input",
        value_name = "FILE",
        default_value = "Input.txt",
        help = "Eingabedatei mit Hexadezimalziffern"
    )]
    pub input: String,

    /// Ausgabedatei für den Hashwert
    /// 
    /// Der berechnete SHA3-224 Hash wird als Hexadezimalstring geschrieben.
    #[arg(
        short = 'o',
        long = "output", 
        value_name = "FILE",
        default_value = "Output.txt",
        help = "Ausgabedatei für den Hashwert (Hexadezimal)"
    )]
    pub output: String,
}

/// SHA3-224 Hasher Struktur
/// 
/// Diese Struktur kapselt den internen Zustand des SHA3-Hashers.
/// Der Zustand wird als 5x5 Array von 64-Bit Worten dargestellt.
pub struct Sha3_224 {
    /// Interner Zustand: 5x5 Array von 64-Bit Worten (insgesamt 1600 Bits)
    state: [[u64; 5]; 5],
    /// Puffer für eingehende Daten (rate / 8 Bytes)
    buffer: Vec<u8>,
    /// Anzahl der Bytes im Puffer
    buffer_len: usize,
}

impl Sha3_224 {
    /// Erstellt einen neuen SHA3-224 Hasher
    /// 
    /// # Returns
    /// 
    /// Einen neuen, initialisierten Hasher mit leerem Zustand
    pub fn new() -> Self {
        Self {
            state: [[0u64; 5]; 5],
            buffer: vec![0u8; RATE / 8], // 144 Bytes Puffer
            buffer_len: 0,
        }
    }

    /// Aktualisiert den Hasher mit neuen Eingabedaten
    /// 
    /// Diese Methode implementiert die "Absorb"-Phase der Sponge-Konstruktion.
    /// Daten werden blockweise verarbeitet, wenn der Puffer voll ist.
    /// 
    /// # Arguments
    /// 
    /// * `data` - Die zu hashenden Eingabedaten als Byte-Slice
    pub fn update(&mut self, data: &[u8]) {
        let mut input = data;
        
        // Verarbeite alle verfügbaren Daten
        while !input.is_empty() {
            // Berechne verfügbaren Platz im Puffer
            let available = (RATE / 8) - self.buffer_len;
            let to_copy = input.len().min(available);
            
            // Kopiere Daten in den Puffer
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&input[..to_copy]);
            self.buffer_len += to_copy;
            input = &input[to_copy..];
            
            // Wenn Puffer voll ist, verarbeite den Block
            if self.buffer_len == RATE / 8 {
                // Klone den Puffer, um Borrow-Checker-Probleme zu vermeiden
                let buffer_copy = self.buffer.clone();
                self.absorb_block(&buffer_copy);
                self.buffer_len = 0;
            }
        }
    }

    /// Finalisiert den Hash und gibt das Ergebnis zurück
    /// 
    /// Diese Methode implementiert das Padding und die "Squeeze"-Phase.
    /// Das SHA3-Padding folgt dem Schema: 0110*1
    /// 
    /// # Returns
    /// 
    /// Den finalen Hash als Vektor von 28 Bytes (224 Bits)
    pub fn finalize(mut self) -> Vec<u8> {
        // SHA3-Padding: 0110*1 (mindestens 2 Bits)
        // Füge 0x06 (0110 in binär) hinzu
        self.buffer[self.buffer_len] = 0x06;
        self.buffer_len += 1;
        
        // Fülle mit Nullen bis zum letzten Byte
        for i in self.buffer_len..RATE / 8 - 1 {
            self.buffer[i] = 0x00;
        }
        
        // Setze das letzte Bit (0x80 = 10000000)
        self.buffer[RATE / 8 - 1] |= 0x80;
        
        // Klone den Puffer für die finale Absorption
        let buffer_copy = self.buffer.clone();
        self.absorb_block(&buffer_copy);
        
        // Squeeze-Phase: Extrahiere die ersten 224 Bits
        self.squeeze()
    }

    /// Absorbiert einen Block in den Zustand
    /// 
    /// # Arguments
    /// 
    /// * `block` - Der zu absorbierende Block (144 Bytes)
    fn absorb_block(&mut self, block: &[u8]) {
        // XOR den Block mit dem Zustand (nur die ersten r Bits)
        for (i, chunk) in block.chunks(8).enumerate() {
            let x = i % 5;
            let y = i / 5;
            
            // Konvertiere 8 Bytes zu u64 (Little-Endian)
            let mut word = 0u64;
            for (j, &byte) in chunk.iter().enumerate() {
                word |= (byte as u64) << (j * 8);
            }
            
            // XOR mit dem Zustand
            self.state[x][y] ^= word;
        }
        
        // Führe die Keccak-Permutation aus
        self.keccak_f();
    }

    /// Extrahiert den Hash aus dem Zustand (Squeeze-Phase)
    /// 
    /// # Returns
    /// 
    /// Die ersten 224 Bits des Zustands als Byte-Vektor
    fn squeeze(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(HASH_SIZE / 8);
        let bytes_needed = HASH_SIZE / 8; // 28 Bytes
        
        let mut bytes_extracted = 0;
        
        // Extrahiere Bytes aus dem Zustand
        for y in 0..5 {
            for x in 0..5 {
                if bytes_extracted >= bytes_needed {
                    break;
                }
                
                let word = self.state[x][y];
                
                // Konvertiere u64 zu Bytes (Little-Endian)
                for i in 0..8 {
                    if bytes_extracted >= bytes_needed {
                        break;
                    }
                    output.push((word >> (i * 8)) as u8);
                    bytes_extracted += 1;
                }
            }
            if bytes_extracted >= bytes_needed {
                break;
            }
        }
        
        output
    }

    /// Keccak-f Permutation (24 Runden)
    /// 
    /// Diese Funktion implementiert die Keccak-Permutation mit den fünf Schritten:
    /// θ (Theta), ρ (Rho), π (Pi), χ (Chi), ι (Iota)
    fn keccak_f(&mut self) {
        for round in 0..ROUNDS {
            self.theta();
            self.rho();
            self.pi();
            self.chi();
            self.iota(round);
        }
    }

    /// θ (Theta) Schritt: Paritäts-Berechnung und XOR
    /// 
    /// Berechnet die Parität jeder Spalte und XORt sie mit benachbarten Spalten.
    /// Formel: a[i][j] ← a[i][j] ⊕ parity[j-1] ⊕ ROL1(parity[j+1])
    fn theta(&mut self) {
        let mut parity = [0u64; 5];
        
        // Berechne Parität für jede Spalte
        for j in 0..5 {
            parity[j] = self.state[0][j] ^ self.state[1][j] ^ self.state[2][j] 
                      ^ self.state[3][j] ^ self.state[4][j];
        }
        
        // Aktualisiere jeden Zustand
        for j in 0..5 {
            let temp = parity[(j + 4) % 5] ^ self.rol64(parity[(j + 1) % 5], 1);
            for i in 0..5 {
                self.state[i][j] ^= temp;
            }
        }
    }

    /// ρ (Rho) Schritt: Zyklisches Rotieren einzelner Wörter
    /// 
    /// Jedes Wort wird um eine spezifische Anzahl von Positionen rotiert.
    /// Die Rotation-Offsets sind in RHO_OFFSETS definiert.
    fn rho(&mut self) {
        for i in 0..5 {
            for j in 0..5 {
                self.state[i][j] = self.rol64(self.state[i][j], RHO_OFFSETS[i][j]);
            }
        }
    }

    /// π (Pi) Schritt: Umordnung der Wörter
    /// 
    /// Permutiert die Positionen der Wörter im 5x5 Array.
    /// Formel: a'[j][(2*i + 3*j) % 5] = a[i][j]
    fn pi(&mut self) {
        let mut temp = [[0u64; 5]; 5];
        
        for i in 0..5 {
            for j in 0..5 {
                temp[j][(2 * i + 3 * j) % 5] = self.state[i][j];
            }
        }
        
        self.state = temp;
    }

    /// χ (Chi) Schritt: Nichtlineare Transformation
    /// 
    /// Einzige nichtlineare Komponente der Permutation.
    /// Formel: a[i][j] ← a[i][j] ⊕ ((¬a[i][(j+1)%5]) & a[i][(j+2)%5])
    fn chi(&mut self) {
        let mut temp = [[0u64; 5]; 5];
        
        for i in 0..5 {
            for j in 0..5 {
                temp[i][j] = self.state[i][j] 
                    ^ ((!self.state[i][(j + 1) % 5]) & self.state[i][(j + 2) % 5]);
            }
        }
        
        self.state = temp;
    }

    /// ι (Iota) Schritt: Addition der Rundenkonstante
    /// 
    /// XORt eine rundspezifische Konstante mit Position [0][0].
    /// 
    /// # Arguments
    /// 
    /// * `round` - Die aktuelle Rundennummer (0-23)
    fn iota(&mut self, round: usize) {
        self.state[0][0] ^= ROUND_CONSTANTS[round];
    }

    /// 64-Bit Links-Rotation
    /// 
    /// # Arguments
    /// 
    /// * `value` - Der zu rotierende Wert
    /// * `positions` - Anzahl der Positionen für die Rotation
    /// 
    /// # Returns
    /// 
    /// Den rotierten Wert
    fn rol64(&self, value: u64, positions: usize) -> u64 {
        let positions = positions % 64;
        (value << positions) | (value >> (64 - positions))
    }
}

/// Konvertiert einen Hexadezimal-String zu Bytes
/// 
/// # Arguments
/// 
/// * `hex_str` - Hexadezimal-String (ohne 0x Präfix)
/// 
/// # Returns
/// 
/// Vektor von Bytes oder Fehler bei ungültiger Eingabe
/// 
/// # Examples
/// 
/// ```
/// let bytes = hex_to_bytes("48656c6c6f").unwrap();
/// assert_eq!(bytes, b"Hello");
/// ```
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Entferne Whitespace und konvertiere zu Kleinbuchstaben
    let clean_hex: String = hex_str
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    
    // Überprüfe, dass nur gültige Hex-Zeichen vorhanden sind
    if !clean_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Ungültige Hexadezimalzeichen gefunden".into());
    }
    
    // Stelle sicher, dass die Länge gerade ist
    let padded_hex = if clean_hex.len() % 2 == 1 {
        format!("0{}", clean_hex)
    } else {
        clean_hex
    };
    
    // Konvertiere Hex-String zu Bytes
    let mut bytes = Vec::new();
    for chunk in padded_hex.as_bytes().chunks(2) {
        let hex_byte = std::str::from_utf8(chunk)?;
        let byte = u8::from_str_radix(hex_byte, 16)?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Konvertiert Bytes zu Hexadezimal-String
/// 
/// # Arguments
/// 
/// * `bytes` - Byte-Slice
/// 
/// # Returns
/// 
/// Hexadezimal-String in Kleinbuchstaben
/// 
/// # Examples
/// 
/// ```
/// let hex = bytes_to_hex(b"Hello");
/// assert_eq!(hex, "48656c6c6f");
/// ```
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Berechnet SHA3-224 Hash für gegebene Daten
/// 
/// # Arguments
/// 
/// * `data` - Die zu hashenden Daten
/// 
/// # Returns
/// 
/// SHA3-224 Hash als Byte-Vektor (28 Bytes)
/// 
/// # Examples
/// 
/// ```
/// let hash = sha3_224(b"Hello, World!");
/// println!("Hash: {}", bytes_to_hex(&hash));
/// ```
pub fn sha3_224(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_224::new();
    hasher.update(data);
    hasher.finalize()
}

/// Hauptfunktion mit CLI-Interface
/// 
/// Das Programm arbeitet still:
/// - Liest Hexadezimaldaten aus der Eingabedatei
/// - Berechnet den SHA3-224 Hash
/// - Schreibt das Ergebnis in die Ausgabedatei
/// - Keine stdout-Ausgaben, nur stderr für Fehler
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI-Argumente mit clap derive
    let cli = Cli::parse();

    // Lese Eingabedatei
    let hex_content = match fs::read_to_string(&cli.input) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Fehler beim Lesen der Eingabedatei '{}': {}", cli.input, e);
            std::process::exit(1);
        }
    };

    // Konvertiere Hexadezimal zu Bytes
    let input_bytes = match hex_to_bytes(&hex_content) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Fehler beim Konvertieren der Hexadezimaldaten: {}", e);
            std::process::exit(1);
        }
    };

    // Berechne SHA3-224 Hash
    let hash = sha3_224(&input_bytes);
    let hash_hex = bytes_to_hex(&hash);

    // Schreibe Ausgabedatei
    match fs::write(&cli.output, &hash_hex) {
        Ok(_) => {
            // Erfolg - keine Ausgabe
        }
        Err(e) => {
            eprintln!("Fehler beim Schreiben der Ausgabedatei '{}': {}", cli.output, e);
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test für leere Eingabe
    /// Laut NIST sollte SHA3-224("") einen spezifischen Hash ergeben
    #[test]
    fn test_empty_input() {
        let hash = sha3_224(b"");
        let hash_hex = bytes_to_hex(&hash);
        
        // Der erwartete Hash für leere Eingabe (kann mit NIST-Testvektoren verglichen werden)
        println!("SHA3-224 of empty string: {}", hash_hex);
        assert_eq!(hash.len(), 28); // 224 bits / 8 = 28 bytes
    }

    /// Test für "abc" Eingabe
    /// Dies ist ein Standard-Testvektor
    #[test]
    fn test_abc_input() {
        let hash = sha3_224(b"abc");
        let hash_hex = bytes_to_hex(&hash);
        
        println!("SHA3-224 of 'abc': {}", hash_hex);
        assert_eq!(hash.len(), 28);
        
        // NIST-Testvektor für "abc":
        // Expected: e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf
        assert_eq!(hash_hex, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    }

    /// Test für längere Eingabe
    #[test]
    fn test_longer_input() {
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = sha3_224(input.as_bytes());
        let hash_hex = bytes_to_hex(&hash);
        
        println!("SHA3-224 of long string: {}", hash_hex);
        assert_eq!(hash.len(), 28);
    }

    /// Test für Hex-Konvertierung
    #[test]
    fn test_hex_conversion() {
        let bytes = hex_to_bytes("48656c6c6f").unwrap();
        assert_eq!(bytes, b"Hello");
        
        let hex = bytes_to_hex(b"Hello");
        assert_eq!(hex, "48656c6c6f");
    }

    /// Test für ungerade Hex-Länge
    #[test]
    fn test_odd_hex_length() {
        let bytes = hex_to_bytes("abc").unwrap();
        assert_eq!(bytes, vec![0x0a, 0xbc]);
    }

    /// Test für CLI-Argumente
    #[test]
    fn test_cli_parsing() {
        let cli = Cli {
            input: "test_input.txt".to_string(),
            output: "test_output.txt".to_string(),
        };
        
        assert_eq!(cli.input, "test_input.txt");
        assert_eq!(cli.output, "test_output.txt");
    }
}
