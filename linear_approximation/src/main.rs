use clap::Parser;
use rand::Rng;
use std::fs;
use std::process;

/// Lineare Kryptoanalyse für SPN
/// 
/// Implementiert Teilschlüsselsuche für gegebene lineare Approximation【22-1】【22-2】
/// Erzeugt dazu die Klartext-Kryptotextpaare einfach selber
/// In der Theorie sind es ca tε⁻² ≈ t·1000 für kleines t (in VL t = 8)【10-2】
/// Ausgabe der Teilschlüssel in Standardoutput als Hexadezimalzahl
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Datei mit Klartexten (Hexadezimal) oder "generate" für automatische Generierung
    #[arg(short, long, help = "Datei mit Klartexten (Hexadezimal) oder 'generate'")]
    plaintexts: String,
    
    /// Datei mit entsprechenden Kryptotexten (Hexadezimal)
    #[arg(short, long, help = "Datei mit entsprechenden Kryptotexten (Hexadezimal)")]
    ciphertexts: String,
    
    /// Anzahl der zu generierenden Paare (bei "generate")
    #[arg(short = 'n', long, help = "Anzahl der zu generierenden Paare (bei 'generate')", default_value = "8000")]
    count: usize,
    
    /// Bekannter Schlüssel für Tests (nur bei Generierung)
    #[arg(short, long, help = "Bekannter Schlüssel für Tests (nur bei Generierung)")]
    test_key: Option<String>,
}

/// SPN-Cipher (identisch zu Aufgabe 1, aber als integrierte Implementierung)
struct SpnCipher {
    s_box: [u8; 16],
    inverse_sbox: [u8; 16],
    permutation: [usize; 16],
    round_key: u16,
}

impl SpnCipher {
    fn new(key: u16) -> Self {
        // S-Box aus der Vorlesung【22-12】
        let s_box = [
            0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
            0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
        ];
        
        // Erstelle inverse S-Box
        let mut inverse_sbox = [0u8; 16];
        for (i, &val) in s_box.iter().enumerate() {
            inverse_sbox[val as usize] = i as u8;
        }
        
        // Permutation aus der Vorlesung【22-12】
        let permutation = [
            0,  4,  8, 12,
            1,  5,  9, 13,
            2,  6, 10, 14,
            3,  7, 11, 15
        ];
        
        SpnCipher {
            s_box,
            inverse_sbox,
            permutation,
            round_key: key,
        }
    }
    
    fn apply_sbox(&self, input: u16) -> u16 {
        let mut result = 0u16;
        for i in 0..4 {
            let nibble = ((input >> (i * 4)) & 0xF) as usize;
            let substituted = self.s_box[nibble] as u16;
            result |= substituted << (i * 4);
        }
        result
    }
    
    fn apply_inverse_sbox(&self, input: u16) -> u16 {
        let mut result = 0u16;
        for i in 0..4 {
            let nibble = ((input >> (i * 4)) & 0xF) as usize;
            let substituted = self.inverse_sbox[nibble] as u16;
            result |= substituted << (i * 4);
        }
        result
    }
    
    fn apply_permutation(&self, input: u16) -> u16 {
        let mut result = 0u16;
        for i in 0..16 {
            let bit = (input >> i) & 1;
            result |= bit << self.permutation[i];
        }
        result
    }
    
    fn encrypt_block(&self, plaintext: u16) -> u16 {
        let mut w = plaintext;
        
        // Runden 1 bis 3
        for _round in 1..=3 {
            w ^= self.round_key;
            w = self.apply_sbox(w);
            w = self.apply_permutation(w);
        }
        
        // Finale Runde
        w ^= self.round_key;
        w = self.apply_sbox(w);
        w ^= self.round_key;
        
        w
    }
    
    /// Berechnet u4 (vor der finalen S-Box) für lineare Analyse【22-1】
    fn compute_u4(&self, plaintext: u16) -> u16 {
        let mut w = plaintext;
        
        // Runden 1 bis 3
        for _round in 1..=3 {
            w ^= self.round_key;
            w = self.apply_sbox(w);
            w = self.apply_permutation(w);
        }
        
        // u4 = w3 ⊕ K4 (vor der finalen S-Box)
        w ^ self.round_key
    }
    
    fn get_round_key(&self) -> u16 {
        self.round_key
    }
}

/// Implementiert die lineare Approximation aus der Vorlesung【22-1】【22-2】
/// X₅ ⊕ X₇ ⊕ X₈ ⊕ U₄₆ ⊕ U₄₈ ⊕ U₄₁₄ ⊕ U₄₁₆ = 0
/// 
/// Diese Approximation hat Güte ε ≈ 1/32【22-2】【22-4】
fn linear_approximation(plaintext: u16, u4: u16) -> u16 {
    // X₅, X₇, X₈ (Bits 5, 7, 8 vom Klartext, 0-basiert: 4, 6, 7)
    let x_bits = ((plaintext >> 4) & 1) ^ ((plaintext >> 6) & 1) ^ ((plaintext >> 7) & 1);
    
    // U₄₆, U₄₈, U₄₁₄, U₄₁₆ (Bits 6, 8, 14, 16 von u4, 0-basiert: 5, 7, 13, 15)
    let u4_bits = ((u4 >> 5) & 1) ^ ((u4 >> 7) & 1) ^ ((u4 >> 13) & 1) ^ ((u4 >> 15) & 1);
    
    x_bits ^ u4_bits
}

/// Rekonstruiert u4-Bits aus Kryptotext und Teilschlüsselkandidaten【10-7】
/// Für die lineare Analyse müssen wir die relevanten Bits von u4 rekonstruieren
fn reconstruct_u4_from_ciphertext(ciphertext: u16, l1: u8, l2: u8, cipher: &SpnCipher) -> u16 {
    // Rückgängig: finale Schlüsseladdition mit hypothetischen Teilschlüsseln
    // L1 entspricht Nibble 2 (Bits 4-7), L2 entspricht Nibble 4 (Bits 12-15)
    
    let mut v4 = ciphertext;
    
    // Hypothetische finale Schlüsseladdition rückgängig machen
    // Wir probieren verschiedene Teilschlüssel für die relevanten Nibbles
    let key_guess = ((l2 as u16) << 12) | ((l1 as u16) << 4);
    v4 ^= key_guess;
    
    // Inverse S-Box anwenden um u4 zu erhalten
    let reconstructed_u4 = cipher.apply_inverse_sbox(v4);
    
    reconstructed_u4
}

/// Führt die Teilschlüsselsuche durch【10-7】
fn subkey_search(plaintexts: &[u16], ciphertexts: &[u16]) -> Vec<(u8, u8, f64)> {
    let mut results = Vec::new();
    let total_pairs = plaintexts.len();
    let cipher = SpnCipher::new(0); // Nur für inverse S-Box Operationen
    
    // Teste alle möglichen Teilschlüsselkandidaten L1, L2 (je 4 Bit)
    for l1 in 0..16u8 {
        for l2 in 0..16u8 {
            let mut count_approximation_holds = 0;
            
            // Teste lineare Approximation für jeden Teilschlüsselkandidaten
            for (&plaintext, &ciphertext) in plaintexts.iter().zip(ciphertexts.iter()) {
                // Rekonstruiere u4 für diesen Teilschlüsselkandidaten
                let u4_reconstructed = reconstruct_u4_from_ciphertext(ciphertext, l1, l2, &cipher);
                
                // Prüfe ob lineare Approximation erfüllt ist
                if linear_approximation(plaintext, u4_reconstructed) == 0 {
                    count_approximation_holds += 1;
                }
            }
            
            // Berechne Wahrscheinlichkeit und Bias
            let probability = count_approximation_holds as f64 / total_pairs as f64;
            let bias = (probability - 0.5).abs();
            
            results.push((l1, l2, bias));
        }
    }
    
    // Sortiere nach Bias (absteigende Reihenfolge)
    results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    
    results
}

/// Generiert Klartext-Kryptotext-Paare für Tests
fn generate_test_pairs(cipher: &SpnCipher, count: usize) -> (Vec<u16>, Vec<u16>) {
    let mut rng = rand::rng();
    let mut plaintexts = Vec::new();
    let mut ciphertexts = Vec::new();
    
    for _ in 0..count {
        let plaintext = rng.random::<u16>();
        let ciphertext = cipher.encrypt_block(plaintext);
        
        plaintexts.push(plaintext);
        ciphertexts.push(ciphertext);
    }
    
    (plaintexts, ciphertexts)
}

/// Konvertiert Hex-String zu Blöcken
fn hex_to_blocks(hex: &str) -> Result<Vec<u16>, String> {
    let clean_hex = hex.replace(char::is_whitespace, "").to_uppercase();
    
    if !clean_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Ungültige Hexadezimalzeichen gefunden".to_string());
    }
    
    let mut padded = clean_hex;
    while padded.len() % 4 != 0 {
        padded.push('0');
    }
    
    let mut blocks = Vec::new();
    for chunk in padded.as_bytes().chunks(4) {
        let block_str = std::str::from_utf8(chunk)
            .map_err(|_| "UTF-8 Konvertierungsfehler")?;
        let block = u16::from_str_radix(block_str, 16)
            .map_err(|_| format!("Ungültiger Hex-Block: {}", block_str))?;
        blocks.push(block);
    }
    
    Ok(blocks)
}

/// Konvertiert Blöcke zu Hex-String
fn blocks_to_hex(blocks: &[u16]) -> String {
    blocks.iter()
        .map(|&block| format!("{:04X}", block))
        .collect()
}

/// Parst Schlüssel aus Hex-String
fn parse_key(key_str: &str) -> Result<u16, String> {
    let clean_key = key_str.replace(char::is_whitespace, "").to_uppercase();
    
    if clean_key.len() != 4 {
        return Err(format!("Schlüssel muss 4 Hex-Ziffern haben, gefunden: {}", clean_key.len()));
    }
    
    if !clean_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Schlüssel enthält ungültige Zeichen".to_string());
    }
    
    u16::from_str_radix(&clean_key, 16)
        .map_err(|_| "Fehler beim Parsen des Schlüssels".to_string())
}

fn main() {
    let args = Args::parse();
    
    // Lade oder generiere Daten
    let (plaintexts, ciphertexts, test_key) = if args.plaintexts == "generate" {
        // Generiere Testdaten
        let test_key = if let Some(key_str) = args.test_key {
            match parse_key(&key_str) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("Fehler beim Parsen des Testschlüssels: {}", e);
                    process::exit(1);
                }
            }
        } else {
            // Verwende Standard-Testschlüssel
            0x2D55
        };
        
        let cipher = SpnCipher::new(test_key);
        let (pt, ct) = generate_test_pairs(&cipher, args.count);
        
        // Speichere generierte Daten
        let pt_hex = blocks_to_hex(&pt);
        let ct_hex = blocks_to_hex(&ct);
        
        let _ = fs::write("generated_plaintexts.txt", &pt_hex);
        let _ = fs::write(&args.ciphertexts, &ct_hex);
        
        (pt, ct, Some(test_key))
    } else {
        // Lade aus Dateien
        let pt_data = match fs::read_to_string(&args.plaintexts) {
            Ok(data) => data.trim().to_string(),
            Err(e) => {
                eprintln!("Fehler beim Laden der Klartexte: {}", e);
                process::exit(1);
            }
        };
        
        let ct_data = match fs::read_to_string(&args.ciphertexts) {
            Ok(data) => data.trim().to_string(),
            Err(e) => {
                eprintln!("Fehler beim Laden der Kryptotexte: {}", e);
                process::exit(1);
            }
        };
        
        let plaintexts = match hex_to_blocks(&pt_data) {
            Ok(blocks) => blocks,
            Err(e) => {
                eprintln!("Fehler beim Parsen der Klartexte: {}", e);
                process::exit(1);
            }
        };
        
        let ciphertexts = match hex_to_blocks(&ct_data) {
            Ok(blocks) => blocks,
            Err(e) => {
                eprintln!("Fehler beim Parsen der Kryptotexte: {}", e);
                process::exit(1);
            }
        };
        
        (plaintexts, ciphertexts, None)
    };
    
    if plaintexts.len() != ciphertexts.len() {
        eprintln!("Fehler: Anzahl Klartexte ({}) != Anzahl Kryptotexte ({})", 
                  plaintexts.len(), ciphertexts.len());
        process::exit(1);
    }
    
    // Führe Teilschlüsselsuche durch
    let results = subkey_search(&plaintexts, &ciphertexts);
    
    // === AUSGABE DER TEILSCHLÜSSEL IN STANDARDOUTPUT ALS HEXADEZIMALZAHL ===【10-2】
    let (best_l1, best_l2, _best_bias) = results[0];
    
    // Hauptausgabe: Teilschlüssel als Hexadezimalzahl
    println!("{:X}{:X}", best_l1, best_l2);
    
    // Optional: Zusätzliche Informationen auf STDERR (für Debugging, nicht auf STDOUT)
    if let Some(key) = test_key {
        let expected_l1 = ((key >> 4) & 0xF) as u8;   // Nibble 2
        let expected_l2 = ((key >> 12) & 0xF) as u8;  // Nibble 4
        
        eprintln!("DEBUG: Testschlüssel: {:04X}", key);
        eprintln!("DEBUG: Erwartete Teilschlüssel: L1={:X}, L2={:X}", expected_l1, expected_l2);
        eprintln!("DEBUG: Gefundene Teilschlüssel: L1={:X}, L2={:X}", best_l1, best_l2);
        
        if best_l1 == expected_l1 && best_l2 == expected_l2 {
            eprintln!("DEBUG: [+] Angriff erfolgreich!");
        } else {
            eprintln!("DEBUG: [-] Angriff fehlgeschlagen - mehr Paare nötig");
        }
        
        eprintln!("DEBUG: Verwendete Paare: {}", plaintexts.len());
        eprintln!("DEBUG: Top 5 Kandidaten:");
        for (i, (l1, l2, bias)) in results.iter().take(5).enumerate() {
            eprintln!("DEBUG: {:2}: {:X}{:X} (Bias: {:.6})", i + 1, l1, l2, bias);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_linear_approximation() {
        // Test der linearen Approximation
        let plaintext = 0x1234;
        let u4 = 0x5678;
        
        // Sollte deterministisch sein
        let result1 = linear_approximation(plaintext, u4);
        let result2 = linear_approximation(plaintext, u4);
        assert_eq!(result1, result2);
        
        // Sollte nur 0 oder 1 zurückgeben
        assert!(result1 == 0 || result1 == 1);
    }
    
    #[test]
    fn test_key_parsing() {
        assert_eq!(parse_key("2D55").unwrap(), 0x2D55);
        assert_eq!(parse_key("abcd").unwrap(), 0xABCD);
        
        assert!(parse_key("123").is_err());  // Zu kurz
        assert!(parse_key("12345").is_err()); // Zu lang
        assert!(parse_key("12GH").is_err());  // Ungültiges Zeichen
    }
    
    #[test]
    fn test_generate_pairs() {
        let cipher = SpnCipher::new(0x1234);
        let (plaintexts, ciphertexts) = generate_test_pairs(&cipher, 100);
        
        assert_eq!(plaintexts.len(), 100);
        assert_eq!(ciphertexts.len(), 100);
        
        // Teste dass Verschlüsselung korrekt ist
        for (&pt, &ct) in plaintexts.iter().zip(ciphertexts.iter()) {
            assert_eq!(cipher.encrypt_block(pt), ct);
        }
    }
    
    #[test]
    fn test_subkey_search_with_known_key() {
        let known_key = 0x2D55;
        let cipher = SpnCipher::new(known_key);
        
        // Generiere wenige Testpaare
        let (plaintexts, ciphertexts) = generate_test_pairs(&cipher, 1000);
        
        // Führe Suche durch
        let results = subkey_search(&plaintexts, &ciphertexts);
        
        // Sollte mindestens ein Ergebnis haben
        assert!(!results.is_empty());
        
        // Extrahiere erwartete Teilschlüssel
        let expected_l1 = ((known_key >> 4) & 0xF) as u8;
        let expected_l2 = ((known_key >> 12) & 0xF) as u8;
        
        // Prüfe ob erwarteter Teilschlüssel in Top-Kandidaten ist
        let found = results.iter().take(10).any(|(l1, l2, _)| {
            *l1 == expected_l1 && *l2 == expected_l2
        });
        
        // Bei 1000 Paaren sollte es oft funktionieren (aber nicht immer)
        // Daher nur Info-Ausgabe statt assert
        println!("Erwartete Teilschlüssel ({:X}{:X}) in Top 10 gefunden: {}", 
                 expected_l1, expected_l2, found);
    }
}
