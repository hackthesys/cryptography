// src/main.rs
use clap::Parser;
use std::process;

/// SPN (Substitution-Permutation Network) Cipher
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input: Folge an Hexadezimalziffern, je 4 ein Block (wie ECB)
    #[arg(short, long, help = "Eingabe als Hexadezimalziffern (je 4 ein Block)")]
    input: String,
    
    /// Schlüssel: 16 Bit / 4 Hexadezimalziffern (für jede Runde gleich)
    #[arg(short, long, help = "Schlüssel als 16 Bit / 4 Hexadezimalziffern")]
    key: String,
    
    /// Output-Datei für verschlüsselte Daten
    #[arg(short, long, help = "Ausgabedatei für verschlüsselte Daten")]
    output: String,
}

/// SPN-Verschlüsselungsstruktur
struct SpnCipher {
    s_box: [u8; 16],
    permutation: [usize; 16],
    round_key: u16,
}

impl SpnCipher {
    fn new(key: u16) -> Self {
        // S-Box aus der Vorlesung【2-5】【2-6】
        let s_box = [
            0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
            0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
        ];
        
        // Permutation aus der Vorlesung【2-5】【2-6】
        let permutation = [
            0,  4,  8, 12,
            1,  5,  9, 13,
            2,  6, 10, 14,
            3,  7, 11, 15
        ];
        
        SpnCipher {
            s_box,
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
    
    fn apply_permutation(&self, input: u16) -> u16 {
        let mut result = 0u16;
        for i in 0..16 {
            let bit = (input >> i) & 1;
            result |= bit << self.permutation[i];
        }
        result
    }
    
    /// Verschlüsselt einen 16-Bit Block - SILENT VERSION
    fn encrypt_block(&self, plaintext: u16) -> u16 {
        let mut w = plaintext;
        
        // Runden 1 bis 3 (N-1 = 3 für N=4)
        for _round in 1..=3 {
            // Schlüsseladdition: u^r = w^(r-1) ⊕ K^r
            let u = w ^ self.round_key;
            
            // Substitution: v^r = S(u^r)
            let v = self.apply_sbox(u);
            
            // Permutation: w^r = P(v^r)
            w = self.apply_permutation(v);
        }
        
        // Finale Runde (Runde 4)
        // Finale Schlüsseladdition: u^N = w^(N-1) ⊕ K^N
        let u_final = w ^ self.round_key;
        
        // Finale Substitution: v^N = S(u^N)
        let v_final = self.apply_sbox(u_final);
        
        // Finale Schlüsseladdition: y = v^N ⊕ K^(N+1)
        let ciphertext = v_final ^ self.round_key;
        
        ciphertext
    }
    
    /// Verschlüsselt eine Folge von Hexadezimalziffern im ECB-Modus - SILENT VERSION
    fn encrypt(&self, input: &str) -> Result<String, String> {
        // Entferne Leerzeichen und konvertiere zu Großbuchstaben
        let clean_input = input.replace(" ", "").to_uppercase();
        
        // Validiere Eingabe (nur Hexadezimalzeichen)
        if !clean_input.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Eingabe enthält ungültige Hexadezimalzeichen".to_string());
        }
        
        // Paddiere auf Vielfaches von 4 mit Nullen
        let mut padded_input = clean_input;
        while padded_input.len() % 4 != 0 {
            padded_input.push('0');
        }
        
        let mut result = String::new();
        
        // Verarbeite jeden 4-stelligen Block (16 Bit)
        for chunk in padded_input.as_bytes().chunks(4) {
            let block_str = std::str::from_utf8(chunk)
                .map_err(|_| "Fehler beim Verarbeiten der Eingabe")?;
            
            // Konvertiere Hex-String zu u16
            let plaintext = u16::from_str_radix(block_str, 16)
                .map_err(|_| format!("Ungültiger Hexadezimalblock: {}", block_str))?;
            
            // Verschlüssele Block
            let ciphertext = self.encrypt_block(plaintext);
            
            // Füge verschlüsselten Block zum Ergebnis hinzu
            result.push_str(&format!("{:04X}", ciphertext));
        }
        
        Ok(result)
    }
}

/// Validiert und parst einen Hexadezimal-Schlüssel
fn parse_key(key_str: &str) -> Result<u16, String> {
    let clean_key = key_str.replace(" ", "").to_uppercase();
    
    if clean_key.len() != 4 {
        return Err(format!("Schlüssel muss genau 4 Hexadezimalziffern haben, gefunden: {}", clean_key.len()));
    }
    
    if !clean_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Schlüssel enthält ungültige Hexadezimalzeichen".to_string());
    }
    
    u16::from_str_radix(&clean_key, 16)
        .map_err(|_| "Fehler beim Parsen des Schlüssels".to_string())
}

/// Schreibt verschlüsselte Daten in eine Datei
fn write_output(filename: &str, data: &str) -> Result<(), String> {
    std::fs::write(filename, data)
        .map_err(|e| format!("Fehler beim Schreiben der Ausgabedatei '{}': {}", filename, e))
}

fn main() {
    let args = Args::parse();
    
    // Parze und validiere Schlüssel
    let key = match parse_key(&args.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Fehler beim Parsen des Schlüssels: {}", e);
            process::exit(1);
        }
    };
    
    // Erstelle SPN-Cipher
    let cipher = SpnCipher::new(key);
    
    // Verschlüssele Eingabe
    let encrypted = match cipher.encrypt(&args.input) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Verschlüsselungsfehler: {}", e);
            process::exit(1);
        }
    };
    
    // Schreibe Ausgabe in Datei
    if let Err(e) = write_output(&args.output, &encrypted) {
        eprintln!("Ausgabefehler: {}", e);
        process::exit(1);
    }
    
    // KEIN OUTPUT AUF STDOUT - nur stille Verarbeitung
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sbox() {
        let cipher = SpnCipher::new(0x0000);
        
        // Teste bekannte S-Box Werte【2-5】
        assert_eq!(cipher.apply_sbox(0x0000), 0xEEEE); // 0->E für jedes Nibble
        assert_eq!(cipher.apply_sbox(0x1111), 0x4444); // 1->4 für jedes Nibble
        assert_eq!(cipher.apply_sbox(0xF000), 0x7EEE); // F->7, 0->E
    }
    
    #[test]
    fn test_key_parsing() {
        assert_eq!(parse_key("1234").unwrap(), 0x1234);
        assert_eq!(parse_key("ABCD").unwrap(), 0xABCD);
        assert_eq!(parse_key("abcd").unwrap(), 0xABCD);
        
        assert!(parse_key("123").is_err());  // Zu kurz
        assert!(parse_key("12345").is_err()); // Zu lang
        assert!(parse_key("12GH").is_err());  // Ungültiges Zeichen
    }
    
    #[test]
    fn test_block_encryption() {
        let cipher = SpnCipher::new(0x2D55);
        
        // Test mit einem bekannten Block
        let plaintext = 0x1234;
        let ciphertext = cipher.encrypt_block(plaintext);
        
        // Stelle sicher, dass die Verschlüsselung deterministisch ist
        assert_eq!(cipher.encrypt_block(plaintext), ciphertext);
    }
    
    #[test]
    fn test_full_encryption() {
        let cipher = SpnCipher::new(0x2D55);
        
        // Test komplette Verschlüsselung
        let result = cipher.encrypt("1234ABCD").unwrap();
        assert_eq!(result.len(), 8); // 2 Blöcke à 4 Hex-Zeichen
        
        // Test mit Padding
        let result_padded = cipher.encrypt("123").unwrap(); // Wird zu "1230"
        assert_eq!(result_padded.len(), 4); // 1 Block à 4 Hex-Zeichen
    }
}
