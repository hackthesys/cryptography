use clap::{Parser, ValueEnum};
use std::fs;
use std::path::{Path, PathBuf};
use num_bigint::BigUint;
use num_traits::{Zero, One};

/// RSA Verschlüsselung/Entschlüsselung mit Textbook RSA (ungepolstert)
/// 
/// SICHERHEITSHINWEIS: Dies ist eine Bildungsimplementierung von Textbook RSA
/// ohne Padding. Nicht für produktive Kryptographie verwenden!
#[derive(Parser)]
#[command(
    name = "rsa-textbook",
    about = "Simple RSA encryption/decryption utility using textbook (unpadded) RSA",
    long_about = "
Diese Implementierung verwendet den klassischen Square-and-Multiply Algorithmus
für modulare Exponentiation. Alle Werte werden als Dezimalzahlen gelesen und geschrieben.

EINGABEFORMAT:
- Input-Datei: Eine einzige Dezimalzahl (Klartext oder Geheimtext)
- Schlüssel-Datei: Zwei Zeilen in Dezimal:
  * Zeile 1: Exponent (e für Verschlüsselung, d für Entschlüsselung)  
  * Zeile 2: Modulus n

ALGORITHMUS:
Modular Exponentiation via Square-and-Multiply (LSB-first Bit-Scanning).
Für jedes gesetzte Bit i im Exponenten: y = (y * x) mod n
Nach jedem Schritt: x = (x * x) mod n
"
)]
#[command(version, author)]
struct Args {
    /// Operation: encrypt oder decrypt
    #[arg(long, value_enum)]
    operation: Operation,

    /// Pfad zur Eingabedatei (enthält eine Dezimalzahl)
    #[arg(long, value_name = "INPUT_FILE")]
    file: PathBuf,

    /// Pfad zur Schlüsseldatei (zwei Zeilen: Exponent, Modulus)  
    #[arg(long, value_name = "KEY_FILE")]
    key: PathBuf,

    /// Ausgabeziel (Datei oder Verzeichnis)
    /// 
    /// Wenn ein Verzeichnis angegeben wird, wird die Ausgabedatei
    /// dort mit dem gleichen Namen wie die Eingabedatei erstellt.
    #[arg(long, value_name = "OUTPUT_DESTINATION")]
    output: PathBuf,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Operation {
    /// RSA-Verschlüsselung: ciphertext = plaintext^e mod n
    Encrypt,
    /// RSA-Entschlüsselung: plaintext = ciphertext^d mod n  
    Decrypt,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Encrypt => write!(f, "Verschlüsselung"),
            Operation::Decrypt => write!(f, "Entschlüsselung"),
        }
    }
}

/// Berechnet x^m mod n mittels Square-and-Multiply (LSB-first)
/// 
/// Dieser Algorithmus implementiert die binäre Exponentiation durch
/// Scannen der Bits des Exponenten von LSB (Least Significant Bit) zu MSB.
/// 
/// # Algorithmus
/// ```text
/// y = 1
/// for i = 0 bis bitLength(m) - 1:
///     if bit i von m ist gesetzt:
///         y = (y * x) mod n
///     x = (x * x) mod n
/// return y
/// ```
/// 
/// # Parameter
/// - `x`: Basis
/// - `m`: Exponent (nicht-negativ)
/// - `n`: Modulus (positiv)
/// 
/// # Rückgabe
/// x^m mod n
fn mod_pow(mut x: BigUint, m: &BigUint, n: &BigUint) -> BigUint {
    let mut y = BigUint::one();
    let bit_length = m.bits();
    
    for i in 0..bit_length {
        // Prüfe das i-te Bit (von rechts, 0-indiziert)
        if m.bit(i) {
            y = (&y * &x) % n;
        }
        x = (&x * &x) % n;
    }
    
    y
}

/// RSA Verschlüsselung: ciphertext = plaintext^e mod n
/// 
/// # Hinweis
/// Kein Padding wird angewendet. Der Aufrufer muss sicherstellen,
/// dass 0 ≤ plaintext < n.
fn encrypt(plaintext: &BigUint, e: &BigUint, n: &BigUint) -> BigUint {
    mod_pow(plaintext.clone(), e, n)
}

/// RSA Entschlüsselung: plaintext = ciphertext^d mod n
/// 
/// # Hinweis  
/// Kein Padding wird entfernt. Der Aufrufer muss sicherstellen,
/// dass 0 ≤ ciphertext < n.
fn decrypt(ciphertext: &BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    mod_pow(ciphertext.clone(), d, n)
}

/// Liest eine große Ganzzahl aus einer Datei
/// 
/// Die Datei sollte eine einzige Dezimalzahl enthalten.
/// Führende und nachfolgende Leerzeichen werden ignoriert.
fn read_big_uint(file_path: &Path) -> Result<BigUint, Box<dyn std::error::Error>> {
    if !file_path.exists() || !file_path.is_file() {
        return Err(format!("Datei nicht gefunden oder nicht lesbar: {}", 
                          file_path.display()).into());
    }

    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Fehler beim Lesen der Datei {}: {}", 
                            file_path.display(), e))?;
    
    let trimmed = content.trim();
    BigUint::parse_bytes(trimmed.as_bytes(), 10)
        .ok_or_else(|| format!("Ungültiges Zahlenformat in {}: '{}'", 
                              file_path.display(), trimmed).into())
}

/// Liest RSA-Schlüssel aus einer Datei
/// 
/// Die Datei muss zwei Zeilen enthalten (beide in Dezimal):
/// 1. Exponent (e für Verschlüsselung oder d für Entschlüsselung)
/// 2. Modulus n
fn read_key(file_path: &Path) -> Result<(BigUint, BigUint), Box<dyn std::error::Error>> {
    if !file_path.exists() || !file_path.is_file() {
        return Err(format!("Schlüsseldatei nicht gefunden: {}", 
                          file_path.display()).into());
    }

    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Fehler beim Lesen der Schlüsseldatei {}: {}", 
                            file_path.display(), e))?;
    
    let lines: Vec<&str> = content.lines().collect();
    
    if lines.len() < 2 {
        return Err("Schlüsseldatei muss zwei Zeilen enthalten: Exponent und Modulus".into());
    }
    
    let exponent = BigUint::parse_bytes(lines[0].trim().as_bytes(), 10)
        .ok_or_else(|| format!("Ungültiges Exponent-Format in Zeile 1: '{}'", 
                              lines[0].trim()))?;
    
    let modulus = BigUint::parse_bytes(lines[1].trim().as_bytes(), 10)
        .ok_or_else(|| format!("Ungültiges Modulus-Format in Zeile 2: '{}'", 
                              lines[1].trim()))?;
    
    if modulus.is_zero() {
        return Err("Modulus darf nicht null sein".into());
    }
    
    Ok((exponent, modulus))
}

/// Bestimmt den finalen Ausgabepfad
/// 
/// Wenn `output_destination` ein Verzeichnis ist, wird der Dateiname
/// von `input_path` verwendet. Andernfalls wird `output_destination`
/// direkt als Dateipfad verwendet.
fn resolve_output_path(output_destination: &Path, input_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output_path = if output_destination.exists() && output_destination.is_dir() {
        let input_filename = input_path
            .file_name()
            .ok_or("Ungültiger Eingabedateiname")?;
        output_destination.join(input_filename)
    } else {
        output_destination.to_path_buf()
    };
    
    // Elternverzeichnis erstellen falls nötig
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Kann Verzeichnis {} nicht erstellen: {}", 
                                parent.display(), e))?;
    }
    
    Ok(output_path)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Eingabewert lesen
    let value = read_big_uint(&args.file)?;
    
    // Schlüssel lesen (Exponent, Modulus)  
    let (exponent, modulus) = read_key(&args.key)?;
    
    // Ausgabepfad bestimmen
    let output_path = resolve_output_path(&args.output, &args.file)?;
    
    // RSA-Operation durchführen
    let result = match args.operation {
        Operation::Encrypt => encrypt(&value, &exponent, &modulus),
        Operation::Decrypt => decrypt(&value, &exponent, &modulus),
    };
    
    // Ergebnis in Datei schreiben
    fs::write(&output_path, result.to_string())
        .map_err(|e| format!("Fehler beim Schreiben in {}: {}", 
                            output_path.display(), e))?;
    
    println!("{} abgeschlossen.", args.operation);
    println!("Ergebnis geschrieben nach: {}", output_path.display());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    
    #[test]
    fn test_mod_pow_small_numbers() {
        let x = BigUint::from(2u32);
        let m = BigUint::from(10u32);
        let n = BigUint::from(1000u32);
        
        let result = mod_pow(x, &m, &n);
        assert_eq!(result, BigUint::from(24u32)); // 2^10 mod 1000 = 1024 mod 1000 = 24
    }
    
    #[test] 
    fn test_rsa_encrypt_decrypt_cycle() {
        // Kleine Testzahlen (p=7, q=11, n=77, phi=60)
        let p = BigUint::from(7u32);
        let q = BigUint::from(11u32);
        let n = &p * &q; // n = 77
        let phi = (&p - 1u32) * (&q - 1u32); // phi = 60
        
        let e = BigUint::from(13u32); // e = 13 (teilerfremd zu 60)
        let message = BigUint::from(42u32);
        
        // Verschlüsseln
        let ciphertext = encrypt(&message, &e, &n);
        
        // Für Entschlüsselung brauchen wir d mit e*d ≡ 1 (mod phi)
        // 13*d ≡ 1 (mod 60), d = 37 (manuell berechnet für diesen Test)
        let d = BigUint::from(37u32);
        
        // Entschlüsseln
        let decrypted = decrypt(&ciphertext, &d, &n);
        
        assert_eq!(message, decrypted);
    }
}
