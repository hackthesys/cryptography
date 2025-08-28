use std::fs;
use std::io::{self, BufRead};
use std::error::Error;
use clap::Parser;
use num_bigint::BigUint;
use num_traits::{Zero, One};
use sha2::{Sha224, Digest};

/// DSA-Verifikations-Programm mit SHA-224
#[derive(Parser)]
#[command(name = "dsa_verify")]
#[command(about = "Verifiziert DSA-Signatur einer Nachricht")]
#[command(version = "1.0")]
struct Args {
    /// Datei mit öffentlichem Schlüssel
    #[arg(long, help = "Pfad zur öffentlichen Schlüsseldatei (p, q, g, y)")]
    public_key_file: String,
    
    /// Datei mit der Nachricht
    #[arg(long, help = "Pfad zur Nachrichtendatei")]
    message_file: String,
    
    /// Datei mit Signatur (optional, sonst stdin)
    #[arg(short, long, help = "Signaturdatei (r, s) - falls nicht angegeben, wird von stdin gelesen")]
    signature: Option<String>,
    
    /// Quiet Mode - nur Exit Code ausgeben
    #[arg(short, long, help = "Keine Textausgabe, nur Exit Code")]
    quiet: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    let (params, public_key) = load_public_key(&args.public_key_file)?;
    let message = fs::read_to_string(&args.message_file)?;
    
    // Signatur laden
    let signature = match args.signature {
        Some(sig_file) => read_signature_from_file(&sig_file)?,
        None => read_signature_from_stdin()?,
    };
    
    let is_valid = dsa_verify(message.as_bytes(), &signature, &params, &public_key)?;
    
    if !args.quiet {
        if is_valid {
            println!("Signatur gültig");
        } else {
            println!("Signatur ungültig");
        }
    }
    
    // Exit Code setzen
    if is_valid {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct DSAParameters {
    p: BigUint,
    q: BigUint,  
    g: BigUint,
}

/// Lädt öffentlichen Schlüssel aus Datei
/// 
/// Erwartet Format:
/// Zeile 1: p (1024-Bit Primzahl)
/// Zeile 2: q (160-Bit Primzahl)
/// Zeile 3: g (Generator)
/// Zeile 4: y (öffentlicher Schlüssel)
fn load_public_key(filename: &str) -> Result<(DSAParameters, BigUint), Box<dyn Error>> {
    let content = fs::read_to_string(filename)
        .map_err(|_| format!("Kann öffentliche Schlüsseldatei '{}' nicht lesen", filename))?;
    
    let lines: Vec<&str> = content.trim().split('\n').collect();
    
    if lines.len() != 4 {
        return Err(format!("Öffentliche Schlüsseldatei muss genau 4 Zeilen haben, gefunden: {}", lines.len()).into());
    }
    
    let p = lines[0].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von p")?;
    let q = lines[1].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von q")?;
    let g = lines[2].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von g")?;
    let y = lines[3].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen des öffentlichen Schlüssels y")?;
    
    // Validierung der Schlüsselparameter
    if y >= p {
        return Err("Öffentlicher Schlüssel y muss kleiner als p sein".into());
    }
    
    Ok((DSAParameters { p, q, g }, y))
}

/// Liest Signatur aus Datei
fn read_signature_from_file(filename: &str) -> Result<(BigUint, BigUint), Box<dyn Error>> {
    let content = fs::read_to_string(filename)
        .map_err(|_| format!("Kann Signaturdatei '{}' nicht lesen", filename))?;
    
    let lines: Vec<&str> = content.trim().split('\n').collect();
    
    if lines.len() != 2 {
        return Err(format!("Signaturdatei muss genau 2 Zeilen haben (r, s), gefunden: {}", lines.len()).into());
    }
    
    let r = lines[0].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von r")?;
    let s = lines[1].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von s")?;
    
    Ok((r, s))
}

/// Liest Signatur von stdin
fn read_signature_from_stdin() -> Result<(BigUint, BigUint), Box<dyn Error>> {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    
    let r_line = lines.next()
        .ok_or("Keine r-Komponente von stdin erhalten")?
        .map_err(|_| "Fehler beim Lesen von r")?;
    let s_line = lines.next()
        .ok_or("Keine s-Komponente von stdin erhalten")?
        .map_err(|_| "Fehler beim Lesen von s")?;
    
    let r = r_line.parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von r")?;
    let s = s_line.parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von s")?;
    
    Ok((r, s))
}

/// SHA-224 Hashfunktion für DSA
fn sha224_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha224::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

/// Konvertiert SHA-224 Hash zu BigUint für DSA-Berechnung
fn hash_to_bigint(hash_bytes: &[u8], q: &BigUint) -> BigUint {
    let hash_int = BigUint::from_bytes_be(hash_bytes);
    // SHA-224 erzeugt 224 Bits, q ist 160 Bits - Reduktion nötig
    hash_int % q
}

/// DSA-Signatur verifizieren
/// 
/// Algorithmus:
/// 1. Prüfe 0 < r < q und 0 < s < q
/// 2. H(m) = SHA-224(message) mod q
/// 3. w = s^(-1) mod q
/// 4. u1 = H(m) * w mod q
/// 5. u2 = r * w mod q  
/// 6. v = ((g^u1 * y^u2) mod p) mod q
/// 7. Signatur gültig ⟺ v = r
fn dsa_verify(message: &[u8], signature: &(BigUint, BigUint), params: &DSAParameters, public_key: &BigUint) -> Result<bool, Box<dyn Error>> {
    let (r, s) = signature;
    
    // Schritt 1: Signatur-Parameter validieren
    if *r == BigUint::zero() || *r >= params.q || *s == BigUint::zero() || *s >= params.q {
        return Ok(false);
    }
    
    // Schritt 2: Hash der Nachricht
    let hash_bytes = sha224_hash(message);
    let hash_int = hash_to_bigint(&hash_bytes, &params.q);
    
    // Schritt 3: w = s^(-1) mod q
    let w = mod_inverse(s, &params.q)?;
    
    // Schritt 4: u1 = H(m) * w mod q
    let u1 = (&hash_int * &w) % &params.q;
    
    // Schritt 5: u2 = r * w mod q
    let u2 = (r * &w) % &params.q;
    
    // Schritt 6: v = ((g^u1 * y^u2) mod p) mod q
    let g_u1 = mod_pow(&params.g, &u1, &params.p);
    let y_u2 = mod_pow(public_key, &u2, &params.p);
    let v = (&g_u1 * &y_u2) % &params.p % &params.q;
    
    // Schritt 7: Vergleich
    Ok(v == *r)
}

/// Modulare Exponentiation: base^exp mod modulus
fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus == &BigUint::one() {
        return BigUint::zero();
    }
    
    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();
    
    while exp > BigUint::zero() {
        if &exp % BigUint::from(2u32) == BigUint::one() {
            result = (result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp /= BigUint::from(2u32);
    }
    result
}

/// Modulares Inverses mit erweitertem Euklidischem Algorithmus
fn mod_inverse(a: &BigUint, m: &BigUint) -> Result<BigUint, Box<dyn Error>> {
    fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
        if *a == BigUint::zero() {
            return (b.clone(), BigUint::zero(), BigUint::one());
        }
        
        let (gcd, x1, y1) = extended_gcd(&(b % a), a);
        let x = y1 - (b / a) * &x1;
        let y = x1;
        
        (gcd, x, y)
    }
    
    let (gcd, x, _) = extended_gcd(&(a % m), m);
    
    if gcd != BigUint::one() {
        return Err("Modulares Inverses existiert nicht - s und q sind nicht teilerfremd".into());
    }
    
    Ok((x % m + m) % m)
}
