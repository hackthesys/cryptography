use std::fs;
use std::error::Error;
use clap::Parser;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};
use rand::thread_rng;
use sha2::{Sha224, Digest};

/// DSA-Signatur-Programm mit SHA-224
#[derive(Parser)]
#[command(name = "dsa_sign")]
#[command(about = "Erstellt DSA-Signatur für eine Nachricht")]
#[command(version = "1.0")]
struct Args {
    /// Datei mit privatem Schlüssel
    #[arg(long, help = "Pfad zur privaten Schlüsseldatei (p, q, g, x)")]
    private_key_file: String,
    
    /// Datei mit der zu signierenden Nachricht
    #[arg(long, help = "Pfad zur Nachrichtendatei")]
    message_file: String,
    
    /// Ausgabedatei für Signatur (optional, sonst stdout)
    #[arg(short, long, help = "Ausgabedatei für Signatur (r, s)")]
    output: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    let (params, private_key) = load_private_key(&args.private_key_file)?;
    let message = fs::read_to_string(&args.message_file)?;
    
    let signature = dsa_sign(message.as_bytes(), &params, &private_key)?;
    
    // Ausgabe der Signatur
    let signature_text = format!("{}\n{}", signature.0, signature.1);
    
    match args.output {
        Some(output_file) => {
            fs::write(output_file, signature_text)?;
        }
        None => {
            print!("{}", signature_text);
        }
    }
    
    Ok(())
}

#[derive(Debug)]
struct DSAParameters {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

/// Lädt privaten Schlüssel aus Datei
/// 
/// Erwartet Format:
/// Zeile 1: p (1024-Bit Primzahl)
/// Zeile 2: q (160-Bit Primzahl) 
/// Zeile 3: g (Generator)
/// Zeile 4: x (privater Schlüssel)
fn load_private_key(filename: &str) -> Result<(DSAParameters, BigUint), Box<dyn Error>> {
    let content = fs::read_to_string(filename)
        .map_err(|_| format!("Kann private Schlüsseldatei '{}' nicht lesen", filename))?;
    
    let lines: Vec<&str> = content.trim().split('\n').collect();
    
    if lines.len() != 4 {
        return Err(format!("Private Schlüsseldatei muss genau 4 Zeilen haben, gefunden: {}", lines.len()).into());
    }
    
    let p = lines[0].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von p")?;
    let q = lines[1].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von q")?;
    let g = lines[2].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen von g")?;
    let x = lines[3].parse::<BigUint>()
        .map_err(|_| "Fehler beim Parsen des privaten Schlüssels x")?;
    
    // Validierung der Schlüsselparameter
    if x >= q {
        return Err("Privater Schlüssel x muss kleiner als q sein".into());
    }
    
    Ok((DSAParameters { p, q, g }, x))
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

/// DSA-Signatur erstellen
/// 
/// Algorithmus:
/// 1. H(m) = SHA-224(message) mod q  
/// 2. Wähle zufälliges k ∈ [1, q-1]
/// 3. r = (g^k mod p) mod q
/// 4. s = k^(-1) * (H(m) + x*r) mod q
/// 5. Signatur = (r, s)
fn dsa_sign(message: &[u8], params: &DSAParameters, private_key: &BigUint) -> Result<(BigUint, BigUint), Box<dyn Error>> {
    let mut rng = thread_rng();
    
    // Schritt 1: Hash der Nachricht
    let hash_bytes = sha224_hash(message);
    let hash_int = hash_to_bigint(&hash_bytes, &params.q);
    
    // Schleife bis gültige Signatur gefunden
    loop {
        // Schritt 2: Zufälliges k wählen
        let k = rng.gen_biguint_range(&BigUint::from(1u32), &params.q);
        
        // Schritt 3: r berechnen
        let r = mod_pow(&params.g, &k, &params.p) % &params.q;
        
        if r == BigUint::zero() {
            continue; // Ungültiges r, neue Runde
        }
        
        // Schritt 4: s berechnen
        let k_inv = mod_inverse(&k, &params.q)?;
        let s = (&k_inv * (&hash_int + private_key * &r)) % &params.q;
        
        if s != BigUint::zero() {
            return Ok((r, s)); // Gültige Signatur gefunden
        }
        // Sonst: s = 0, neue Runde
    }
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
        return Err("Modulares Inverses existiert nicht - k und q sind nicht teilerfremd".into());
    }
    
    Ok((x % m + m) % m)
}
