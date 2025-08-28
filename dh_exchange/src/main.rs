use clap::Parser;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};
use std::io::{self, BufRead};

/// DH-Schlüsselaustausch: Führt Diffie-Hellman Schlüsselaustausch durch
#[derive(Parser)]
#[command(name = "dh_exchange")]
#[command(about = "Führt Diffie-Hellman Schlüsselaustausch durch")]
#[command(version = "1.0")]
struct Args {
    /// Verwende vorgegebene private Schlüssel für Tests (unsicher!)
    #[arg(long = "test-mode")]
    test_mode: bool,
    
    /// Alices privater Schlüssel (nur im Test-Modus)
    #[arg(long = "alice-key")]
    alice_key: Option<String>,
}

/// Modulare Exponentiation mit Square-and-Multiply Algorithmus
fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus == &BigUint::one() {
        return BigUint::zero();
    }
    
    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();
    
    while exp > BigUint::zero() {
        if &exp % 2u32 == BigUint::one() {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }
    
    result
}

/// Generiert sicheren privaten Schlüssel für Diffie-Hellman
/// Der private Schlüssel liegt im Bereich [2, p-2] und hat ausreichende Bitlänge
fn generate_private_key(p: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    
    // Generiere Schlüssel im Bereich [2, p-2]
    // Verwende mindestens 160 Bits für Sicherheit
    let min_bits = std::cmp::min(160, p.bits() - 2);
    let mut private_key = rng.gen_biguint(min_bits as u64);
    
    // Stelle sicher, dass der Schlüssel im gültigen Bereich liegt
    private_key = private_key % (p - 2u32) + 2u32;
    
    private_key
}

/// Liest eine Zeile von stdin und konvertiert sie zu BigUint
fn read_biguint_from_stdin() -> Result<BigUint, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err("Leere Eingabe erhalten".into());
    }
    
    let number = trimmed.parse::<BigUint>()?;
    Ok(number)
}

/// Validiert DH-Parameter auf grundlegende Sicherheitseigenschaften
fn validate_dh_params(p: &BigUint, g: &BigUint) -> Result<(), Box<dyn std::error::Error>> {
    // p sollte mindestens 512 Bits haben
    if p.bits() < 512 {
        return Err(format!("Warnung: p hat nur {} Bits, empfohlen sind mindestens 1024", p.bits()).into());
    }
    
    // g sollte im Bereich [2, p-2] liegen
    if g < &BigUint::from(2u32) || g >= &(p - 1u32) {
        return Err("g muss im Bereich [2, p-2] liegen".into());
    }
    
    // p sollte ungerade sein
    if p % 2u32 == BigUint::zero() {
        return Err("p sollte eine ungerade Primzahl sein".into());
    }
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Schritt 1: Lese Parameter p und g von stdin
    let p = read_biguint_from_stdin()?;
    let g = read_biguint_from_stdin()?;
    
    // Validiere Parameter
    validate_dh_params(&p, &g)?;
    
    // Schritt 2: Generiere Alices private und öffentliche Schlüssel
    let alice_private = if args.test_mode && args.alice_key.is_some() {
        args.alice_key.unwrap().parse::<BigUint>()?
    } else {
        generate_private_key(&p)
    };
    
    // Berechne Alices öffentlichen Schlüssel: A = g^a mod p
    let alice_public = mod_pow(&g, &alice_private, &p);
    
    // Schritt 3: Ausgabe von Alices öffentlichem Schlüssel
    println!("{}", alice_public);
    
    // Schritt 4: Lese Bobs öffentlichen Schlüssel
    let bob_public = read_biguint_from_stdin()?;
    
    // Validiere Bobs öffentlichen Schlüssel
    // Verwende Referenzen um Ownership-Probleme zu vermeiden
    let p_minus_1 = &p - 1u32;
    if bob_public < BigUint::from(2u32) || bob_public >= p_minus_1 {
        return Err("Bobs öffentlicher Schlüssel ist ungültig".into());
    }
    
    // Schritt 5: Berechne gemeinsames Geheimnis
    // Alice berechnet: S = B^a mod p
    let shared_secret = mod_pow(&bob_public, &alice_private, &p);
    
    // Schritt 6: Ausgabe des gemeinsamen Geheimnisses
    println!("{}", shared_secret);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mod_pow() {
        let base = BigUint::from(2u32);
        let exp = BigUint::from(10u32);
        let modulus = BigUint::from(1000u32);
        
        let result = mod_pow(&base, &exp, &modulus);
        assert_eq!(result, BigUint::from(24u32)); // 2^10 mod 1000 = 1024 mod 1000 = 24
    }
    
    #[test]
    fn test_dh_exchange() {
        // Verwende kleine Werte für Test
        let p = BigUint::from(23u32);
        let g = BigUint::from(5u32);
        let alice_private = BigUint::from(6u32);
        let bob_private = BigUint::from(15u32);
        
        // Alice berechnet A = g^a mod p
        let alice_public = mod_pow(&g, &alice_private, &p);
        
        // Bob berechnet B = g^b mod p  
        let bob_public = mod_pow(&g, &bob_private, &p);
        
        // Beide berechnen gemeinsames Geheimnis
        let alice_secret = mod_pow(&bob_public, &alice_private, &p);
        let bob_secret = mod_pow(&alice_public, &bob_private, &p);
        
        assert_eq!(alice_secret, bob_secret);
    }
}
