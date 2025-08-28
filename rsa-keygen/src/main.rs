use clap::Parser;
use std::fs;
use std::path::PathBuf;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};
use rand::thread_rng;

/// RSA-Schlüsselgenerierung
/// 
/// Generiert RSA-Schlüsselpaare mit den angegebenen Parametern.
/// Implementiert Miller-Rabin Primzahltest und Square-and-Multiply für modulare Exponentiation.
#[derive(Parser)]
#[command(
    name = "rsa-keygen",
    about = "RSA key generation utility",
    long_about = "
Generiert RSA-Schlüsselpaare durch:
1. Erzeugung zweier großer Primzahlen p, q
2. Berechnung von n = p * q und φ(n) = (p-1)(q-1)  
3. Wahl von e (oft 65537) teilerfremd zu φ(n)
4. Berechnung von d ≡ e^(-1) (mod φ(n)) mit erweitertem euklidischen Algorithmus

AUSGABEFORMAT:
- Privater Schlüssel: d (Zeile 1), n (Zeile 2)
- Öffentlicher Schlüssel: e (Zeile 1), n (Zeile 2)  
- Primzahlen: p (Zeile 1), q (Zeile 2)
"
)]
#[command(version)]
struct Args {
    /// Gewünschte Bitlänge des Schlüssels (ca., als Zahl)
    #[arg(long, value_name = "LÄNGE")]
    length: u32,

    /// Ausgabedatei für privaten Schlüssel (d, n)
    #[arg(long, value_name = "OUTPUT_PRIVAT")]
    private_output: PathBuf,

    /// Ausgabedatei für öffentlichen Schlüssel (e, n)
    #[arg(long, value_name = "OUTPUT_ÖFFENTLICH")]
    public_output: PathBuf,

    /// Ausgabedatei für benutzte Primzahlen (p, q)
    #[arg(long, value_name = "OUTPUT_BENUTZTE_PRIMZAHLEN")]
    primes_output: PathBuf,
}

/// Berechnet x^m mod n mittels Square-and-Multiply
fn mod_pow(mut x: BigUint, m: &BigUint, n: &BigUint) -> BigUint {
    let mut y = BigUint::one();
    let bit_length = m.bits();
    
    for i in 0..bit_length {
        if m.bit(i) {
            y = (&y * &x) % n;
        }
        x = (&x * &x) % n;
    }
    
    y
}

/// Miller-Rabin Primzahltest
/// 
/// Probabilistischer Primzahltest mit k Runden.
/// Fehlerwahrscheinlichkeit: höchstens (1/4)^k
fn miller_rabin_test(n: &BigUint, k: u32) -> bool {
    // Spezialfälle
    if *n == BigUint::from(2u32) || *n == BigUint::from(3u32) {
        return true;
    }
    if n < &BigUint::from(2u32) || n % 2u32 == BigUint::zero() {
        return false;
    }

    // Schreibe n-1 als d * 2^r mit ungeradem d
    let mut d = n - 1u32;
    let mut r = 0u32;
    while &d % 2u32 == BigUint::zero() {
        d /= 2u32;
        r += 1;
    }

    let mut rng = thread_rng();
    
    // k Testrunden
    'outer: for _ in 0..k {
        // Wähle zufällige Basis a im Bereich [2, n-2]
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - 1u32));
        let mut x = mod_pow(a, &d, n);
        
        if x == BigUint::one() || x == n - 1u32 {
            continue;
        }
        
        // Wiederhole r-1 mal das Quadrieren
        for _ in 0..r-1 {
            x = mod_pow(x.clone(), &BigUint::from(2u32), n);
            if x == n - 1u32 {
                continue 'outer;
            }
        }
        return false; // Zusammengesetzt
    }
    true // Wahrscheinlich prim
}

/// Generiert Primzahl mit ungefähr der gewünschten Bitlänge
/// 
/// Verwendet die Optimierung aus dem Lab: Teste 30z + i für i ∈ {1,7,11,13,17,19,23,29,...}
/// um Zahlen zu vermeiden, die durch kleine Primzahlen teilbar sind.
fn generate_prime(bit_length: u32) -> BigUint {
    let mut rng = thread_rng();
    let offsets = [1u32, 7, 11, 13, 17, 19, 23, 29];
    
    loop {
        // Generiere zufällige Basis z
        let z = rng.gen_biguint(bit_length as u64);
        let base = (&z / 30u32) * 30u32;
        
        // Teste 30z + i für verschiedene i
        for &offset in &offsets {
            let candidate: BigUint = &base + BigUint::from(offset);
            
            // Stelle sicher, dass die Bitlänge stimmt
            if candidate.bits() as u32 != bit_length {
                continue;
            }
            
            // Miller-Rabin Test mit 20 Runden (hohe Sicherheit)
            if miller_rabin_test(&candidate, 20) {
                return candidate;
            }
        }
    }
}

/// Erweiteter euklidischer Algorithmus
/// 
/// Berechnet gcd(a,b) und Koeffizienten x,y sodass ax + by = gcd(a,b)
fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
    if *a == BigUint::zero() {
        return (b.clone(), BigUint::zero(), BigUint::one());
    }
    
    let (gcd, x1, y1) = extended_gcd(&(b % a), a);
    
    // Berechne x = y1 - (b/a) * x1
    let quotient = b / a;
    let product = &quotient * &x1;
    
    let x = if y1 >= product {
        y1 - product
    } else {
        // Behandle negativen Fall - addiere Modulus um positiv zu machen
        let diff = product - y1;
        if diff < *b {
            b - diff
        } else {
            BigUint::zero()
        }
    };
    
    (gcd, x, x1)
}

/// Berechnet modulares Inverses von a modulo m mittels erweitertem euklidischen Algorithmus
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (gcd, x, _) = extended_gcd(a, m);
    
    if gcd != BigUint::one() {
        return None; // Kein Inverses existiert
    }
    
    // Normalisiere x zu positivem Wert
    Some(x % m)
}

/// Generiert RSA-Schlüsselpaar
/// 
/// Algorithmus:
/// 1. Generiere zwei verschiedene Primzahlen p, q
/// 2. Berechne n = p * q und φ(n) = (p-1)(q-1)
/// 3. Wähle e teilerfremd zu φ(n) (verwendet 2^16 + 1 = 65537)
/// 4. Berechne d ≡ e^(-1) (mod φ(n))
fn generate_keypair(bit_length: u32) -> Result<(BigUint, BigUint, BigUint, BigUint, BigUint), Box<dyn std::error::Error>> {
    // Generiere zwei verschiedene Primzahlen
    let p = generate_prime(bit_length / 2);
    let mut q = generate_prime(bit_length / 2);
    
    // Stelle sicher, dass p ≠ q
    while p == q {
        q = generate_prime(bit_length / 2);
    }
    
    let n = &p * &q;
    let phi = (&p - 1u32) * (&q - 1u32);
    
    // Wähle e = 2^16 + 1 = 65537 (häufig verwendet, da prim und kleine Hamming-Gewicht)
    let e = BigUint::from(65537u32);
    
    // Überprüfe, dass gcd(e, φ(n)) = 1
    let (gcd, _, _) = extended_gcd(&e, &phi);
    if gcd != BigUint::one() {
        return Err("e ist nicht teilerfremd zu φ(n)".into());
    }
    
    // Berechne d als modulares Inverses von e modulo φ(n)
    let d = mod_inverse(&e, &phi)
        .ok_or("Kann modulares Inverses nicht berechnen")?;
    
    Ok((p, q, n, e, d))
}

/// Schreibt zwei BigUint-Werte in eine Datei (eine pro Zeile, dezimal)
fn write_key_file(file_path: &PathBuf, val1: &BigUint, val2: &BigUint) -> Result<(), Box<dyn std::error::Error>> {
    // Erstelle Elternverzeichnis falls nötig
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let content = format!("{}\n{}", val1, val2);
    fs::write(file_path, content)
        .map_err(|e| format!("Fehler beim Schreiben in {}: {}", file_path.display(), e))?;
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Validiere Eingabe
    if args.length < 512 {
        return Err("Bitlänge sollte mindestens 512 sein für Sicherheit".into());
    }
    
    // Generiere RSA-Schlüsselpaar
    let (p, q, n, e, d) = generate_keypair(args.length)?;
    
    // Schreibe privaten Schlüssel (d, n)
    write_key_file(&args.private_output, &d, &n)?;
    
    // Schreibe öffentlichen Schlüssel (e, n)
    write_key_file(&args.public_output, &e, &n)?;
    
    // Schreibe benutzte Primzahlen (p, q)
    write_key_file(&args.primes_output, &p, &q)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_miller_rabin_known_primes() {
        assert!(miller_rabin_test(&BigUint::from(17u32), 10));
        assert!(miller_rabin_test(&BigUint::from(97u32), 10));
        assert!(!miller_rabin_test(&BigUint::from(15u32), 10));
        assert!(!miller_rabin_test(&BigUint::from(21u32), 10));
    }
    
    #[test]
    fn test_mod_inverse() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }
    
    #[test]
    fn test_keypair_generation_small() {
        let (p, q, n, e, d) = generate_keypair(1024).unwrap();
        
        // Teste, dass p und q prim sind (approximativ)
        assert!(miller_rabin_test(&p, 10));
        assert!(miller_rabin_test(&q, 10));
        
        // Teste, dass n = p * q
        assert_eq!(n, &p * &q);
        
        // Teste, dass e * d ≡ 1 (mod φ(n))
        let phi = (&p - 1u32) * (&q - 1u32);
        assert_eq!((&e * &d) % &phi, BigUint::one());
    }
}
