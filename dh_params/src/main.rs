use clap::Parser;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};

/// DH-Parametergenerierung: Generiert sichere Parameter für Diffie-Hellman-Schlüsselaustausch
#[derive(Parser)]
#[command(name = "dh_params")]
#[command(about = "Generiert Diffie-Hellman Parameter (Primzahl p und Generator g)")]
#[command(version = "1.0")]
struct Args {
    /// Bitlänge der Primzahl (ungefähr)
    #[arg(value_name = "BITLENGTH")]
    bit_length: usize,
    
    /// Anzahl der Miller-Rabin Runden für Primzahltest (Standard: 40)
    #[arg(short = 'r', long = "rounds", default_value = "40")]
    miller_rabin_rounds: usize,
}

/// Modulare Exponentiation: berechnet (base^exp) mod modulus
/// Implementiert das "Square-and-Multiply" Verfahren (Quadrieren und Multiplizieren)
fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus == &BigUint::one() {
        return BigUint::zero();
    }
    
    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();
    
    while exp > BigUint::zero() {
        // Prüfe das niedrigste Bit von exp
        if &exp % 2u32 == BigUint::one() {
            result = (result * &base) % modulus;
        }
        // Bereite nächste Iteration vor: quadriere base, halbiere exp
        exp >>= 1;
        base = (&base * &base) % modulus;
    }
    
    result
}

/// Miller-Rabin Primzahltest
/// Probabilistischer Primzahltest mit Fehlerwahrscheinlichkeit ≤ (1/4)^k
fn miller_rabin(n: &BigUint, k: usize) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n % 2u32 == BigUint::zero() {
        return false;
    }
    
    // Schreibe n-1 = 2^s * d mit d ungerade
    let n_minus_1 = n - 1u32;
    let mut s = 0u32;
    let mut d = n_minus_1.clone();
    
    while &d % 2u32 == BigUint::zero() {
        d >>= 1;
        s += 1;
    }
    
    let mut rng = rand::thread_rng();
    
    // Führe k Testrunden durch
    for _ in 0..k {
        // Wähle zufällige Basis a ∈ [2, n-2]
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - 1u32));
        let mut x = mod_pow(&a, &d, n);
        
        if x == BigUint::one() || x == n_minus_1 {
            continue;
        }
        
        let mut composite = true;
        for _ in 0..(s-1) {
            x = mod_pow(&x, &BigUint::from(2u32), n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }
        
        if composite {
            return false;
        }
    }
    
    true
}

/// Generiert eine sichere Primzahl q und prüft ob p = 2q + 1 auch prim ist
/// Dies erzeugt eine "sichere Primzahl" (safe prime), die für DH geeignet ist
fn generate_safe_prime(bit_length: usize, k: usize) -> (BigUint, BigUint) {
    let mut rng = rand::thread_rng();
    
    loop {
        // Generiere zufällige ungerade Zahl q mit gewünschter Bitlänge
        // Konvertiere usize zu u64 für gen_biguint
        let mut q = rng.gen_biguint((bit_length - 1) as u64);
        q |= BigUint::one(); // Stelle sicher, dass q ungerade ist
        q |= BigUint::one() << (bit_length - 2); // Setze höchstes Bit für korrekte Bitlänge
        
        // Prüfe ob q prim ist
        if !miller_rabin(&q, k) {
            continue;
        }
        
        // Berechne p = 2q + 1
        let p = &q * 2u32 + 1u32;
        
        // Prüfe ob p auch prim ist
        if miller_rabin(&p, k) {
            return (p, q);
        }
    }
}

/// Findet einen Generator (oder Beinahe-Generator) für Z*_p
/// Für sichere Primzahlen p = 2q + 1 testen wir einfache Kandidaten
fn find_generator(p: &BigUint, q: &BigUint) -> BigUint {
    let candidates = [2u32, 3u32, 5u32, 7u32, 11u32, 13u32, 17u32, 19u32, 23u32, 29u32];
    
    for &candidate in &candidates {
        let g = BigUint::from(candidate);
        
        // g muss in [2, p-2] liegen
        if g >= p - 1u32 {
            continue;
        }
        
        // Prüfe ob g^q ≢ 1 (mod p) und g^2 ≢ 1 (mod p)
        // Dies stellt sicher, dass g eine große Ordnung hat
        let g_to_q = mod_pow(&g, q, p);
        let g_to_2 = mod_pow(&g, &BigUint::from(2u32), p);
        
        if g_to_q != BigUint::one() && g_to_2 != BigUint::one() {
            return g;
        }
    }
    
    // Fallback: verwende g = 2
    BigUint::from(2u32)
}

fn main() {
    let args = Args::parse();
    
    // Validiere Eingabe
    if args.bit_length < 8 {
        eprintln!("Fehler: Bitlänge muss mindestens 8 sein");
        std::process::exit(1);
    }
    
    // Generiere sichere Primzahl p = 2q + 1
    let (p, q) = generate_safe_prime(args.bit_length, args.miller_rabin_rounds);
    
    // Finde Generator g
    let g = find_generator(&p, &q);
    
    // Ausgabe in gewünschtem Format
    println!("{}", p);  // erste Zeile: Primzahl p
    println!("{}", g);  // zweite Zeile: Generator g
}
