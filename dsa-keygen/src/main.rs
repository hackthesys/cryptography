use std::fs::File;
use std::io::Write;
use std::error::Error;
use clap::Parser;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};
use rand::thread_rng;

/// DSA-Schlüsselgenerator - Parameter (L, N) = (1024, 160)
#[derive(Parser)]
#[command(name = "dsa_keygen")]
#[command(about = "Generiert DSA Parameter und Schlüssel")]
#[command(version = "1.0")]
struct Args {
    /// Dateiname für den öffentlichen Schlüssel
    #[arg(long, default_value = "public_key.pem")]
    public_key_file: String,
    
    /// Dateiname für den privaten Schlüssel
    #[arg(long, default_value = "private_key.pem")]    
    private_key_file: String,
    
    /// Bitlänge der großen Primzahl p (Standard: 1024)
    #[arg(long, default_value = "1024")]
    p_length: usize,
    
    /// Bitlänge der kleinen Primzahl q (Standard: 160)
    #[arg(long, default_value = "160")]
    q_length: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    validate_parameters(args.p_length, args.q_length)?;
    
    let params = generate_dsa_parameters(args.p_length, args.q_length)?;
    let keys = generate_dsa_keys(&params)?;
    
    write_public_key_file(&args.public_key_file, &params, &keys.public_key)?;
    write_private_key_file(&args.private_key_file, &params, &keys.private_key)?;
    
    Ok(())
}

/// DSA-Parameter
#[derive(Debug, Clone)]
struct DSAParameters {
    p: BigUint,  // 1024-Bit Primzahl
    q: BigUint,  // 160-Bit Primzahl
    g: BigUint,  // Generator
}

/// DSA-Schlüsselpaar  
#[derive(Debug)]
struct DSAKeys {
    private_key: BigUint,  // x
    public_key: BigUint,   // y = g^x mod p
}

fn validate_parameters(l_bits: usize, n_bits: usize) -> Result<(), Box<dyn Error>> {
    if l_bits < n_bits {
        return Err("L muss größer als N sein".into());
    }
    Ok(())
}

fn generate_dsa_parameters(l_bits: usize, n_bits: usize) -> Result<DSAParameters, Box<dyn Error>> {
    let mut rng = thread_rng();
    
    // Konvertiere zu u64 für gen_biguint
    let n_bits_u64 = n_bits as u64;
    let l_bits_u64 = l_bits as u64;
    
    // Generiere q (160 Bits)
    let q = loop {
        let mut candidate = rng.gen_biguint(n_bits_u64);
        candidate |= BigUint::one() << (n_bits - 1);
        candidate |= BigUint::one();
        
        if is_probably_prime(&candidate, 40) {
            break candidate;
        }
    };
    
    // Generiere p (1024 Bits) mit p = k*q + 1
    let p = loop {
        let min_k = (BigUint::one() << (l_bits - 1)) / &q;
        let max_k = ((BigUint::one() << l_bits) - BigUint::one()) / &q;
        
        let k = rng.gen_biguint_range(&min_k, &max_k);
        let p_candidate = &k * &q + BigUint::one();
        
        // Korrigierter Typvergleich
        if p_candidate.bits() == l_bits_u64 && is_probably_prime(&p_candidate, 40) {
            break p_candidate;
        }
    };
    
    // Generiere Generator g
    let exponent = (&p - BigUint::one()) / &q;
    let g = loop {
        let h = rng.gen_biguint_range(&BigUint::from(2u32), &p);
        let g_candidate = mod_pow(&h, &exponent, &p);
        
        if g_candidate != BigUint::one() {
            break g_candidate;
        }
    };
    
    Ok(DSAParameters { p, q, g })
}

fn generate_dsa_keys(params: &DSAParameters) -> Result<DSAKeys, Box<dyn Error>> {
    let mut rng = thread_rng();
    
    let private_key = rng.gen_biguint_range(&BigUint::from(2u32), &params.q);
    let public_key = mod_pow(&params.g, &private_key, &params.p);
    
    Ok(DSAKeys { private_key, public_key })
}

fn write_public_key_file(filename: &str, params: &DSAParameters, public_key: &BigUint) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(filename)?;
    writeln!(file, "{}", params.p)?;
    writeln!(file, "{}", params.q)?;
    writeln!(file, "{}", params.g)?;
    writeln!(file, "{}", public_key)?;
    Ok(())
}

fn write_private_key_file(filename: &str, params: &DSAParameters, private_key: &BigUint) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(filename)?;
    writeln!(file, "{}", params.p)?;
    writeln!(file, "{}", params.q)?;
    writeln!(file, "{}", params.g)?;
    writeln!(file, "{}", private_key)?;
    Ok(())
}

fn is_probably_prime(n: &BigUint, k: u32) -> bool {
    if *n < BigUint::from(2u32) { return false; }
    if *n == BigUint::from(2u32) || *n == BigUint::from(3u32) { return true; }
    if n % BigUint::from(2u32) == BigUint::zero() { return false; }
    
    let mut r = 0u32;
    let mut d = n - BigUint::one();
    while &d % BigUint::from(2u32) == BigUint::zero() {
        d /= BigUint::from(2u32);
        r += 1;
    }
    
    let mut rng = thread_rng();
    
    'outer: for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - BigUint::one()));
        let mut x = mod_pow(&a, &d, n);
        
        if x == BigUint::one() || x == n - BigUint::one() {
            continue 'outer;
        }
        
        for _ in 0..(r-1) {
            x = mod_pow(&x, &BigUint::from(2u32), n);
            if x == n - BigUint::one() {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

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
