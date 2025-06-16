use clap::{Parser, ValueEnum};


// Defining the command-line arguments.
#[derive(Parser, Debug)]
struct Cli {
    #[arg(short,long, help = "Path to the input file")]
    file: String,

    #[arg(short,long,help = "Key for the cipher")]
    key: u8,

    #[arg(short,long,help = "Path to the output file")]
    output: String,

    #[arg(short,long,help = "Mode of operation (encrypt/decrypt)")]
    mode: OperationMode,
}

#[derive(Clone, Debug, ValueEnum)]
enum OperationMode {
    Encrypt,
    Decrypt,
}

fn main() {
    let cli: Cli = Cli::parse();
    match cli.mode {
        OperationMode::Encrypt => {
            let content: String = std::fs::read_to_string(&cli.file)
                .expect("Failed to read the input file");
            //println!("{}", content);
            let cypher = encrypt(&content, cli.key);
            std::fs::write(cli.output, cypher)
                .expect("TODO: panic message");
        }
        OperationMode::Decrypt => {

        }
    }
}

fn encrypt(content: &str, key: u8) -> String {
    // Simple additive cipher encryption logic
    content.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { 'A' } else { 'a' };
                let new_char = ((c as u8 - base as u8 + key) % 26) + base as u8;
                new_char as char
            } else {
                c
            }
        })
        .collect()
}
