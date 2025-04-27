mod encryption;
mod decryption;
mod hashing;
mod other;
mod symmetric;
mod generate;
use clap::{Arg, Command};
use rpassword::read_password;
use std::thread;

fn run() {
    let matches = Command::new("Tricrypt CLI Tool")
        .version("0.0.1")
        .author("Trinami")
        .about("Hashes input files using various algorithms or encrypts files")
        .subcommand(
            Command::new("hash")
                .about("Hashes input files using various algorithms")
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .value_name("FILE")
                        .help("Sets the input file to use for hashing")
                        .required(true),
                )
                .arg(
                    Arg::new("hashes")
                        .short('x')
                        .long("hashes")
                        .value_name("HASHES")
                        .help("Comma-separated list of hashes to use (e.g., sha2_384,sha3_512,ripemd320,tiger2,whirlpool,blake2b512,blake3,streebog512,jh512,trihash) or 'all'")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("encrypt")
                .about("Encrypts the input file to the output file with an optional password")
                .arg(
                    Arg::new("input-filename")
                        .long("input")
                        .value_name("INPUT")
                        .help("Sets the input file to use for encryption")
                        .required(true),
                )
                .arg(
                    Arg::new("output-filename")
                        .long("output")
                        .value_name("OUTPUT")
                        .help("Sets the output file for encryption")
                        .required(true),
                )
                .arg(
                    Arg::new("password")
                        .long("password")
                        .value_name("PASSWORD")
                        .help("Optional password for encryption")
                        .required(false),
                )
                .arg(
                    Arg::new("random-hex-value")
                        .long("random")
                        .value_name("RANDOM")
                        .help("Optional 128-bit, secure, random, hex value for encryption")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts the input file to the output file with an optional password")
                .arg(
                    Arg::new("input-filename")
                        .long("input")
                        .value_name("INPUT")
                        .help("Sets the input file to use for decryption")
                        .required(true),
                )
                .arg(
                    Arg::new("output-filename")
                        .long("output")
                        .value_name("OUTPUT")
                        .help("Sets the output file for decryption")
                        .required(true),
                )
                .arg(
                    Arg::new("password")
                        .long("password")
                        .value_name("PASSWORD")
                        .help("Optional password for decryption")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("generate")
                .about("Generates a trikey")
                .arg(
                    Arg::new("output-pubkey-filename")
                        .long("output-pubkey")
                        .value_name("OUTPUT_PUBKEY")
                        .help("Sets the output file for the public trikey")
                        .required(true),
                )
                .arg(
                    Arg::new("output-privkey-filename")
                        .long("output-privkey")
                        .value_name("OUTPUT_PRIVKEY")
                        .help("Sets the output file for the private trikey")
                        .required(true),
                ),
        );

    let matches = matches.get_matches();

    match matches.subcommand() {
        Some(("hash", sub_m)) => {
            let file_path = sub_m.get_one::<String>("file").unwrap();
            let hashes = sub_m.get_one::<String>("hashes").unwrap();
            hashing::file_hash::hash_file(file_path, hashes);
        }
        Some(("encrypt", sub_m)) => {
            let input_filename = sub_m.get_one::<String>("input-filename").unwrap();
            let output_filename = sub_m.get_one::<String>("output-filename").unwrap();
            let password = match sub_m.get_one::<String>("password").map(|s| s.as_str()) {
                Some(p) => Some(p.to_string()),
                None => {
                    println!("Enter password: ");
                    let pass1 = read_password().expect("Failed to read password");
                    println!("Confirm password: ");
                    let pass2 = read_password().expect("Failed to read password");
                    if pass1 == pass2 {
                        Some(pass1)
                    } else {
                        eprintln!("Passwords do not match.");
                        return;
                    }
                }
            };
            let random_hex_value = sub_m.get_one::<String>("random-hex-value").map(|s| s.as_str());
            encryption::encrypt_file(input_filename, output_filename, password.as_deref(), random_hex_value);
        }
        Some(("decrypt", sub_m)) => {
            let input_filename = sub_m.get_one::<String>("input-filename").unwrap();
            let output_filename = sub_m.get_one::<String>("output-filename").unwrap();
            let password = match sub_m.get_one::<String>("password").map(|s| s.as_str()) {
                Some(p) => Some(p.to_string()),
                None => {
                    println!("Enter password: ");
                    let pass1 = read_password().expect("Failed to read password");
                    println!("Confirm password: ");
                    let pass2 = read_password().expect("Failed to read password");
                    if pass1 == pass2 {
                        Some(pass1)
                    } else {
                        eprintln!("Passwords do not match.");
                        return;
                    }
                }
            };
            decryption::decrypt_file(input_filename, output_filename, password.as_deref());
        }
        Some(("generate", sub_m)) => {
            let output_pubkey_filename = sub_m.get_one::<String>("output-pubkey-filename").unwrap();
            let output_privkey_filename = sub_m.get_one::<String>("output-privkey-filename").unwrap();
            generate::generate_trikey(output_pubkey_filename, output_privkey_filename);
        }
        _ => {
            eprintln!("No subcommand was used. Use 'hash' or 'encrypt'.\n");
            let _ = Command::new("Trihash CLI Tool").print_help();
        }
    }
}

fn main() {
    thread::Builder::new()
        .stack_size(763 * 1024 * 1024)
        .spawn(|| run())
        .expect("Failed to spawn thread with increased stack size")
        .join()
        .expect("Application thread panicked");
}
