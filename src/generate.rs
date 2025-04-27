use std::fs::File;
use std::io::Write;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pqcrypto::prelude::*;
use rand::TryRngCore;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::RsaPrivateKey;

use pqcrypto::kem::hqc256::keypair as hqc256_keypair;
use pqcrypto::kem::mceliece8192128f::keypair as mceliece8192128f_keypair;
use pqcrypto::kem::mlkem1024::keypair as mlkem1024_keypair;
use x25519_dalek::PublicKey as x25519_PublicKey;

use pqcrypto::sign::falconpadded1024::keypair as falconpadded1024_keypair;
use pqcrypto::sign::mldsa87::keypair as mldsa87_keypair;
use pqcrypto::sign::sphincssha2256ssimple::keypair as sphincssha2256ssimple_keypair;
use pqcrypto::sign::sphincsshake256fsimple::keypair as sphincsshake256fsimple_keypair;
use ed25519_dalek::SigningKey;


use crate::other::overwrite_file::overwrite_file;

pub fn generate_trikey(output_pubkey_filename: &str, output_privkey_filename: &str) {
    if !overwrite_file(output_pubkey_filename) {
        return;
    }
    if !overwrite_file(output_privkey_filename) {
        return;
    }

    let mut csprng = rand::rngs::OsRng::default();
    let mut rng_rsa = rand_rsa::thread_rng();

    let mut tripubkey_file = File::create(output_pubkey_filename).expect("Failed to create pubkey file");
    let mut triprivkey_file = File::create(output_privkey_filename).expect("Failed to create privkey file");

    //RSA Key
    println!("Generating RSA key");
    let rsa_private_key = RsaPrivateKey::new(&mut rng_rsa, 4096).expect("Failed to generate RSA private key");
    let rsa_public_key = rsa_private_key.to_public_key();

    //KEM keys
    println!("Generating hqc256 key");
    let (hqc256_pk, hqc256_sk) = hqc256_keypair();
    println!("Generating mceliece8192128f key");
    let (mceliece8192128f_pk, mceliece8192128f_sk) = mceliece8192128f_keypair();
    println!("Generating mlkem1024 key");
    let (mlkem1024_pk, mlkem1024_sk) = mlkem1024_keypair();

    println!("Generating x25519 key");
    let mut x25519_sk = [0u8; 32];
    csprng.try_fill_bytes(&mut x25519_sk).expect("Failed to fill secret key");
    let x25519_pk = x25519_PublicKey::from(x25519_sk);

    //signing keys
    println!("Generating falconpadded1024 key");
    let (falconpadded1024_pk, falconpadded1024_sk) = falconpadded1024_keypair();
    println!("Generating mldsa87 key");
    let (mldsa87_pk, mldsa87_sk) = mldsa87_keypair();
    println!("Generating sphincssha2256ssimple key");
    let (sphincssha2256ssimple_pk, sphincssha2256ssimple_sk) = sphincssha2256ssimple_keypair();
    println!("Generating sphincsshake256fsimple key");
    let (sphincsshake256fsimple_pk, sphincsshake256fsimple_sk) = sphincsshake256fsimple_keypair();

    //ed25519 key
    println!("Generating ed25519 key");
    let mut ed25519_sk = [0u8; 32];
    csprng.try_fill_bytes(&mut ed25519_sk).expect("Failed to fill secret key");
    let signing_key = SigningKey::from_bytes(&ed25519_sk);
    let ed25519_pk = signing_key.verifying_key();
    // convert to base64
    let rsa_pk_doc = rsa_public_key
        .to_pkcs1_der()
        .expect("Failed to encode RSA public key");
    let rsa_pk_base64 = STANDARD.encode(rsa_pk_doc.as_bytes());
    let rsa_sk_doc = rsa_private_key
        .to_pkcs1_der()
        .expect("Failed to encode RSA private key");
    let rsa_sk_base64 = STANDARD.encode(rsa_sk_doc.as_bytes());

    let hqc256_pk_base64 = STANDARD.encode(hqc256_pk.as_bytes());
    let hqc256_sk_base64 = STANDARD.encode(hqc256_sk.as_bytes());
    
    let mceliece8192128f_pk_base64 = STANDARD.encode(mceliece8192128f_pk.as_bytes());
    let mceliece8192128f_sk_base64 = STANDARD.encode(mceliece8192128f_sk.as_bytes());

    let mlkem1024_pk_base64 = STANDARD.encode(mlkem1024_pk.as_bytes());
    let mlkem1024_sk_base64 = STANDARD.encode(mlkem1024_sk.as_bytes());
    
    let x25519_pk_base64 = STANDARD.encode(x25519_pk.as_bytes());
    let x25519_sk_base64 = STANDARD.encode(&x25519_sk);

    let falconpadded1024_pk_base64 = STANDARD.encode(falconpadded1024_pk.as_bytes());
    let falconpadded1024_sk_base64 = STANDARD.encode(falconpadded1024_sk.as_bytes());

    let mldsa87_pk_base64 = STANDARD.encode(mldsa87_pk.as_bytes());
    let mldsa87_sk_base64 = STANDARD.encode(mldsa87_sk.as_bytes());

    let sphincssha2256ssimple_pk_base64 = STANDARD.encode(sphincssha2256ssimple_pk.as_bytes());
    let sphincssha2256ssimple_sk_base64 = STANDARD.encode(sphincssha2256ssimple_sk.as_bytes());

    let sphincsshake256fsimple_pk_base64 = STANDARD.encode(sphincsshake256fsimple_pk.as_bytes());
    let sphincsshake256fsimple_sk_base64 = STANDARD.encode(sphincsshake256fsimple_sk.as_bytes());
    
    let ed25519_pk_base64 = STANDARD.encode(ed25519_pk.as_bytes());
    let ed25519_sk_base64 = STANDARD.encode(&ed25519_sk);

    //pubkey
    tripubkey_file.write_all("-----BEGIN PUBLIC TRIKEY v0.0.1-----\n".as_bytes()).expect("Failed to write public key");
    for i in 0..10 {
        if i != 0 {
            tripubkey_file.write_all("\n-----NEXT KEY-----\n".as_bytes()).expect("Failed to write public key");
        }
        match i {
            0 => tripubkey_file.write_all(rsa_pk_base64.as_bytes()).expect("Failed to write public key"),
            1 => tripubkey_file.write_all(hqc256_pk_base64.as_bytes()).expect("Failed to write public key"),
            2 => tripubkey_file.write_all(mceliece8192128f_pk_base64.as_bytes()).expect("Failed to write public key"),
            3 => tripubkey_file.write_all(mlkem1024_pk_base64.as_bytes()).expect("Failed to write public key"),
            4 => tripubkey_file.write_all(x25519_pk_base64.as_bytes()).expect("Failed to write public key"),
            5 => tripubkey_file.write_all(falconpadded1024_pk_base64.as_bytes()).expect("Failed to write public key"),
            6 => tripubkey_file.write_all(mldsa87_pk_base64.as_bytes()).expect("Failed to write public key"),
            7 => tripubkey_file.write_all(sphincssha2256ssimple_pk_base64.as_bytes()).expect("Failed to write public key"),
            8 => tripubkey_file.write_all(sphincsshake256fsimple_pk_base64.as_bytes()).expect("Failed to write public key"),
            9 => tripubkey_file.write_all(ed25519_pk_base64.as_bytes()).expect("Failed to write public key"),
            _ => {}
        }
    }
    tripubkey_file.write_all("-----END PUBLIC TRIKEY-----\n".as_bytes()).expect("Failed to write public key");
    
    //privkey
    triprivkey_file.write_all("-----BEGIN PRIVATE TRIKEY v0.0.1-----\n".as_bytes()).expect("Failed to write public key");
    for i in 0..10 {
        if i != 0 {
            triprivkey_file.write_all("\n-----NEXT KEY-----\n".as_bytes()).expect("Failed to write public key");
        }
            match i {
                0 => triprivkey_file.write_all(rsa_sk_base64.as_bytes()).expect("Failed to write private key"),
                1 => triprivkey_file.write_all(hqc256_sk_base64.as_bytes()).expect("Failed to write private key"),
                2 => triprivkey_file.write_all(mceliece8192128f_sk_base64.as_bytes()).expect("Failed to write private key"),
                3 => triprivkey_file.write_all(mlkem1024_sk_base64.as_bytes()).expect("Failed to write private key"),
                4 => triprivkey_file.write_all(x25519_sk_base64.as_bytes()).expect("Failed to write private key"),
                5 => triprivkey_file.write_all(falconpadded1024_sk_base64.as_bytes()).expect("Failed to write private key"),
                6 => triprivkey_file.write_all(mldsa87_sk_base64.as_bytes()).expect("Failed to write private key"),
                7 => triprivkey_file.write_all(sphincssha2256ssimple_sk_base64.as_bytes()).expect("Failed to write private key"),
                8 => triprivkey_file.write_all(sphincsshake256fsimple_sk_base64.as_bytes()).expect("Failed to write private key"),
                9 => triprivkey_file.write_all(ed25519_sk_base64.as_bytes()).expect("Failed to write private key"),
            _ => {}
        }
    }
    triprivkey_file.write_all("\n-----END PRIVATE TRIKEY-----\n".as_bytes()).expect("Failed to write private key");

    println!("Trikey generated successfully");
}
