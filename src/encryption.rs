use hex;
use rand::{self, rngs::StdRng, SeedableRng};
use rand::RngCore;
use cipher::generic_array::GenericArray;

use crate::
{
    hashing::{self, file_hash::hash_file, trihash}, other::{append_file::append_file, copy_file::copy_file}, symmetric::
    {
        aes::Aes256Cipher, camellia::CamelliaCipher, cbc::cbc_encrypt_file_no_iv, gift::GiftCipher, kuznyechik::KuznyechikCipher, magma::MagmaCipher, serpent::SerpentCipher, sm4::Sm4Cipher, threefish::ThreefishCipher, twofish::TwofishCipher, xtea::XteaCipher
    }
};
use crate::hashing::padding::pad_file;
use crate::other::overwrite_file::overwrite_file;
use crate::hashing::padding::PADDING_IV_SIZE;
use crate::symmetric::chacha20::chacha20_xor;

pub fn encrypt_file(input_filename: &str, output_filename: &str, password: Option<&str>, hex_value: Option<&str>) {
    if !overwrite_file(output_filename) {
        return;
    }

    if let Err(e) = copy_file(input_filename, output_filename) {
        println!("Failed to copy file: {}", e);
        return;
    }

    //pad file
    if let Err(e) = pad_file(output_filename) {
        println!("Failed to pad file: {}", e);
        return;
    }

    // Convert hex_value to a 64-bit array or generate a random one
    let mut iv = [0u8; PADDING_IV_SIZE];
    if let Some(hex) = hex_value {
        // Convert hex string to bytes
        hex::decode_to_slice(hex, &mut iv).expect("Invalid hex value");
    } else {
        // Generate random 128-bit value from os rng
        let mut rng = StdRng::from_os_rng();
        rng.fill_bytes(&mut iv);
    }

    //key generation
    println!("Generating keys");
    let keys = hashing::extract_keys::extract_keys(password, &iv);
    let chacha20_key = GenericArray::from_slice(&keys.0[..32]);
    let chacha20_nonce = GenericArray::from_slice(&iv[..8]);
    
    println!("Encrypting file");
    chacha20_xor(output_filename, *chacha20_key, *chacha20_nonce);
    cbc_encrypt_file_no_iv::<XteaCipher>(output_filename, &keys.1[..16].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<CamelliaCipher>(output_filename, &keys.2[..32].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<ThreefishCipher>(output_filename, &keys.3[..128].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<MagmaCipher>(output_filename, &keys.4[..32].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<Sm4Cipher>(output_filename, &keys.5[..16].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<KuznyechikCipher>(output_filename, &keys.6[..32].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<GiftCipher>(output_filename, &keys.7[..16].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<SerpentCipher>(output_filename, &keys.8[..32].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<TwofishCipher>(output_filename, &keys.9[..32].try_into().expect("Slice with incorrect length"));
    cbc_encrypt_file_no_iv::<Aes256Cipher>(output_filename, &keys.10[..32].try_into().expect("Slice with incorrect length"));

    //append iv to the end of the file
    if let Err(e) = append_file(output_filename, &iv) {
        println!("Failed to append IV: {}", e);
        return;
    }
    println!("Appended IV to file");

    println!("Calculating trihash");
    let trihash = hash_file(output_filename, "trihash");
    
    let trihash_hex = trihash["Trihash"].as_str().unwrap_or("");
    println!("Trihash value: {}", trihash_hex);
    
    println!("Verifying trihash");
    let trihash_bytes = hex::decode(trihash_hex).unwrap_or_default();
    let verified_trihash = trihash::trihash_array(&[&trihash_bytes, &keys.11]);
    
    // Write verified trihash to the end of the file
    if let Err(e) = append_file(output_filename, &verified_trihash) {
        println!("Failed to append verified trihash: {}", e);
        return;
    }

    println!("Encryption process completed.");
}