use cipher::generic_array::GenericArray;
use hex;

use crate::{hashing::{self, trihash}, other::{copy_file::copy_file, truncate_file::truncate_file_with_return}, symmetric::
{
    cbc::cbc_decrypt_file_no_iv,
    aes::Aes256Cipher,
    camellia::CamelliaCipher,
    gift::GiftCipher,
    kuznyechik::KuznyechikCipher,
    magma::MagmaCipher,
    serpent::SerpentCipher,
    sm4::Sm4Cipher,
    threefish::ThreefishCipher,
    twofish::TwofishCipher,
    xtea::XteaCipher
}};
use crate::hashing::padding::unpad_file;
use crate::other::overwrite_file::overwrite_file;
use crate::hashing::padding::PADDING_IV_SIZE;
use crate::symmetric::chacha20::chacha20_xor;

pub fn decrypt_file(input_filename: &str, output_filename: &str, password: Option<&str>) {
    if !overwrite_file(output_filename) {
        return;
    }

    if let Err(e) = copy_file(input_filename, output_filename) {
        println!("Failed to copy file: {}", e);
        return;
    }

    let unverified_trihash = truncate_file_with_return(output_filename, 32);
    if let Err(e) = unverified_trihash {
        println!("Failed to truncate trihash: {}", e);
        return;
    }

    println!("Calculating trihash");
    let trihash = hashing::file_hash::hash_file(output_filename, "trihash");
    let trihash_hex = trihash["Trihash"].as_str().unwrap_or("");
    println!("Trihash value: {}", trihash_hex);

    //truncate iv
    let iv = truncate_file_with_return(output_filename, PADDING_IV_SIZE);
    if let Err(e) = iv {
        println!("Failed to truncate IV: {}", e);
        return;
    }
    let iv = iv.unwrap();
    println!("IV: {:?}", hex::encode(&iv));

    println!("Generating keys");
    //key generation
    let keys = hashing::extract_keys::extract_keys(password, &iv);
    let chacha20_key = GenericArray::from_slice(&keys.0[..32]);
    let chacha20_nonce = GenericArray::from_slice(&iv[..8]);
    
    println!("Verifying trihash");
    let trihash_bytes = hex::decode(trihash_hex).unwrap_or_default();
    let verified_trihash = trihash::trihash_array(&[&trihash_bytes, &keys.11]);

    if verified_trihash != unverified_trihash.unwrap().as_slice() {
        println!("Verifying trihash failed");
        return;
    }
    println!("Verifying trihash success");

    println!("Decrypting file");
    cbc_decrypt_file_no_iv::<Aes256Cipher>(output_filename, &keys.10[..32].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<TwofishCipher>(output_filename, &keys.9[..32].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<SerpentCipher>(output_filename, &keys.8[..32].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<GiftCipher>(output_filename, &keys.7[..16].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<KuznyechikCipher>(output_filename, &keys.6[..32].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<Sm4Cipher>(output_filename, &keys.5[..16].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<MagmaCipher>(output_filename, &keys.4[..32].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<ThreefishCipher>(output_filename, &keys.3[..128].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<CamelliaCipher>(output_filename, &keys.2[..32].try_into().expect("Slice with incorrect length"));
    cbc_decrypt_file_no_iv::<XteaCipher>(output_filename, &keys.1[..16].try_into().expect("Slice with incorrect length"));
    chacha20_xor(output_filename, *chacha20_key, *chacha20_nonce);

    //unpad file
    if let Err(e) = unpad_file(output_filename) {
        println!("Failed to unpad file: {}", e);
        return;
    }

    println!("Decryption process completed.");
    
}