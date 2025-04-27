use argon2::{
    password_hash::{
        PasswordHasher, SaltString
    },
    Argon2, Algorithm
};
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::{Sha3_256, Digest as Sha3Digest};
use ripemd::{Ripemd320, Digest as RipemdDigest};
use skein::{Skein256, Digest as SkeinDigest};
use whirlpool::{Whirlpool, Digest as WhirlpoolDigest};
use tiger::{Tiger2, Digest as TigerDigest};
use sm3::{Sm3, Digest as Sm3Digest};
use streebog::{Streebog256, Digest as StreebogDigest};
use fsb::{Fsb256, Digest as FsbDigest};
use jh::{Jh256, Digest as JhDigest};
use generic_array::typenum::U32;

pub fn hash_iv_round(iv: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, &iv);

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);

    return result;
}

pub fn extract_argon2_keys(password: Option<&str>, iv: &[u8]) -> ([u8; 64], [u8; 48], [u8; 64], [u8; 64], [u8; 64], [u8; 40], [u8; 64], [u8; 64], [u8; 64], [u8; 64], [u8; 64], [u8; 64], [u8; 32]) {
    let mut current_iv = hash_iv_round(iv);
    let mut keys = ([0u8; 64], [0u8; 48], [0u8; 64], [0u8; 64], [0u8; 64], [0u8; 40], [0u8; 64], [0u8; 64], [0u8; 64], [0u8; 64], [0u8; 64], [0u8; 64], [0u8; 32]);

    for i in 0..13 {
        current_iv = hash_iv_round(&current_iv);

        let salt = SaltString::encode_b64(&current_iv).unwrap();
        let output_size = match i {
            0 => 64,
            1 => 48,
            2 => 64,
            3 => 64,
            4 => 64,
            5 => 40,
            6 => 64,
            7 => 64,
            8 => 64,
            9 => 64,
            10 => 64,
            11 => 64,
            12 => 32,
            _ => 64,
        };
        
        let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::default(), argon2::Params::new(80 * 1000, (i+1) as u32, 1, Some(output_size)).unwrap());
        let password_hash = argon2.hash_password(
            password.unwrap().as_bytes(),
            &salt,
        ).unwrap();

        let hash = password_hash.hash.unwrap();
        let hash_bytes = hash.as_bytes();
        
        match i {
            0 => keys.0.copy_from_slice(&hash_bytes[..64]),
            1 => keys.1.copy_from_slice(&hash_bytes[..48]),
            2 => keys.2.copy_from_slice(&hash_bytes[..64]),
            3 => keys.3.copy_from_slice(&hash_bytes[..64]),
            4 => keys.4.copy_from_slice(&hash_bytes[..64]),
            5 => keys.5.copy_from_slice(&hash_bytes[..40]),
            6 => keys.6.copy_from_slice(&hash_bytes[..64]),
            7 => keys.7.copy_from_slice(&hash_bytes[..64]),
            8 => keys.8.copy_from_slice(&hash_bytes[..64]),
            9 => keys.9.copy_from_slice(&hash_bytes[..64]),
            10 => keys.10.copy_from_slice(&hash_bytes[..64]),
            11 => keys.11.copy_from_slice(&hash_bytes[..64]),
            12 => keys.12.copy_from_slice(&hash_bytes[..32]),
            _ => (),
        }
    }

    keys
}

// Hash the value 12 times and use each hash as a salt for Argon2id (4th and 5th 64 byte values are for threefish 1024 key)
pub fn extract_keys(password: Option<&str>, iv: &[u8]) -> ([u8; 32], [u8; 16], [u8; 32], [u8; 128], [u8; 32], [u8; 16], [u8; 32], [u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let argon2_keys = extract_argon2_keys(password, iv);

    // Define the keys array with fixed sizes
    let mut keys = ([0u8; 32], [0u8; 16], [0u8; 32], [0u8; 128], [0u8; 32], [0u8; 16], [0u8; 32], [0u8; 16], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);

    //hash the first 64 bytes with blake3
    let mut hasher = blake3::Hasher::new();
    hasher.update(&argon2_keys.0);
    let hash = hasher.finalize();
    keys.0[..32].copy_from_slice(&hash.as_bytes()[..32]);

    //hash 2nd 48 bytes with tiger192
    let mut hasher = Tiger2::new();
    TigerDigest::update(&mut hasher, &argon2_keys.1);
    let hash = hasher.finalize();
    keys.1[..16].copy_from_slice(&hash[..16]);

    //hash 3rd 64 bytes with skein 256
    let mut hasher = Skein256::<U32>::new();
    SkeinDigest::update(&mut hasher, &argon2_keys.2);
    let hash = hasher.finalize();
    keys.2[..32].copy_from_slice(&hash[..32]);

    //hash 4th and 5th 64 bytes with whirpool
    let mut hasher = Whirlpool::new();
    WhirlpoolDigest::update(&mut hasher, &argon2_keys.3);
    let hash = hasher.finalize();
    keys.3[..64].copy_from_slice(&hash);
    let mut hasher = Whirlpool::new();
    WhirlpoolDigest::update(&mut hasher, &argon2_keys.4);
    let hash = hasher.finalize();
    keys.3[64..128].copy_from_slice(&hash);

    //hash 6th 48 bytes with ripemd 320
    let mut hasher = Ripemd320::new();
    RipemdDigest::update(&mut hasher, &argon2_keys.5);
    let hash = hasher.finalize();
    keys.4[0..32].copy_from_slice(&hash[..32]);

    //hash 7th 64 bytes with sm3
    let mut hasher = Sm3::new();
    Sm3Digest::update(&mut hasher, &argon2_keys.6);
    let hash = hasher.finalize();
    keys.5[..16].copy_from_slice(&hash[..16]);

    //hash 8th 64 bytes with streebog 256
    let mut hasher = Streebog256::new();
    StreebogDigest::update(&mut hasher, &argon2_keys.7);
    let hash = hasher.finalize();
    keys.6[..32].copy_from_slice(&hash[..32]);

    //hash 9th 64 bytes with fsb 256
    let mut hasher = Fsb256::new();
    FsbDigest::update(&mut hasher, &argon2_keys.8);
    let hash = hasher.finalize();
    keys.7[..16].copy_from_slice(&hash[..16]);

    //hash 10th 64 bytes with sha256
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, &argon2_keys.9);
    let hash = hasher.finalize();
    keys.8[..32].copy_from_slice(&hash[..32]);

    //hash 11th 64 bytes with jh
    let mut hasher = Jh256::new();
    JhDigest::update(&mut hasher, &argon2_keys.10);
    let hash = hasher.finalize();
    keys.9[..32].copy_from_slice(&hash[..32]);
    
    //hash 12th 64 bytes with sha3-256
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, &argon2_keys.11);
    let hash = hasher.finalize();
    keys.10[..32].copy_from_slice(&hash[..32]);

    //just copy the last key for MAC
    keys.11.copy_from_slice(&argon2_keys.12);

    keys
}