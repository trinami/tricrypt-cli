use sha2::{Sha512, Digest};
use blake2::Blake2b512;
use ripemd::Ripemd320;
use whirlpool::Whirlpool;
use tiger::Tiger2;
use blake3::Hasher as Blake3Hasher;

use jh::Jh512;
use skein::Skein256;
use streebog::Streebog512;
use sm3::Sm3;
use sha3::Sha3_512;
use shabal::Shabal512;
use fsb::Fsb512;
use ascon_hash::AsconHash256;
use generic_array::typenum::U32;

use argon2::{
    password_hash::{
        PasswordHasher, SaltString
    },
    Argon2, Algorithm
};

pub fn trihash(jh: &[u8], skein: &[u8], streebog: &[u8], sm3: &[u8], sha3: &[u8], shabal: &[u8], fsb: &[u8], ascon: &[u8]) -> [u8; 32] {
    // First level of Merkle Tree
    let mut sha2_hasher = Sha512::new();
    sha2_hasher.update(jh);
    sha2_hasher.update(skein);
    let sha2_result = sha2_hasher.finalize();

    let mut blake2_hasher = Blake2b512::new();
    blake2_hasher.update(streebog);
    blake2_hasher.update(sm3);
    let blake2_result = blake2_hasher.finalize();

    let mut ripemd_hasher = Ripemd320::new();
    ripemd_hasher.update(sha3);
    ripemd_hasher.update(shabal);
    let ripemd_result = ripemd_hasher.finalize();

    let mut whirlpool_hasher = Whirlpool::new();
    whirlpool_hasher.update(fsb);
    whirlpool_hasher.update(ascon);
    let whirlpool_result = whirlpool_hasher.finalize();

    // Second level of Merkle Tree
    let mut tiger_hasher = Tiger2::new();
    tiger_hasher.update(&sha2_result);
    tiger_hasher.update(&blake2_result);
    let tiger_result = tiger_hasher.finalize();

    let mut blake3_hasher = Blake3Hasher::new();
    blake3_hasher.update(&ripemd_result);
    blake3_hasher.update(&whirlpool_result);
    let blake3_result = blake3_hasher.finalize();
    let blake3_result_bytes: &[u8] = blake3_result.as_bytes();

    // Top of the Merkle Tree
    let params: argon2::Params = argon2::Params::new(
        1333 * 1000, // 1.333 GB RAM
        1 as u32, // 1 round
        1, // 1 thread
        Some(32) // 32 bytes output
    ).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::default(), params);
    let salt = SaltString::encode_b64(tiger_result.as_slice()).unwrap(); // no random salt, that argon2 doesn't get single point of failure
    let password_hash = argon2.hash_password(
        &[tiger_result.as_slice(), blake3_result_bytes].concat(),
        &salt
    ).unwrap();

    // Extract the hash bytes and convert to [u8; 32]
    let hash = password_hash.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash_bytes[..32]);

    return output;
}

pub fn trihash_array(array: &[&[u8]]) -> [u8; 32] {
    // First level of Merkle Tree
    let mut jh_hasher = Jh512::new();
    for data in array {
        jh_hasher.update(data);
    }
    let jh_result = jh_hasher.finalize();

    let mut skein_hasher = Skein256::<U32>::new();
    for data in array {
        skein_hasher.update(data);
    }
    let skein_result = skein_hasher.finalize();

    let mut streebog_hasher = Streebog512::new();
    for data in array {
        streebog_hasher.update(data);
    }
    let streebog_result = streebog_hasher.finalize();

    let mut sm3_hasher = Sm3::new();
    for data in array {
        sm3_hasher.update(data);
    }
    let sm3_result = sm3_hasher.finalize();

    let mut sha3_hasher = Sha3_512::new();
    for data in array {
        sha3_hasher.update(data);
    }
    let sha3_result = sha3_hasher.finalize();

    let mut shabal_hasher = Shabal512::new();
    for data in array {
        shabal_hasher.update(data);
    }
    let shabal_result = shabal_hasher.finalize();

    let mut fsb_hasher = Fsb512::new();
    for data in array {
        fsb_hasher.update(data);
    }
    let fsb_result = fsb_hasher.finalize();

    let mut ascon_hasher = AsconHash256::new();
    for data in array {
        ascon_hasher.update(data);
    }
    let ascon_result = ascon_hasher.finalize();

    // Second level of Merkle Tree
    let mut sha2_hasher = Sha512::new();
    sha2_hasher.update(jh_result);
    sha2_hasher.update(skein_result);
    let sha2_result = sha2_hasher.finalize();

    let mut blake2_hasher = Blake2b512::new();
    blake2_hasher.update(streebog_result);
    blake2_hasher.update(sm3_result);
    let blake2_result = blake2_hasher.finalize();

    let mut ripemd_hasher = Ripemd320::new();
    ripemd_hasher.update(sha3_result);
    ripemd_hasher.update(shabal_result);
    let ripemd_result = ripemd_hasher.finalize();

    let mut whirlpool_hasher = Whirlpool::new();
    whirlpool_hasher.update(fsb_result);
    whirlpool_hasher.update(ascon_result);
    let whirlpool_result = whirlpool_hasher.finalize();

    // Third level of Merkle Tree
    let mut tiger_hasher = Tiger2::new();
    tiger_hasher.update(&sha2_result);
    tiger_hasher.update(&blake2_result);
    let tiger_result = tiger_hasher.finalize();

    let mut blake3_hasher = Blake3Hasher::new();
    blake3_hasher.update(&ripemd_result);
    blake3_hasher.update(&whirlpool_result);
    let blake3_result = blake3_hasher.finalize();
    let blake3_result_bytes: &[u8] = blake3_result.as_bytes();

    // Top of the Merkle Tree
    let params: argon2::Params = argon2::Params::new(
        1333 * 1000, // 1.333 GB RAM
        1 as u32, // 1 round
        1, // 1 thread
        Some(32) // 32 bytes output
    ).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::default(), params);
    let salt = SaltString::encode_b64(tiger_result.as_slice()).unwrap(); // no random salt, that argon2 doesn't get single point of failure
    let password_hash = argon2.hash_password(
        &[tiger_result.as_slice(), blake3_result_bytes].concat(),
        &salt
    ).unwrap();

    // Extract the hash bytes and convert to [u8; 32]
    let hash = password_hash.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash_bytes[..32]);

    return output;
}
