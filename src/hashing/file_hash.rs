use ripemd::Ripemd320;
use skein::Skein256;
use whirlpool::Whirlpool;
use tiger::Tiger2;
use sm3::Sm3;
use streebog::Streebog512;
use fsb::Fsb512;
use sha2::{Sha512, Digest};
use jh::Jh512;
use sha3::Sha3_512;
use blake2::Blake2b512;
use shabal::Shabal512;
use ascon_hash::AsconHash256;

use generic_array::GenericArray;
use generic_array::typenum::U32;
use std::fs::File;
use std::io::{BufReader, Read};
use serde_json::json;

use crate::hashing;

pub fn hash_file(file_path: &str, hashes: &str) -> serde_json::Value {
    let file = File::open(file_path).expect("Failed to open input file");
    let mut reader = BufReader::new(file);
    let mut buffer = [0; 4096];

    let mut sha2_512 = if hashes.contains("sha2_512") || hashes.contains("trihash") || hashes == "all" {
        Some(Sha512::new())
    } else {
        None
    };

    let mut sha3_512 = if hashes.contains("sha3_512") || hashes.contains("trihash") || hashes == "all" {
        Some(Sha3_512::new())
    } else {
        None
    };

    let mut ripemd320 = if hashes.contains("ripemd320") || hashes.contains("trihash") || hashes == "all" {
        Some(Ripemd320::new())
    } else {
        None
    };

    let mut tiger2 = if hashes.contains("tiger2") || hashes.contains("trihash") || hashes == "all" {
        Some(Tiger2::new())
    } else {
        None
    };

    let mut whirlpool = if hashes.contains("whirlpool") || hashes.contains("trihash") || hashes == "all" {
        Some(Whirlpool::new())
    } else {
        None
    };

    let mut blake2b512 = if hashes.contains("blake2b512") || hashes.contains("trihash") || hashes == "all" {
        Some(Blake2b512::new())
    } else {
        None
    };

    let mut blake3 = if hashes.contains("blake3") || hashes.contains("trihash") || hashes == "all" {
        Some(blake3::Hasher::new())
    } else {
        None
    };

    let mut streebog512 = if hashes.contains("streebog512") || hashes.contains("trihash") || hashes == "all" {
        Some(Streebog512::new())
    } else {
        None
    };

    let mut jh512 = if hashes.contains("jh512") || hashes.contains("trihash") || hashes == "all" {
        Some(Jh512::new())
    } else {
        None
    };

    let mut fsb512 = if hashes.contains("fsb512") || hashes.contains("trihash") || hashes == "all" {
        Some(Fsb512::new())
    } else {
        None
    };

    let mut sm3 = if hashes.contains("sm3") || hashes.contains("trihash") || hashes == "all" {
        Some(Sm3::new())
    } else {
        None
    };

    let mut skein256 = if hashes.contains("skein256") || hashes.contains("trihash") || hashes == "all" {
        Some(Skein256::<U32>::new())
    } else {
        None
    };

    let mut shabal512 = if hashes.contains("shabal512") || hashes.contains("trihash") || hashes == "all" {
        Some(Shabal512::new())
    } else {
        None
    };

    let mut ascon = if hashes.contains("ascon") || hashes.contains("trihash") || hashes == "all" {
        Some(AsconHash256::new())
    } else {
        None
    };

    let mut jh_output = None;
    let mut skein_output = None;
    let mut streebog_output = None;
    let mut sm3_output = None;
    let mut sha3_output = None;
    let mut fsb_output = None;
    let mut shabal_output = None;
    let mut ascon_output = None;

    while let Ok(bytes_read) = reader.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        let chunk = &buffer[..bytes_read];

        if let Some(ref mut hasher) = sha2_512 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = sha3_512 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = ripemd320 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = tiger2 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = whirlpool {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = blake2b512 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = blake3 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = streebog512 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = jh512 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = fsb512 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = sm3 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = skein256 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = shabal512 {
            hasher.update(chunk);
        }
        if let Some(ref mut hasher) = ascon {
            hasher.update(chunk);
        }
    }

    drop(reader);

    let mut results = json!({});

    if let Some(hasher) = sha2_512 {
        let hash = hasher.finalize();
        results["SHA2-512"] = json!(format!("{:x}", hash));
    }
    if let Some(hasher) = sha3_512 {
        let hash = hasher.finalize();
        results["SHA3-512"] = json!(format!("{:x}", hash));
        sha3_output = Some(hash);
    }
    if let Some(hasher) = ripemd320 {
        let hash = hasher.finalize();
        results["RIPEMD-320"] = json!(format!("{:x}", hash));
    }
    if let Some(hasher) = tiger2 {
        let hash = hasher.finalize();
        results["Tiger2"] = json!(format!("{:x}", hash));
    }
    if let Some(hasher) = whirlpool {
        let hash = hasher.finalize();
        results["Whirlpool"] = json!(format!("{:x}", hash));
    }
    if let Some(hasher) = blake2b512 {
        let hash = hasher.finalize();
        results["Blake2b512"] = json!(format!("{:x}", hash));
    }
    if let Some(hasher) = blake3 {
        let hash = hasher.finalize();
        let hash_bytes: &GenericArray<u8, _> = hash.as_bytes().into();
        results["Blake3"] = json!(format!("{:x}", hash_bytes));
    }
    if let Some(hasher) = streebog512 {
        let hash = hasher.finalize();
        results["Streebog512"] = json!(format!("{:x}", hash));
        streebog_output = Some(hash);
    }
    if let Some(hasher) = jh512 {
        let hash = hasher.finalize();
        results["Jh512"] = json!(format!("{:x}", hash));
        jh_output = Some(hash);
    }
    if let Some(hasher) = fsb512 {
        let hash = hasher.finalize();
        results["FSB-512"] = json!(format!("{:x}", hash));
        fsb_output = Some(hash);
    }
    if let Some(hasher) = sm3 {
        let hash = hasher.finalize();
        results["SM3"] = json!(format!("{:x}", hash));
        sm3_output = Some(hash);
    }
    if let Some(hasher) = skein256 {
        let hash = hasher.finalize();
        results["Skein-256"] = json!(format!("{:x}", hash));
        skein_output = Some(hash);
    }
    if let Some(hasher) = shabal512 {
        let hash = hasher.finalize();
        results["Shabal-512"] = json!(format!("{:x}", hash));
        shabal_output = Some(hash);
    }
    if let Some(hasher) = ascon {
        let hash = hasher.finalize();
        results["Ascon"] = json!(format!("{:x}", hash));
        ascon_output = Some(hash);
    }

    if hashes.contains("trihash") || hashes == "all" {
        if let (Some(jh), Some(skein), Some(streebog), Some(sm3), 
                Some(sha3), Some(fsb), Some(shabal), Some(ascon)) =
            (&jh_output, &skein_output, &streebog_output, &sm3_output, 
             &sha3_output, &fsb_output, &shabal_output, &ascon_output) {
            
            let trihash_result = hashing::trihash::trihash(
                jh.as_ref(),
                skein.as_ref(),
                streebog.as_ref(),
                sm3.as_ref(),
                sha3.as_ref(),
                shabal.as_ref(),
                fsb.as_ref(),
                ascon.as_ref()
            );
            let trihash_result_array: GenericArray<u8, _> = GenericArray::from(trihash_result);
            results["Trihash"] = json!(format!("{:x}", trihash_result_array));
        }
    }

    return results;
}