use ripemd::Ripemd128;
use sha3::{Sha3_512, Digest as Sha3Digest};

use super::extract_keys::master_key_round;

pub struct XRNG {
    pool: [u8; 64],
    ready: bool,
    bytes_added: usize,
}

impl XRNG {
    pub fn new() -> Self {
        Self {
            pool: [0u8; 64],
            ready: false,
            bytes_added: 0,
        }
    }

    pub fn start(&mut self, random_byte: u8) -> bool {
        if self.ready {
            return true;
        }

        self.pool[self.bytes_added%64] ^= random_byte;
        self.bytes_added += 1;

        if self.bytes_added >= 128 {
            let mut hasher = Sha3_512::new();
            
            hasher.update(&self.pool);
            let hash = hasher.finalize();
            self.pool = hash.try_into().unwrap();
            self.ready = true;

            return true;
        }

        false
    }

    pub fn get_random16bytes(&mut self) -> Result<[u8; 16], &'static str> {
        if !self.ready {
            return Err("Entropy pool not ready");
        }

        self.pool = master_key_round(&self.pool, &self.pool);

        let mut hasher = Ripemd128::new();
        hasher.update(&self.pool);
        
        let result: [u8; 16] = hasher.finalize().as_slice().try_into().map_err(|_| "Conversion error")?;
        Ok(result)
    }
}
