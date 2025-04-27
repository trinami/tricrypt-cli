use magma::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for Magma
pub struct MagmaCipher {
    cipher: magma::Magma,
}

impl BlockCipher for MagmaCipher {
    const BLOCK_SIZE: usize = 8;
    type Key = [u8; 32];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize Magma cipher");
        Self { cipher }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockEncrypt::encrypt_block(&self.cipher, &mut block_array);
    }
    
    fn decrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockDecrypt::decrypt_block(&self.cipher, &mut block_array);
    }
}
