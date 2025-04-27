use sm4::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for SM4
pub struct Sm4Cipher {
    cipher: sm4::Sm4,
}

impl BlockCipher for Sm4Cipher {
    const BLOCK_SIZE: usize = 16;
    type Key = [u8; 16];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize SM4 cipher");
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
