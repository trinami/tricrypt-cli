use xtea::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, array::Array};
use crate::symmetric::cipher::BlockCipher;

// Implementation for XTEA
pub struct XteaCipher {
    cipher: xtea::Xtea,
}

impl BlockCipher for XteaCipher {
    const BLOCK_SIZE: usize = 8;
    type Key = [u8; 16];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = xtea::Xtea::new_from_slice(key)
            .expect("Failed to initialize XTEA cipher");
        Self { cipher }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_arr = [0u8; Self::BLOCK_SIZE];
        block_arr.copy_from_slice(block);
        
        let mut block_array = Array::from(block_arr);
        BlockCipherEncrypt::encrypt_block(&self.cipher, &mut block_array);
        
        block.copy_from_slice(&block_array);
    }
    
    fn decrypt_block(&self, block: &mut [u8]) {
        let mut block_arr = [0u8; Self::BLOCK_SIZE];
        block_arr.copy_from_slice(block);
        
        let mut block_array = Array::from(block_arr);
        BlockCipherDecrypt::decrypt_block(&self.cipher, &mut block_array);
        
        block.copy_from_slice(&block_array);
    }
}
