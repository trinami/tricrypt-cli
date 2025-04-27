use gift_cipher::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, array::Array as GiftArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for GIFT
pub struct GiftCipher {
    cipher: gift_cipher::Gift128,
}

impl BlockCipher for GiftCipher {
    const BLOCK_SIZE: usize = 16;
    type Key = [u8; 16];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = gift_cipher::cipher::KeyInit::new_from_slice(key)
            .expect("Failed to initialize GIFT cipher");
        Self { cipher }
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_arr = [0u8; Self::BLOCK_SIZE];
        block_arr.copy_from_slice(block);
        
        let mut block_array = GiftArray::from(block_arr);
        BlockCipherEncrypt::encrypt_block(&self.cipher, &mut block_array);
        
        block.copy_from_slice(&block_array);
    }
    
    fn decrypt_block(&self, block: &mut [u8]) {
        let mut block_arr = [0u8; Self::BLOCK_SIZE];
        block_arr.copy_from_slice(block);
        
        let mut block_array = GiftArray::from(block_arr);
        BlockCipherDecrypt::decrypt_block(&self.cipher, &mut block_array);
        
        block.copy_from_slice(&block_array);
    }
}
