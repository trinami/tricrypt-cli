use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for AES256
pub struct Aes256Cipher {
    enc_cipher: aes::Aes256Enc,
    dec_cipher: aes::Aes256Dec,
}

impl BlockCipher for Aes256Cipher {
    const BLOCK_SIZE: usize = 16;
    type Key = [u8; 32];
    
    fn new(key: &Self::Key) -> Self {
        let enc_cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize AES256 encryption cipher");
        let dec_cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize AES256 decryption cipher");
        Self { enc_cipher, dec_cipher }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockEncrypt::encrypt_block(&self.enc_cipher, &mut block_array);
    }
    
    fn decrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockDecrypt::decrypt_block(&self.dec_cipher, &mut block_array);
    }
}
