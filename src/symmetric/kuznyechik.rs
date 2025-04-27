use kuznyechik::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for Kuznyechik
pub struct KuznyechikCipher {
    enc_cipher: kuznyechik::KuznyechikEnc,
    dec_cipher: kuznyechik::KuznyechikDec,
}

impl BlockCipher for KuznyechikCipher {
    const BLOCK_SIZE: usize = 16;
    type Key = [u8; 32];
    
    fn new(key: &Self::Key) -> Self {
        let enc_cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize Kuznyechik encryption cipher");
        let dec_cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize Kuznyechik decryption cipher");
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
