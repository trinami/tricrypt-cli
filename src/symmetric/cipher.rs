pub trait BlockCipher {
    const BLOCK_SIZE: usize;
    type Key;
    
    fn new(key: &Self::Key) -> Self;
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);
}
