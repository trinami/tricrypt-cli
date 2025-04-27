use std::io::{Read, Seek, Write};
use std::fs::OpenOptions;
use crate::symmetric::cipher::BlockCipher;

// Generic CBC encryption
pub fn cbc_encrypt_file_no_iv<C: BlockCipher>(filename: &str, key: &C::Key) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(filename)
        .expect("Failed to open file");

    let file_size = file.metadata().expect("Failed to read metadata").len();
    if file_size == 0 {
        return; // Nothing to encrypt
    }
    
    let cipher = C::new(key);
    
    // Buffer size for efficient I/O operations
    const BUFFER_SIZE: usize = 4096;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut position = 0;
    let mut last_block = vec![0u8; C::BLOCK_SIZE]; // Zero IV for first block
    
    while position < file_size {
        // Read file at current position
        file.seek(std::io::SeekFrom::Start(position))
            .expect("Failed to seek in file");
        
        let bytes_read = file.read(&mut buffer[..BUFFER_SIZE.min((file_size - position) as usize)])
            .expect("Failed to read from file");
        
        if bytes_read == 0 {
            break;
        }
        
        // Process only complete blocks
        let complete_blocks = bytes_read / C::BLOCK_SIZE;
        
        for i in 0..complete_blocks {
            let block_start = i * C::BLOCK_SIZE;
            let block_end = block_start + C::BLOCK_SIZE;
            
            // XOR with previous block (or IV for first block)
            let mut block = vec![0u8; C::BLOCK_SIZE];
            block.copy_from_slice(&buffer[block_start..block_end]);
            
            for j in 0..C::BLOCK_SIZE {
                block[j] ^= last_block[j];
            }
            
            // Encrypt block
            cipher.encrypt_block(&mut block);
            
            // Write encrypted block back to buffer
            buffer[block_start..block_end].copy_from_slice(&block);
            
            // Save this encrypted block for next iteration
            last_block = block;
        }
        
        // Write encrypted data back to file
        file.seek(std::io::SeekFrom::Start(position))
            .expect("Failed to seek in file for writing");
        file.write_all(&buffer[..bytes_read])
            .expect("Failed to write to file");
        
        position += bytes_read as u64;
    }
    
    file.flush().expect("Failed to flush file");
}

// Generic CBC decryption
pub fn cbc_decrypt_file_no_iv<C: BlockCipher>(filename: &str, key: &C::Key) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(filename)
        .expect("Failed to open file");
    
    let file_size = file.metadata().expect("Failed to read metadata").len();
    if file_size == 0 || file_size % C::BLOCK_SIZE as u64 != 0 {
        panic!("Invalid file size for CBC decryption");
    }
    
    let cipher = C::new(key);
    
    // Process in blocks from end to beginning
    const BUFFER_SIZE: usize = 4096;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut position = file_size;
    
    while position > 0 {
        // How many bytes to read in this iteration
        let chunk_size = std::cmp::min(position as usize, BUFFER_SIZE);
        position -= chunk_size as u64;
        
        // Read this chunk
        file.seek(std::io::SeekFrom::Start(position))
            .expect("Failed to seek in file");
        file.read_exact(&mut buffer[..chunk_size])
            .expect("Failed to read from file");
        
        // Process only complete blocks
        let complete_blocks = chunk_size / C::BLOCK_SIZE;
        
        // We need the previous block for XOR operation
        let mut prev_encrypted_block = vec![0u8; C::BLOCK_SIZE];
        
        // If this is not the beginning of the file, read the previous block
        if position > 0 {
            file.seek(std::io::SeekFrom::Start(position - C::BLOCK_SIZE as u64))
                .expect("Failed to seek in file");
            file.read_exact(&mut prev_encrypted_block)
                .expect("Failed to read from file");
            file.seek(std::io::SeekFrom::Start(position))
                .expect("Failed to seek in file");
        }
        
        // Process blocks from end to beginning
        for i in (0..complete_blocks).rev() {
            let block_start = i * C::BLOCK_SIZE;
            let block_end = block_start + C::BLOCK_SIZE;
            
            // Save current encrypted block
            let mut current_encrypted_block = vec![0u8; C::BLOCK_SIZE];
            current_encrypted_block.copy_from_slice(&buffer[block_start..block_end]);
            
            // Decrypt block
            let mut decrypted_block = current_encrypted_block.clone();
            cipher.decrypt_block(&mut decrypted_block);
            
            // XOR with previous encrypted block (or zero IV for first block)
            let xor_block = if i > 0 {
                let prev_block_start = (i - 1) * C::BLOCK_SIZE;
                &buffer[prev_block_start..prev_block_start + C::BLOCK_SIZE]
            } else if position > 0 {
                &prev_encrypted_block
            } else {
                &vec![0u8; C::BLOCK_SIZE] // Zero IV for first block
            };
            
            for j in 0..C::BLOCK_SIZE {
                decrypted_block[j] ^= xor_block[j];
            }
            
            // Write decrypted block back to buffer
            buffer[block_start..block_end].copy_from_slice(&decrypted_block);
        }
        
        // Write decrypted data back to file
        file.seek(std::io::SeekFrom::Start(position))
            .expect("Failed to seek in file for writing");
        file.write_all(&buffer[..chunk_size])
            .expect("Failed to write to file");
    }
    
    file.flush().expect("Failed to flush file");
    drop(file);
}