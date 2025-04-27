use std::io::{Read, Seek, Write};

use cipher::KeyIvInit;
use chacha20::ChaCha20Legacy;
use cipher::generic_array::{GenericArray, typenum::{U32, U8}};
use cipher::StreamCipher;

pub fn chacha20_xor(filename: &str, password: GenericArray<u8, U32>, iv: GenericArray<u8, U8>) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(filename)
        .expect(&format!("Failed to open file: {}", filename));

    let mut cipher = ChaCha20Legacy::new(&password, &iv);

    //read output file in 4096 byte chunks and update cipher, and update file
    let mut buffer = [0u8; 4096];
    let mut position = 0;
    while let Ok(bytes_read) = file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        cipher.apply_keystream(&mut buffer[..bytes_read]);
        file.seek(std::io::SeekFrom::Start(position))
            .expect(&format!("Failed to seek in file: {}", filename));
        file.write_all(&buffer[..bytes_read])
            .expect(&format!("Failed to write to file: {}", filename));
        position += bytes_read as u64;
        file.seek(std::io::SeekFrom::Start(position))
            .expect(&format!("Failed to seek in file: {}", filename));
    }
    file.flush()
        .expect(&format!("Failed to flush file: {}", filename));

    drop(file);
}
