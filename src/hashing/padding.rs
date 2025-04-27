use std::{fs::File, io::{Read, Seek, Write}};

use sha3::{Shake256, digest::{ExtendableOutput, XofReader, Update}};

use crate::other::truncate_file::truncate_file;

pub const PADDING_LENGTH_INFORMATION_FIELD_SIZE: u64 = 1; //1 byte
pub const PADDING_IV_SIZE: usize = 8; //64 bit, 8 byte

pub fn pad_file(filename: &str) -> Result<(), std::io::Error> {
    let file_size = std::fs::metadata(filename)?.len();
    let padding_length = 128 - ((file_size + PADDING_LENGTH_INFORMATION_FIELD_SIZE) % 128);

    //iterate through file in 4096 byte chunks and update shake256 hash
    let mut shake = Shake256::default();
    let mut read_file = File::open(filename)?;
    let mut buffer = [0u8; 4096];
    let mut padding_bytes = vec![0u8; padding_length as usize];
    
    while let Ok(bytes_read) = read_file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        shake.update(&buffer[..bytes_read]);
    }
    //clear buffer
    buffer.fill(0);

    let mut reader = shake.finalize_xof();
    XofReader::read(&mut reader, &mut padding_bytes);

    //append padding_bytes to the end of the file
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(filename)?;
    file.write_all(&padding_bytes)?;
    //clear buffer
    padding_bytes.fill(0);

    //write single byte of padding length to the end of the file as the 4096th byte
    file.write_all(&[padding_length as u8])?;
    //clear padding_length //next line shouldnt be removed by compiler!
    //padding_length = 0;
    file.flush()?;
    drop(file);
    Ok(())
}

pub fn unpad_file(filename: &str) -> Result<(), std::io::Error> {
    //read last byte, count +1 and remove  padding_length from file (truncate)
    let mut file = File::open(filename)?;
    let file_size = file.metadata()?.len();
    if file_size > 0 {
        file.seek(std::io::SeekFrom::End(-(PADDING_LENGTH_INFORMATION_FIELD_SIZE as i64)))?;
        let mut last_byte = [0u8; 1];
        file.read_exact(&mut last_byte)?;
        let padding_length = last_byte[0] as u64;
        drop(file);

        truncate_file(filename, (padding_length + PADDING_LENGTH_INFORMATION_FIELD_SIZE) as usize)?;
    }

    Ok(())
}
