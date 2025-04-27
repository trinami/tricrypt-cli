use std::{fs::OpenOptions, io::{Read, Seek, SeekFrom, Write}};

pub fn truncate_file(filename: &str, length: usize) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(filename)?;

    let file_length = file.metadata()?.len();

    file.set_len(file_length - length as u64)?;
    file.flush()?;
    drop(file);
    
    Ok(())
}

//return the truncated bytes
pub fn truncate_file_with_return(filename: &str, length: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .open(filename)?;

    let file_length = file.metadata()?.len();

    file.seek(SeekFrom::Start(file_length - length as u64))?;

    let mut truncated_bytes = Vec::new();
    file.read_to_end(&mut truncated_bytes)?;

    file.set_len(file_length - length as u64)?;
    file.flush()?;
    drop(file);

    Ok(truncated_bytes)
}
