use std::fs::OpenOptions;
use std::io::{Write, Seek};

pub fn append_file(filename: &str, data: &[u8]) -> Result<(), std::io::Error> {
    match OpenOptions::new()
        .write(true)
        .open(filename)
    {
        Ok(mut file) => {
            if let Err(e) = file.seek(std::io::SeekFrom::End(0)) {
                eprintln!("Error seeking file {}: {}", filename, e);
                return Err(e);
            }
            
            if let Err(e) = file.write_all(data) {
                eprintln!("Error writing to file {}: {}", filename, e);
                return Err(e);
            }
            
            if let Err(e) = file.flush() {
                eprintln!("Error flushing file {}: {}", filename, e);
                return Err(e);
            }

            drop(file);
            
            Ok(())
        },
        Err(e) => {
            eprintln!("Error opening file {}: {}", filename, e);
            Err(e)
        }
    }
}
