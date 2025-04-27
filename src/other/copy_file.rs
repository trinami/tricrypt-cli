use std::fs::File;
use std::io;

pub fn copy_file(source: &str, destination: &str) -> Result<(), std::io::Error> {
    let mut source_file = File::open(source)?;
    let mut destination_file = File::create(destination)?;

    io::copy(&mut source_file, &mut destination_file)?;
    drop(source_file);
    drop(destination_file);
    
    Ok(())
}
