pub fn overwrite_file(filename: &str) -> bool {
    if std::path::Path::new(filename).exists() {
        //want to delete the file and all its contents? ask user for confirmation (file with output filname already exists)
        println!("File with name {} already exists. Do you want to delete it and all its contents? (y/n)", filename);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim() == "y" {
            std::fs::remove_file(filename).unwrap();

            return true;
        }
        else {
            println!("Cancelled encryption.");

            return false;
        }
    }

    return true;
}
 