fn main() {
    if let Err(error) = rustvault::run() {
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }
}
