mod gui;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    aes::cipher::InvalidLength,
    Aes256Gcm, Nonce,
};
use argon2::{
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const DEFAULT_VAULT_NAME: &str = "rustvault.json";

#[derive(Parser, Debug)]
pub struct Cli {
    #[arg(long, global = true, help = "Render command output as JSON")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Init {
        #[arg(long, help = "Master password used to encrypt the vault")]
        master_password: String,
    },
    Add(AddArgs),
    List(ListArgs),
    Get(GetArgs),
    Edit(EditArgs),
    Delete(DeleteArgs),
    Generate(GenerateArgs),
    Export(ExportArgs),
    Import(ImportArgs),
    Gui,
    Tui,
    Totp,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    #[arg(long, help = "Master password used to unlock the vault")]
    pub master_password: String,
    #[arg(long, help = "Entry name")]
    pub name: String,
    #[arg(long, help = "Username or email")]
    pub username: String,
    #[arg(long, help = "Password value; if omitted, a secure one is generated")]
    pub password: Option<String>,
    #[arg(long, help = "Website or URL")]
    pub url: Option<String>,
    #[arg(long, help = "Free-form notes")]
    pub notes: Option<String>,
    #[arg(long, value_delimiter = ',', help = "Comma-separated tags")]
    pub tags: Vec<String>,
    #[arg(long, default_value_t = 20, help = "Password length when auto-generating")]
    pub length: usize,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long, help = "Master password used to unlock the vault")]
    pub master_password: String,
    #[arg(long, help = "Filter by tag")]
    pub tag: Option<String>,
    #[arg(long, help = "Substring match against the entry name")]
    pub query: Option<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    #[arg(long, help = "Master password used to unlock the vault")]
    pub master_password: String,
    #[arg(help = "Name of the entry to fetch")]
    pub name: String,
    #[arg(long, help = "Include the secret password in the response")]
    pub show_password: bool,
}

#[derive(Args, Debug)]
pub struct EditArgs {
    #[arg(long, help = "Master password used to unlock the vault")]
    pub master_password: String,
    #[arg(help = "Name of the existing entry")]
    pub name: String,
    #[arg(long, help = "Updated username or email")]
    pub username: Option<String>,
    #[arg(long, help = "Updated password value")]
    pub password: Option<String>,
    #[arg(long, help = "Updated URL")]
    pub url: Option<String>,
    #[arg(long, help = "Updated notes")]
    pub notes: Option<String>,
    #[arg(long, value_delimiter = ',', help = "Updated comma-separated tags")]
    pub tags: Vec<String>,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[arg(long, help = "Master password used to unlock the vault")]
    pub master_password: String,
    #[arg(help = "Name of the entry to remove")]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct GenerateArgs {
    #[arg(long, default_value_t = 24, help = "Length of generated password")]
    pub length: usize,
    #[arg(long, help = "Include symbols in the generated password")]
    pub symbols: bool,
    #[arg(long, help = "Exclude digits from the generated password")]
    pub no_numbers: bool,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    #[arg(value_enum, help = "Output format")]
    pub format: ExportFormat,
    #[arg(long, help = "Master password used to decrypt the vault")]
    pub master_password: String,
    #[arg(long, help = "Write exported data to this file; defaults to stdout")]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    #[arg(value_enum, help = "Input format")]
    pub format: ImportFormat,
    #[arg(long, help = "Master password used to encrypt the vault")]
    pub master_password: String,
    #[arg(help = "Path to the file to import")]
    pub input: PathBuf,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ExportFormat {
    Json,
    Csv,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ImportFormat {
    Json,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub entries: Vec<VaultEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredVault {
    pub version: u64,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug)]
pub struct AppError(pub String);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<aes_gcm::Error> for AppError {
    fn from(value: aes_gcm::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<InvalidLength> for AppError {
    fn from(value: InvalidLength) -> Self {
        Self(value.to_string())
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(value: base64::DecodeError) -> Self {
        Self(value.to_string())
    }
}

/// Runs the application entry point and dispatches to either the GUI or the selected CLI command.
pub fn run() -> Result<(), AppError> {
    if std::env::args_os().len() <= 1 {
        return gui::run_gui();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { master_password } => {
            init_vault(&master_password, cli.json)?;
        }
        Commands::Add(args) => {
            add_entry(args, cli.json)?;
        }
        Commands::List(args) => {
            list_entries(args, cli.json)?;
        }
        Commands::Get(args) => {
            get_entry(args, cli.json)?;
        }
        Commands::Edit(args) => {
            edit_entry(args, cli.json)?;
        }
        Commands::Delete(args) => {
            delete_entry(args, cli.json)?;
        }
        Commands::Generate(args) => {
            let password = generate_password(args.length, args.symbols, args.no_numbers);
            print_json(&serde_json::json!({ "password": password }), cli.json)?;
        }
        Commands::Export(args) => {
            export_vault(args, cli.json)?;
        }
        Commands::Import(args) => {
            import_vault(args, cli.json)?;
        }
        Commands::Gui => {
            gui::run_gui()?;
        }
        Commands::Tui => {
            println!("TUI mode is planned for a future release. Use the CLI commands to manage your vault.");
        }
        Commands::Totp => {
            println!("TOTP support is planned for a future release.");
        }
    }

    Ok(())
}

/// Formats a serializable value as pretty JSON to stdout for CLI consumers.
fn print_json<T: Serialize>(value: &T, json: bool) -> Result<(), AppError> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

/// Creates a new encrypted vault file using the supplied master password.
pub fn init_vault(master_password: &str, json: bool) -> Result<(), AppError> {
    let path = vault_path();
    if path.exists() {
        return Err(AppError(format!("Vault already exists at {}", path.display())));
    }

    let vault = VaultData::default();
    save_vault(&vault, master_password)?;

    let payload = serde_json::json!({ "message": "Vault initialized", "path": path.display().to_string() });
    print_json(&payload, json)?;
    Ok(())
}

/// Adds a new entry to the vault after validating uniqueness and encrypting the updated vault.
pub fn add_entry(args: AddArgs, json: bool) -> Result<(), AppError> {
    let mut vault = load_vault(&args.master_password)?;
    if vault.entries.iter().any(|entry| entry.name == args.name) {
        return Err(AppError(format!("Entry '{}' already exists", args.name)));
    }

    let password = args.password.unwrap_or_else(|| generate_password(args.length, true, false));
    let timestamp = current_timestamp();
    let entry = VaultEntry {
        id: uuid::Uuid::new_v4().to_string(),
        name: args.name,
        username: args.username,
        password,
        url: args.url.unwrap_or_default(),
        notes: args.notes.unwrap_or_default(),
        tags: normalize_tags(args.tags),
        created_at: timestamp.clone(),
        updated_at: timestamp,
    };

    vault.entries.push(entry.clone());
    save_vault(&vault, &args.master_password)?;

    print_json(&serde_json::json!({ "message": "Entry added", "entry": entry }), json)?;
    Ok(())
}

/// Lists vault entries, optionally filtered by tag or a text search query.
pub fn list_entries(args: ListArgs, json: bool) -> Result<(), AppError> {
    let vault = load_vault(&args.master_password)?;
    let filtered = filter_entries(vault.entries, args.tag.as_deref(), args.query.as_deref());

    if json {
        print_json(&filtered, true)?;
    } else {
        if filtered.is_empty() {
            println!("No entries found");
        } else {
            for entry in filtered {
                println!("{} | {} | {} | tags: {}", entry.name, entry.username, entry.url, entry.tags.join(", "));
            }
        }
    }
    Ok(())
}

/// Fetches a single vault entry by name and optionally includes the secret password in the output.
pub fn get_entry(args: GetArgs, json: bool) -> Result<(), AppError> {
    let vault = load_vault(&args.master_password)?;
    let entry = vault
        .entries
        .into_iter()
        .find(|item| item.name == args.name)
        .ok_or_else(|| AppError(format!("Entry '{}' not found", args.name)))?;

    if args.show_password {
        print_json(&entry, json)?;
    } else {
        let payload = serde_json::json!({
            "name": entry.name,
            "username": entry.username,
            "url": entry.url,
            "notes": entry.notes,
            "tags": entry.tags,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        });
        print_json(&payload, json)?;
    }
    Ok(())
}

/// Updates an existing vault entry with any provided fields and saves the encrypted vault again.
pub fn edit_entry(args: EditArgs, json: bool) -> Result<(), AppError> {
    let mut vault = load_vault(&args.master_password)?;
    let index = vault
        .entries
        .iter()
        .position(|item| item.name == args.name)
        .ok_or_else(|| AppError(format!("Entry '{}' was not found", args.name)))?;

    let mut entry = vault.entries.remove(index);
    if let Some(username) = args.username {
        entry.username = username;
    }
    if let Some(password) = args.password {
        entry.password = password;
    }
    if let Some(url) = args.url {
        entry.url = url;
    }
    if let Some(notes) = args.notes {
        entry.notes = notes;
    }
    if !args.tags.is_empty() {
        entry.tags = normalize_tags(args.tags);
    }
    entry.updated_at = current_timestamp();
    vault.entries.push(entry.clone());
    save_vault(&vault, &args.master_password)?;

    print_json(&serde_json::json!({ "message": "Entry updated", "entry": entry }), json)?;
    Ok(())
}

/// Removes the named entry from the vault if it exists and persists the updated encrypted data.
pub fn delete_entry(args: DeleteArgs, json: bool) -> Result<(), AppError> {
    let mut vault = load_vault(&args.master_password)?;
    let before = vault.entries.len();
    vault.entries.retain(|item| item.name != args.name);
    if vault.entries.len() == before {
        return Err(AppError(format!("Entry '{}' not found", args.name)));
    }

    save_vault(&vault, &args.master_password)?;
    print_json(&serde_json::json!({ "message": "Entry deleted", "name": args.name }), json)?;
    Ok(())
}

/// Exports the currently unlocked vault as JSON or CSV to stdout or a destination file.
pub fn export_vault(args: ExportArgs, json: bool) -> Result<(), AppError> {
    let vault = load_vault(&args.master_password)?;
    let payload = match args.format {
        ExportFormat::Json => serde_json::to_string_pretty(&vault)?,
        ExportFormat::Csv => export_csv(&vault),
    };

    if let Some(output) = args.output {
        fs::write(output, payload)?;
        print_json(&serde_json::json!({ "message": "Export complete" }), json)?;
    } else if json {
        print_json(&serde_json::json!({ "data": payload }), true)?;
    } else {
        println!("{}", payload);
    }
    Ok(())
}

/// Imports entries from a JSON or CSV file into the active vault without duplicating name collisions.
pub fn import_vault(args: ImportArgs, json: bool) -> Result<(), AppError> {
    let mut vault = load_vault(&args.master_password)?;
    let imported = match args.format {
        ImportFormat::Json => import_json_file(args.input)?,
        ImportFormat::Csv => import_csv_file(args.input)?,
    };

    for entry in imported {
        if !vault.entries.iter().any(|item| item.name == entry.name) {
            vault.entries.push(entry);
        }
    }

    save_vault(&vault, &args.master_password)?;
    print_json(&serde_json::json!({ "message": "Import complete", "count": vault.entries.len() }), json)?;
    Ok(())
}

/// Loads the encrypted vault from disk and decrypts it with the provided master password.
fn load_vault(master_password: &str) -> Result<VaultData, AppError> {
    let path = vault_path();
    if !path.exists() {
        return Err(AppError(format!("Vault does not exist at {}", path.display())));
    }

    let stored: StoredVault = serde_json::from_slice(&fs::read(path)?)?;
    let key = derive_key(master_password, &base64_decode(&stored.salt)?);
    let nonce_bytes = parse_nonce(&stored.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(AppError::from)?;
    let ciphertext = base64_decode(&stored.ciphertext)?;
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    let vault: VaultData = serde_json::from_slice(&plaintext)?;
    Ok(vault)
}

/// Saves the in-memory vault to disk by encrypting it with a fresh random salt and nonce.
fn save_vault(vault: &VaultData, master_password: &str) -> Result<(), AppError> {
    let dir = vault_dir();
    fs::create_dir_all(&dir)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let key = derive_key(master_password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(AppError::from)?;
    let plaintext = serde_json::to_vec(vault)?;
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

    let stored = StoredVault {
        version: 1,
        salt: BASE64.encode(&salt),
        nonce: BASE64.encode(nonce.as_slice()),
        ciphertext: BASE64.encode(ciphertext),
    };

    fs::write(vault_path(), serde_json::to_string_pretty(&stored)?)?;
    Ok(())
}

/// Derives an AES key from the master password and random salt using the Argon2id KDF.
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(65536, 3, 1, Some(32)).expect("valid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}

/// Decodes a Base64 nonce payload and validates it is the expected AES-GCM length.
fn parse_nonce(value: &str) -> Result<[u8; 12], AppError> {
    let bytes = base64_decode(value)?;
    if bytes.len() != 12 {
        return Err(AppError("Invalid nonce length".to_string()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Decodes a Base64-encoded byte string from the encrypted vault format.
fn base64_decode(value: &str) -> Result<Vec<u8>, AppError> {
    Ok(BASE64.decode(value)?)
}

/// Returns the current Unix timestamp as a string for entry created/updated metadata.
fn current_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

/// Trims, sorts, and deduplicates tags so stored metadata remains consistent.
fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut normalized = tags
        .into_iter()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

/// Filters the vault entries by optional tag and text query parameters.
fn filter_entries(entries: Vec<VaultEntry>, tag: Option<&str>, query: Option<&str>) -> Vec<VaultEntry> {
    entries
        .into_iter()
        .filter(|entry| {
            if let Some(tag_value) = tag {
                if !entry.tags.iter().any(|entry_tag| entry_tag.eq_ignore_ascii_case(tag_value)) {
                    return false;
                }
            }
            if let Some(pattern) = query {
                let haystack = format!(
                    "{} {} {} {}",
                    entry.name, entry.username, entry.url, entry.notes
                )
                .to_ascii_lowercase();
                if !haystack.contains(&pattern.to_ascii_lowercase()) {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Converts the vault to CSV format with a header row and escaped values for safe export.
fn export_csv(vault: &VaultData) -> String {
    let mut rows = Vec::new();
    rows.push("name,username,password,url,notes,tags".to_string());
    for entry in &vault.entries {
        rows.push(format!(
            "{},{},{},{},{},{}",
            csv_field(&entry.name),
            csv_field(&entry.username),
            csv_field(&entry.password),
            csv_field(&entry.url),
            csv_field(&entry.notes),
            csv_field(&entry.tags.join("|"))
        ));
    }
    rows.join("\n")
}

/// Escapes CSV special characters so exported values remain parseable by spreadsheet tools.
fn csv_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    if escaped.contains(',') || escaped.contains('"') || escaped.contains('\n') {
        format!("\"{}\"", escaped)
    } else {
        escaped
    }
}

/// Imports the entries from a JSON export file and returns them as a plain Vec.
fn import_json_file(path: PathBuf) -> Result<Vec<VaultEntry>, AppError> {
    let data: VaultData = serde_json::from_slice(&fs::read(path)?)?;
    Ok(data.entries)
}

/// Imports entries from a CSV file, preserving names, credentials, and tags for merge-in operations.
fn import_csv_file(path: PathBuf) -> Result<Vec<VaultEntry>, AppError> {
    let content = fs::read_to_string(path)?;
    let mut lines = content.lines();
    let _header = lines.next();
    let mut entries = Vec::new();

    for line in lines {
        let cells: Vec<&str> = line.split(',').collect();
        if cells.len() < 6 {
            continue;
        }
        let tags = if cells[5].trim().is_empty() {
            Vec::new()
        } else {
            cells[5].split('|').map(str::to_string).collect()
        };
        entries.push(VaultEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: cells[0].trim().to_string(),
            username: cells[1].trim().to_string(),
            password: cells[2].trim().to_string(),
            url: cells[3].trim().to_string(),
            notes: cells[4].trim().to_string(),
            tags,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        });
    }

    Ok(entries)
}

/// Generates a secure random password using a configurable pool of letters, digits, and symbols.
pub fn generate_password(length: usize, include_symbols: bool, no_numbers: bool) -> String {
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const NUMBERS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{};:,.<>?/";

    let mut pool = Vec::new();
    pool.extend_from_slice(LOWERCASE);
    pool.extend_from_slice(UPPERCASE);
    if !no_numbers {
        pool.extend_from_slice(NUMBERS);
    }
    if include_symbols {
        pool.extend_from_slice(SYMBOLS);
    }

    let mut rng = rand::thread_rng();
    let len = if length == 0 { 1 } else { length };
    let mut result = String::with_capacity(len);
    for _ in 0..len {
        let index = rng.gen_range(0..pool.len());
        result.push(pool[index] as char);
    }
    result
}

/// Resolves the directory that stores the vault file in the user profile for the current platform.
fn vault_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string())
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    };
    Path::new(&base).join(".vault")
}

/// Returns the full path to the encrypted vault file inside the platform-specific vault directory.
fn vault_path() -> PathBuf {
    vault_dir().join(DEFAULT_VAULT_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_generation_respects_length() {
        let password = generate_password(16, true, false);
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn round_trip_vault_serialization() {
        let vault = VaultData {
            entries: vec![VaultEntry {
                id: "demo".to_string(),
                name: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: "https://github.com".to_string(),
                notes: "Primary account".to_string(),
                tags: vec!["work".to_string(), "dev".to_string()],
                created_at: "1".to_string(),
                updated_at: "1".to_string(),
            }],
        };

        let serialized = serde_json::to_vec(&vault).unwrap();
        let decoded: VaultData = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].name, "GitHub");
    }
}
