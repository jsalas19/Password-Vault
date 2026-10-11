# RustVault

RustVault is a local password vault written in Rust. It provides a desktop GUI and a command-line interface for storing, searching, importing, and exporting account entries.

## Features

- Create and unlock a local encrypted vault
- Add, edit, list, search, and delete entries
- Store usernames, passwords, URLs, notes, and tags
- Generate random passwords with configurable length and character options
- Import and export entries as JSON or CSV
- Launch the desktop GUI directly, or use the CLI for scripts and terminal workflows
- Encrypt the vault file with AES-256-GCM using a key derived from the master password with Argon2id

## Requirements

- Rust and Cargo (install through [rustup](https://rustup.rs/))

## Build and launch

Run the desktop GUI from the project directory:

```sh
cargo run
```

The GUI can also be launched explicitly:

```sh
cargo run -- gui
```

Build a standalone executable:

```sh
cargo build --release
```

On Windows, the executable is `target\release\rustvault.exe`. Running it without arguments opens the GUI. On other platforms, the executable is at `target/release/rustvault`.

Run the test suite with:

```sh
cargo test
```

## CLI usage

Initialize a vault:

```sh
cargo run -- init --master-password "your-master-password"
```

Add an entry. If `--password` is omitted, RustVault generates one using `--length` (default: 20):

```sh
cargo run -- add \
  --master-password "your-master-password" \
  --name "GitHub" \
  --username "octocat" \
  --password "S3cret!" \
  --url "https://github.com" \
  --notes "Primary account" \
  --tags work,dev
```

List entries, optionally filtering by tag or a text query:

```sh
cargo run -- list --master-password "your-master-password"
cargo run -- list --master-password "your-master-password" --tag work
cargo run -- list --master-password "your-master-password" --query github
```

Get an entry. Passwords are omitted unless `--show-password` is specified:

```sh
cargo run -- get --master-password "your-master-password" GitHub
cargo run -- get --master-password "your-master-password" GitHub --show-password
```

Edit or delete an entry:

```sh
cargo run -- edit --master-password "your-master-password" GitHub --username "new-name"
cargo run -- delete --master-password "your-master-password" GitHub
```

Generate a password (default length: 24):

```sh
cargo run -- generate --length 32 --symbols
cargo run -- generate --length 24 --no-numbers
```

Import or export data in JSON or CSV format:

```sh
cargo run -- export json --master-password "your-master-password" --output vault-export.json
cargo run -- export csv --master-password "your-master-password" --output vault-export.csv
cargo run -- import json --master-password "your-master-password" vault-export.json
```

Add `--json` before the command to request JSON-formatted output where supported, for example:

```sh
cargo run -- --json list --master-password "your-master-password"
```

## Vault location and security

The encrypted vault file is named `rustvault.json` and is stored in the `.vault` directory under your user profile:

- Windows: `%USERPROFILE%\.vault\rustvault.json`
- macOS/Linux: `$HOME/.vault/rustvault.json`

The vault contents are encrypted at rest with AES-256-GCM. Argon2id derives the encryption key from the master password and a random salt; each save uses a fresh salt and nonce.

**Keep your master password safe.** It is required to decrypt the vault and cannot be recovered by RustVault. CLI examples pass it as a command-line argument, which may be visible in shell history or process listings; use the GUI or take appropriate precautions when entering it.

JSON and CSV exports are **unencrypted** and contain the vault data in readable form. Store exported files securely and remove them when no longer needed.

## Current limitations

- The GUI currently supports unlocking/browsing entries, searching, and adding entries. Editing and deleting entries are available through the CLI.
- TUI mode and TOTP support are placeholders and are not implemented yet.
- FIDO2 unlock, clipboard integration, synchronization, and a packaged installer are not currently available.
