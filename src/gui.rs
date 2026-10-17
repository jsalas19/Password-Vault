use eframe::egui;

use crate::{generate_password, normalize_tags, save_vault, AppError, VaultEntry};

/// Starts the desktop GUI and creates a top-level window for the password vault experience.
pub fn run_gui() -> Result<(), AppError> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "RustVault",
        native_options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(GuiApp::default()))
        }),
    )
    .map_err(|err| AppError(err.to_string()))?;
    Ok(())
}

/// Holds the GUI state for unlocking the vault, editing forms, and browsing saved entries.
#[derive(Default)]
pub struct GuiApp {
    master_password: String,
    search_query: String,
    status: String,
    entries: Vec<VaultEntry>,
    form_name: String,
    form_username: String,
    form_password: String,
    form_url: String,
    form_notes: String,
    form_tags: String,
    password_length: usize,
    selected_index: Option<usize>,
    vault_unlocked: bool,
    show_password: bool,
    recovery_enabled: bool,
    recovery_notice: Option<String>,
    recovery_mode: bool,
    recovery_key_input: String,
    replacement_password: String,
    confirm_replacement_password: String,
}

impl GuiApp {
    /// Attempts to decrypt the vault using the form password and populate the entry list when successful.
    fn unlock_vault(&mut self) {
        if self.master_password.trim().is_empty() {
            self.status = "Enter a master password first.".to_string();
            return;
        }

        match crate::load_vault(&self.master_password) {
            Ok(vault) => {
                let recovery_enabled = match crate::vault_has_recovery() {
                    Ok(enabled) => enabled,
                    Err(err) => {
                        self.entries.clear();
                        self.vault_unlocked = false;
                        self.status = err.to_string();
                        return;
                    }
                };
                self.entries = vault.entries;
                self.vault_unlocked = true;
                self.recovery_enabled = recovery_enabled;
                self.selected_index = None;
                self.status = format!("Vault unlocked · {} entries", self.entries.len());
            }
            Err(err) => {
                self.entries.clear();
                self.vault_unlocked = false;
                self.recovery_enabled = false;
                self.selected_index = None;
                self.status = err.to_string();
            }
        }
    }

    /// Creates a new vault only when no vault already exists, then leaves it unlocked.
    fn create_vault(&mut self) {
        if self.master_password.trim().is_empty() {
            self.status = "Choose a master password before creating your vault.".to_string();
            return;
        }

        match crate::create_vault(&self.master_password) {
            Ok(recovery_key) => {
                self.entries.clear();
                self.vault_unlocked = true;
                self.recovery_enabled = true;
                self.recovery_notice = Some(recovery_key);
                self.selected_index = None;
                self.status =
                    "Vault created. Save your recovery key before continuing.".to_string();
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    /// Generates and displays a recovery key for an already-unlocked legacy vault.
    fn enable_recovery(&mut self) {
        match crate::enable_vault_recovery(&self.master_password) {
            Ok(recovery_key) => {
                self.recovery_enabled = true;
                self.recovery_notice = Some(recovery_key);
                self.status = "Recovery enabled. Save your recovery key now.".to_string();
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    /// Replaces the forgotten master password using the recovery key.
    fn recover_access(&mut self) {
        if self.replacement_password.trim().is_empty() {
            self.status = "Enter a new master password.".to_string();
            return;
        }
        if self.replacement_password != self.confirm_replacement_password {
            self.status = "The new master passwords do not match.".to_string();
            return;
        }

        match crate::recover_vault(&self.recovery_key_input, &self.replacement_password) {
            Ok(()) => {
                self.master_password = std::mem::take(&mut self.replacement_password);
                self.confirm_replacement_password.clear();
                self.recovery_key_input.clear();
                self.recovery_mode = false;
                self.unlock_vault();
                self.status = "Master password changed. Vault recovered and unlocked.".to_string();
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    /// Clears decrypted data and the master password from the GUI state.
    fn lock_vault(&mut self) {
        if self.recovery_notice.is_some() {
            self.status = "Save or copy your recovery key before locking the vault.".to_string();
            return;
        }
        self.entries.clear();
        self.master_password.clear();
        self.form_password.clear();
        self.selected_index = None;
        self.show_password = false;
        self.vault_unlocked = false;
        self.recovery_enabled = false;
        self.recovery_notice = None;
        self.status = "Vault locked.".to_string();
    }

    /// Saves a new entry into the vault and refreshes the in-memory list with the latest record.
    fn add_entry(&mut self) {
        let name = self.form_name.trim().to_string();
        if name.is_empty() {
            self.status = "Entry name is required.".to_string();
            return;
        }
        if !self.vault_unlocked {
            self.status = "Unlock the vault before adding entries.".to_string();
            return;
        }

        let mut vault = match crate::load_vault(&self.master_password) {
            Ok(vault) => vault,
            Err(err) => {
                self.vault_unlocked = false;
                self.entries.clear();
                self.status = format!("Could not verify the unlocked vault: {err}");
                return;
            }
        };

        if vault.entries.iter().any(|entry| entry.name == name) {
            self.status = format!("Entry '{}' already exists.", name);
            return;
        }

        let password = if self.form_password.trim().is_empty() {
            generate_password(self.password_length.max(8), true, false)
        } else {
            self.form_password.trim().to_string()
        };

        let timestamp = crate::current_timestamp();
        let entry = VaultEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.clone(),
            username: self.form_username.trim().to_string(),
            password,
            url: self.form_url.trim().to_string(),
            notes: self.form_notes.trim().to_string(),
            tags: normalize_tags(
                self.form_tags
                    .split(',')
                    .map(|tag| tag.trim().to_string())
                    .filter(|tag| !tag.is_empty())
                    .collect(),
            ),
            created_at: timestamp.clone(),
            updated_at: timestamp,
        };

        vault.entries.push(entry.clone());
        if let Err(err) = save_vault(&vault, &self.master_password) {
            self.status = err.to_string();
            return;
        }

        self.entries.push(entry);
        self.status = format!("Added entry '{}'.", name);
        self.form_name.clear();
        self.form_username.clear();
        self.form_password.clear();
        self.form_url.clear();
        self.form_notes.clear();
        self.form_tags.clear();
        self.selected_index = Some(self.entries.len() - 1);
        self.show_password = false;
    }

    /// Generates a random password for the form using the configured password length.
    fn generate_password_for_form(&mut self) {
        self.form_password = generate_password(self.password_length.max(12), true, false);
    }

    /// Returns the indexes of entries matching the current search query.
    fn filtered_entry_indexes(&self) -> Vec<usize> {
        let query = self.search_query.trim().to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let matches = query.is_empty()
                    || format!(
                        "{} {} {} {} {}",
                        entry.name,
                        entry.username,
                        entry.url,
                        entry.notes,
                        entry.tags.join(" ")
                    )
                    .to_lowercase()
                    .contains(&query);
                matches.then_some(index)
            })
            .collect()
    }
}

/// Paints the main desktop window and its controls for unlocking, searching, and adding entries.
impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("RustVault");
            ui.label("Your encrypted password vault");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Master password");
                let password = ui.add_sized(
                    egui::vec2(300.0, 28.0),
                    egui::TextEdit::singleline(&mut self.master_password)
                        .password(true)
                        .hint_text("Enter your master password"),
                );
                if password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.unlock_vault();
                }
                if ui.button("Unlock").clicked() {
                    self.unlock_vault();
                }
                if !self.vault_unlocked && ui.button("Create new vault").clicked() {
                    self.create_vault();
                }
                if self.vault_unlocked && ui.button("Lock").clicked() {
                    self.lock_vault();
                }
            });

            ui.separator();

            if self.vault_unlocked {
                if let Some(recovery_key) = self.recovery_notice.clone() {
                    ui.group(|ui| {
                        ui.heading("Save your recovery key");
                        ui.label("This key is shown only now. Store it somewhere safe and separate from this device.");
                        let mut visible_key = recovery_key.clone();
                        ui.add(
                            egui::TextEdit::singleline(&mut visible_key)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        );
                        ui.horizontal(|ui| {
                            if ui.button("Copy recovery key").clicked() {
                                ui.ctx().copy_text(recovery_key.clone());
                                self.status = "Recovery key copied. Store it securely.".to_string();
                            }
                            if ui.button("I've saved it").clicked() {
                                self.recovery_notice = None;
                                self.status = "Recovery key hidden. Keep your saved copy safe.".to_string();
                            }
                        });
                    });
                    ui.add_space(8.0);
                }
                ui.columns(2, |cols| {
                    cols[0].vertical(|ui| {
                        ui.group(|ui| {
                            ui.heading("Add an entry");
                            ui.label("Name");
                            ui.text_edit_singleline(&mut self.form_name);
                            ui.label("Username");
                            ui.text_edit_singleline(&mut self.form_username);
                            ui.label("Password (leave blank to generate)");
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.form_password)
                                        .password(true)
                                        .desired_width(190.0),
                                );
                                if ui.button("Generate").clicked() {
                                    self.generate_password_for_form();
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.label("Length");
                                ui.add(
                                    egui::DragValue::new(&mut self.password_length)
                                        .speed(1.0)
                                        .range(8..=128),
                                );
                            });
                            ui.label("Website URL");
                            ui.text_edit_singleline(&mut self.form_url);
                            ui.label("Tags (comma-separated)");
                            ui.text_edit_singleline(&mut self.form_tags);
                            ui.label("Notes");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.form_notes)
                                    .desired_rows(4)
                                    .desired_width(f32::INFINITY),
                            );
                            if ui.button("Save entry").clicked() {
                                self.add_entry();
                            }
                        });
                    });

                    cols[1].vertical(|ui| {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.heading("Your entries");
                                ui.label(format!("({})", self.entries.len()));
                            });
                            ui.add(
                                egui::TextEdit::singleline(&mut self.search_query)
                                    .hint_text("Search name, username, URL, notes, or tags"),
                            );

                            let indexes = self.filtered_entry_indexes();
                            if self.entries.is_empty() {
                                ui.label("No entries yet. Add one using the form.");
                            } else if indexes.is_empty() {
                                ui.label("No entries match your search.");
                            } else {
                                egui::ScrollArea::vertical()
                                    .max_height(220.0)
                                    .show(ui, |ui| {
                                        for index in indexes {
                                            let entry = &self.entries[index];
                                            let selected = self.selected_index == Some(index);
                                            if ui.selectable_label(selected, &entry.name).clicked()
                                            {
                                                self.selected_index = Some(index);
                                                self.show_password = false;
                                            }
                                            ui.small(format!(
                                                "{} · {}",
                                                if entry.username.is_empty() {
                                                    "No username"
                                                } else {
                                                    &entry.username
                                                },
                                                if entry.url.is_empty() {
                                                    "No URL"
                                                } else {
                                                    &entry.url
                                                }
                                            ));
                                        }
                                    });
                            }
                        });

                        if let Some(entry) = self
                            .selected_index
                            .and_then(|index| self.entries.get(index))
                        {
                            ui.add_space(8.0);
                            ui.group(|ui| {
                                ui.heading(&entry.name);
                                ui.label(format!(
                                    "Username: {}",
                                    if entry.username.is_empty() {
                                        "—"
                                    } else {
                                        &entry.username
                                    }
                                ));
                                ui.label(format!(
                                    "URL: {}",
                                    if entry.url.is_empty() {
                                        "—"
                                    } else {
                                        &entry.url
                                    }
                                ));
                                ui.checkbox(&mut self.show_password, "Show password");
                                ui.label(if self.show_password {
                                    format!("Password: {}", entry.password)
                                } else {
                                    "Password: ••••••••".to_string()
                                });
                                if !entry.tags.is_empty() {
                                    ui.label(format!("Tags: {}", entry.tags.join(", ")));
                                }
                                if !entry.notes.is_empty() {
                                    ui.label("Notes");
                                    ui.label(&entry.notes);
                                }
                            });
                        } else {
                            ui.add_space(8.0);
                            ui.label("Select an entry to view its details.");
                        }
                    });
                });
                if !self.recovery_enabled {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("This existing vault has no recovery key.");
                        if ui.button("Set up recovery").clicked() {
                            self.enable_recovery();
                        }
                    });
                }
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(36.0);
                    ui.heading("Unlock your vault");
                    ui.label("Enter your master password above, or create a new vault.");
                    ui.label("Your master password cannot be recovered if you forget it.");
                    if ui.button(if self.recovery_mode {
                        "Back to unlock"
                    } else {
                        "Forgot master password? Use recovery key"
                    })
                    .clicked()
                    {
                        self.recovery_mode = !self.recovery_mode;
                    }
                    if self.recovery_mode {
                        ui.add_space(12.0);
                        ui.group(|ui| {
                            ui.heading("Recover vault access");
                            ui.label("Enter the recovery key you saved when setting up recovery.");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.recovery_key_input)
                                    .hint_text("Recovery key")
                                    .desired_width(420.0),
                            );
                            ui.label("New master password");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.replacement_password)
                                    .password(true)
                                    .desired_width(420.0),
                            );
                            ui.label("Confirm new master password");
                            ui.add(
                                egui::TextEdit::singleline(
                                    &mut self.confirm_replacement_password,
                                )
                                .password(true)
                                .desired_width(420.0),
                            );
                            if ui.button("Recover and change master password").clicked() {
                                self.recover_access();
                            }
                        });
                    }
                });
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                if !self.status.is_empty() {
                    ui.separator();
                    ui.label(&self.status);
                }
            });
        });
    }
}
