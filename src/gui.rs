use eframe::egui;

use crate::{
    generate_password, normalize_tags, save_vault, AppError, VaultEntry, VaultData,
};

/// Starts the desktop GUI and creates a top-level window for the password vault experience.
pub fn run_gui() -> Result<(), AppError> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "RustVault",
        native_options,
        Box::new(|_cc| Ok(Box::new(GuiApp::default()))),
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
                self.entries = vault.entries;
                self.status = format!("Unlocked {} entries", self.entries.len());
            }
            Err(err) => {
                self.entries.clear();
                self.status = err.to_string();
            }
        }
    }

    /// Saves a new entry into the vault and refreshes the in-memory list with the latest record.
    fn add_entry(&mut self) {
        let name = self.form_name.trim().to_string();
        if name.is_empty() {
            self.status = "Entry name is required.".to_string();
            return;
        }
        if self.master_password.trim().is_empty() {
            self.status = "Enter the master password before adding entries.".to_string();
            return;
        }

        let mut vault = match crate::load_vault(&self.master_password) {
            Ok(vault) => vault,
            Err(_) => VaultData::default(),
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
        self.status = format!("Added entry '{}'", name);
        self.form_name.clear();
        self.form_username.clear();
        self.form_password.clear();
        self.form_url.clear();
        self.form_notes.clear();
        self.form_tags.clear();
        self.selected_index = None;
    }

    /// Generates a random password for the form using the configured password length.
    fn generate_password_for_form(&mut self) {
        self.form_password = generate_password(self.password_length.max(12), true, false);
    }

    /// Returns the entries matching the current search query so the GUI can render a filtered list.
    fn filtered_entries(&self) -> Vec<&VaultEntry> {
        let query = self.search_query.trim().to_lowercase();
        self.entries
            .iter()
            .filter(|entry| {
                if query.is_empty() {
                    true
                } else {
                    let haystack = format!(
                        "{} {} {} {}",
                        entry.name, entry.username, entry.url, entry.notes
                    )
                    .to_lowercase();
                    haystack.contains(&query)
                }
            })
            .collect()
    }
}

/// Paints the main desktop window and its controls for unlocking, searching, and adding entries.
impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("RustVault");

            ui.horizontal(|ui| {
                ui.label("Master password");
                let password = ui.add_sized(
                    egui::vec2(260.0, 28.0),
                    egui::TextEdit::singleline(&mut self.master_password).password(true),
                );
                if password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.unlock_vault();
                }
                if ui.button("Unlock").clicked() {
                    self.unlock_vault();
                }
            });

            ui.separator();

            ui.columns(2, |cols| {
                cols[0].vertical(|ui| {
                    ui.group(|ui| {
                        ui.label("New entry");
                        ui.horizontal(|ui| {
                            ui.label("Name");
                            ui.text_edit_singleline(&mut self.form_name);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Username");
                            ui.text_edit_singleline(&mut self.form_username);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Password");
                            ui.add(egui::TextEdit::singleline(&mut self.form_password).password(true));
                            if ui.button("Generate").clicked() {
                                self.generate_password_for_form();
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("Length");
                            ui.add(egui::DragValue::new(&mut self.password_length).speed(1.0).range(8..=128));
                        });
                        ui.horizontal(|ui| {
                            ui.label("URL");
                            ui.text_edit_singleline(&mut self.form_url);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Tags");
                            ui.text_edit_singleline(&mut self.form_tags);
                        });
                        ui.group(|ui| {
                            ui.label("Notes");
                            ui.text_edit_multiline(&mut self.form_notes);
                        });
                        if ui.button("Save entry").clicked() {
                            self.add_entry();
                        }
                    });
                });

                cols[1].vertical(|ui| {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label("Search");
                            ui.text_edit_singleline(&mut self.search_query);
                        });
                        ui.separator();

                        if self.entries.is_empty() {
                            ui.label("No entries loaded.");
                        } else {
                            let visible_indexes: Vec<usize> = self
                                .entries
                                .iter()
                                .enumerate()
                                .filter_map(|(idx, entry)| {
                                    let query = self.search_query.trim().to_lowercase();
                                    if query.is_empty() {
                                        Some(idx)
                                    } else {
                                        let haystack = format!(
                                            "{} {} {} {}",
                                            entry.name, entry.username, entry.url, entry.notes
                                        )
                                        .to_lowercase();
                                        if haystack.contains(&query) {
                                            Some(idx)
                                        } else {
                                            None
                                        }
                                    }
                                })
                                .collect();

                            for idx in visible_indexes {
                                let entry = &self.entries[idx];
                                let selected = self.selected_index == Some(idx);
                                if ui.selectable_label(selected, &entry.name).clicked() {
                                    self.selected_index = Some(idx);
                                }
                                ui.label(format!("{} · {}", entry.username, entry.url));
                                if !entry.tags.is_empty() {
                                    ui.label(format!("Tags: {}", entry.tags.join(", ")));
                                }
                                ui.separator();
                            }
                        }
                    });
                });
            });

            ui.separator();
            ui.label(&self.status);
        });
    }
}
