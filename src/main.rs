#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use quick_xml::de::from_str;
use rayon::prelude::*;
use rfd::FileDialog;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::fs;
use std::time::Instant;
use std::collections::HashSet;
use chrono::NaiveDateTime;
use rust_xlsxwriter::*; // Excel Support

// --- XML Structures ---
#[derive(Debug, Deserialize, Clone)]
struct Event {
    #[serde(rename = "Timestamp")]
    timestamp: Option<String>,
    #[serde(rename = "Packet-Type")]
    packet_type: Option<String>,
    #[serde(rename = "Class")]
    class: Option<String>,
    #[serde(rename = "Acct-Session-Id")]
    acct_session_id: Option<String>, // Key for correlation
    #[serde(rename = "Computer-Name")]
    server: Option<String>,
    #[serde(rename = "Client-IP-Address")]
    ap_ip: Option<String>,
    #[serde(rename = "NAS-Identifier")]
    ap_name: Option<String>,
    #[serde(rename = "Client-Friendly-Name")]
    client_friendly_name: Option<String>,
    #[serde(rename = "Calling-Station-Id")]
    mac: Option<String>,
    #[serde(rename = "User-Name")]
    user_name: Option<String>,
    #[serde(rename = "SAM-Account-Name")]
    sam_account: Option<String>,
    #[serde(rename = "Reason-Code")]
    reason_code: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct RadiusRequest {
    timestamp: String,
    parsed_time: Option<NaiveDateTime>, // For sorting/filtering
    req_type: String,
    server: String,
    ap_ip: String,
    ap_name: String,
    mac: String,
    user: String,
    resp_type: String,
    reason: String,
    class_id: String,
    session_id: String, // New field for Acct-Session-Id
    bg_color: Option<egui::Color32>, 
}

impl RadiusRequest {
     // "MM/DD/YYYY HH:MM:SS" or with milliseconds -> NaiveDateTime
    fn parse_timestamp(s: &str) -> Option<NaiveDateTime> {
        // Try common formats, starting with the one found in user logs (with ms)
        NaiveDateTime::parse_from_str(s, "%m/%d/%Y %H:%M:%S%.3f").ok()
            .or_else(|| NaiveDateTime::parse_from_str(s, "%m/%d/%Y %H:%M:%S").ok())
            .or_else(|| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.3f").ok())
            .or_else(|| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok())
    }

    fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        self.user.to_lowercase().contains(&q) 
        || self.mac.to_lowercase().contains(&q)
        || self.ap_ip.contains(&q)
        || self.ap_name.to_lowercase().contains(&q)
        || self.server.to_lowercase().contains(&q)
        || self.reason.to_lowercase().contains(&q)
        || self.req_type.to_lowercase().contains(&q)
        || self.resp_type.to_lowercase().contains(&q)
    }

    fn to_tsv(&self) -> String {
        format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", 
            self.timestamp, self.req_type, self.server, self.ap_ip, 
            self.ap_name, self.mac, self.user, self.reason)
    }
}

struct AboutWindow {
    open: bool,
}

impl Default for AboutWindow {
    fn default() -> Self {
        Self { open: false }
    }
}

impl AboutWindow {
    fn show(&mut self, ctx: &egui::Context) {
        if !self.open {
            return;
        }
        
        let mut should_close = false;
        
        egui::Window::new("À propos")
            .open(&mut self.open)
            .resizable(false)
            .collapsible(false)
            .default_width(500.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(15.0);
                    ui.heading(egui::RichText::new("RADIUS Log Browser").size(26.0).strong());
                    ui.label(egui::RichText::new("NPS/IAS Edition").size(15.0).color(egui::Color32::GRAY));
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).size(13.0).color(egui::Color32::DARK_GRAY));
                    ui.add_space(20.0);
                });
                
                ui.separator();
                ui.add_space(15.0);
                
                // Section Auteur
                ui.group(|ui| {
                    ui.set_min_width(450.0);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("👤").size(18.0));
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Développé par").size(11.0).color(egui::Color32::GRAY));
                            ui.label(egui::RichText::new("Olivier Noblanc").size(15.0).strong());
                        });
                    });
                    ui.add_space(8.0);
                });
                
                ui.add_space(12.0);
                
                // Section Projet
                ui.group(|ui| {
                    ui.set_min_width(450.0);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("🔗").size(18.0));
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Dépôt GitHub").size(11.0).color(egui::Color32::GRAY));
                            ui.hyperlink_to(
                                egui::RichText::new("olivier-noblanc/nps-radius-log-viewer").size(13.0),
                                "https://github.com/olivier-noblanc/nps-radius-log-viewer"
                            );
                        });
                    });
                    ui.add_space(8.0);
                });
                
                ui.add_space(15.0);
                ui.separator();
                ui.add_space(15.0);
                
                // Description
                ui.label(egui::RichText::new("📝 Description").size(14.0).strong());
                ui.add_space(8.0);
                ui.label("Visualiseur haute performance pour les logs RADIUS de Microsoft NPS/IAS.");
                ui.label("Construit avec Rust et egui pour une vitesse maximale et zéro dépendance.");
                
                ui.add_space(15.0);
                ui.separator();
                ui.add_space(15.0);
                
                // Licence
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("⚖️ Licence :").size(13.0).strong());
                    ui.label(egui::RichText::new("MIT / Apache 2.0").size(13.0));
                });
                
                ui.add_space(15.0);
                ui.separator();
                ui.add_space(15.0);
                
                // Crédit
                ui.label(egui::RichText::new("🙏 Remerciements").size(13.0).strong());
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.label("Basé sur le projet original de");
                    ui.hyperlink_to(
                        "burnacid",
                        "https://github.com/burnacid/RADIUS-Log-Browser"
                    );
                });
                
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    if ui.button(egui::RichText::new("Fermer").size(14.0)).clicked() {
                        should_close = true;
                    }
                });
                ui.add_space(15.0);
            });
        
        if should_close {
            self.open = false;
        }
    }
}

struct RadiusBrowserApp {
    items: Arc<Vec<RadiusRequest>>, 
    filtered_items: Arc<Vec<RadiusRequest>>,
    status: String,
    search_text: String,
    selected_row: Option<usize>,
    // Store calculated widths: [Time, Type, Server, IP, Name, MAC, User]
    // Store calculated widths: [Time, Type, Server, IP, Name, MAC, User]
    // Reason is remainder.
    col_widths: Vec<f32>,
    layout_version: usize,
    show_errors_only: bool, // New Filter State
    about_window: AboutWindow, // About Window
}

impl Default for RadiusBrowserApp {
    fn default() -> Self {
        Self {
            items: Arc::new(Vec::new()),
            filtered_items: Arc::new(Vec::new()),
            status: "Ready. Click 'Open Log File' to load.".to_owned(),
            search_text: String::new(),
            selected_row: None,
            col_widths: vec![130.0, 110.0, 110.0, 100.0, 150.0, 130.0, 150.0, 300.0],
            layout_version: 0,
            show_errors_only: false,
            about_window: AboutWindow::default(),
        }
    }
}

impl RadiusBrowserApp {
    fn apply_filter(&mut self) {
        let query = self.search_text.trim().to_lowercase();
        let all = self.items.clone();
        
        // 1. Identify "Failed Sessions" by Acct-Session-Id
        // We collect the Session IDs of all Access-Rejects.
        let mut failed_session_ids: HashSet<String> = HashSet::new();

        if self.show_errors_only {
            for item in all.iter() {
                if item.resp_type == "Access-Reject" {
                    if !item.session_id.is_empty() {
                         failed_session_ids.insert(item.session_id.clone());
                    }
                }
            }
        }

        let filtered: Vec<RadiusRequest> = all.iter()
            .filter(|item| {
                // 2. Exact Session Filter
                if self.show_errors_only {
                     // Must belong to a failed session ID
                     if item.session_id.is_empty() || !failed_session_ids.contains(&item.session_id) {
                         return false;
                     }
                    
                    // REFINEMENT: Hide "Success" rows even for failed sessions to avoid noise?
                    // The user said "show me the exchange", so we WANT to see Requests and Challenges.
                    // But we likely don't want to see "Access-Accept" if by some miracle it happened (unlikely).
                    // We definitely don't want to see "Accounting-Response".
                    if item.resp_type == "Access-Accept" || item.resp_type == "Accounting-Response" {
                        return false;
                    }
                }
                
                // 3. Text Search
                if query.is_empty() {
                    return true;
                }
                item.matches(&query)
            })
            .cloned()
            .collect();
            
        self.filtered_items = Arc::new(filtered);
        self.selected_row = None;
    }

    fn calculate_widths(items: &[RadiusRequest], ctx: &egui::Context) -> Vec<f32> {
        let mut max_widths = vec![130.0, 80.0, 100.0, 100.0, 120.0, 120.0, 100.0, 200.0]; 
        
        let font_id = egui::FontId::proportional(14.0); // Exact match to Body style
        let header_font = egui::FontId::proportional(14.0); 
        
        // Measure Headers first
        let headers = ["Timestamp", "Type", "Server", "AP IP", "AP Name", "MAC", "User", "Result/Reason"];
        ctx.fonts(|fonts| {
             for (i, h) in headers.iter().enumerate() {
                 let w = fonts.layout_no_wrap(h.to_string(), header_font.clone(), egui::Color32::WHITE).rect.width();
                 if w > max_widths[i] { max_widths[i] = w; }
             }
        });

        // Measure first 5000 items (fast enough with direct layout)
        let sample_limit = 5000;
        
        ctx.fonts(|fonts| {
            for item in items.iter().take(sample_limit) {
                // Helper to measure and update
                let mut measure = |idx: usize, text: &str| {
                    if text.is_empty() { return; }
                    let w = fonts.layout_no_wrap(text.to_string(), font_id.clone(), egui::Color32::WHITE).rect.width();
                    if w > max_widths[idx] { max_widths[idx] = w; }
                };

                measure(0, &item.timestamp);
                measure(1, &item.req_type);
                measure(2, &item.server);
                measure(3, &item.ap_ip);
                measure(4, &item.ap_name);
                measure(5, &item.mac);
                measure(6, &item.user);
                
                let reason = if !item.reason.is_empty() { &item.reason } else { &item.resp_type };
                measure(7, reason);
            }
        });

        // Add padding + Clamping
        max_widths.iter().map(|w| (w + 24.0).clamp(60.0, 800.0)).collect()
    }
}

impl eframe::App for RadiusBrowserApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut filter_changed = false;

        // --- Top Panel: File & Search ---
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(4.0); 
            ui.horizontal(|ui| {
                if ui.button("📂 Open Log File").clicked() {
                    if let Some(path) = FileDialog::new().add_filter("Log", &["log"]).pick_file() {
                        let path_str = path.to_string_lossy().to_string();
                        let start = Instant::now();
                        
                        match parse_full_logic(&path_str) {
                            Ok(items) => {
                                 let count = items.len();
                                 let new_widths = Self::calculate_widths(&items, ctx); // Pass ctx
                                 self.items = Arc::new(items);
                                 self.col_widths = new_widths; // Apply widths
                                 self.layout_version += 1; // RESET TABLE STATE
                                 self.search_text.clear();
                                 self.show_errors_only = false; // Reset filters on load
                                 self.filtered_items = self.items.clone();
                                 self.status = format!("Loaded {} requests in {:?}", count, start.elapsed());
                                 self.selected_row = None;
                            }
                            Err(e) => {
                                self.status = format!("Error: {}", e);
                            }
                        }
                    }
                }

                ui.separator();
                
                // Toggle Button for Errors
                let btn = ui.button(if self.show_errors_only { "⚠️ Show All" } else { "⚠️ Failed Sessions" });
                if btn.clicked() {
                    self.show_errors_only = !self.show_errors_only;
                    filter_changed = true;
                }
                if self.show_errors_only {
                     ui.label(egui::RichText::new("(Showing all traffic for failed users)").color(egui::Color32::RED));
                }

                ui.separator();
                ui.label(egui::RichText::new("🔍 Search:").strong());
                if ui.text_edit_singleline(&mut self.search_text).changed() {
                    filter_changed = true;
                }
                
                if !self.search_text.is_empty() {
                    if ui.button("❌ Clear").clicked() {
                        self.search_text.clear();
                        filter_changed = true;
                    }
                }

                ui.separator();
                if ui.add_enabled(self.selected_row.is_some(), egui::Button::new("📋 Copy Row")).clicked() {
                    if let Some(idx) = self.selected_row {
                        if idx < self.filtered_items.len() {
                             ui.ctx().copy_text(self.filtered_items[idx].to_tsv());
                        }
                    }
                }
                
                ui.separator();
                if ui.button("ℹ️ About").clicked() {
                    self.about_window.open = true;
                }
            });
            ui.add_space(4.0);
            ui.label(&self.status);
            ui.add_space(4.0);
        });

        if filter_changed {
            self.apply_filter();
        }

        // --- Keyboard Navigation ---
        // Handle keys only if no text edit is focused (simple check: if we're typing search, don't nav)
        // Better: ctx.input(...)
        let mut scroll_target = None;
        if !ctx.wants_keyboard_input() {
            let total = self.filtered_items.len();
            if total > 0 {
                let current = self.selected_row.unwrap_or(0);
                let mut next = current;
                let mut changed = false;

                if ctx.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
                    if current < total - 1 {
                        next = current + 1;
                        changed = true;
                    }
                }
                if ctx.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                    if current > 0 {
                        next = current - 1;
                        changed = true;
                    }
                }
                if ctx.input(|i| i.key_pressed(egui::Key::PageDown)) {
                    next = (current + 20).min(total - 1);
                    changed = true;
                }
                if ctx.input(|i| i.key_pressed(egui::Key::PageUp)) {
                    next = current.saturating_sub(20);
                    changed = true;
                }
                 if ctx.input(|i| i.key_pressed(egui::Key::Home)) {
                    next = 0;
                    changed = true;
                }
                if ctx.input(|i| i.key_pressed(egui::Key::End)) {
                    if total > 0 {
                        next = total - 1;
                        changed = true;
                    }
                }

                if changed {
                    // Double Safety Clamp
                    next = next.min(total.saturating_sub(1));
                    self.selected_row = Some(next);
                    scroll_target = Some(next);
                }
            }
        }

        // --- Central Panel: Virtual Table ---
        egui::CentralPanel::default().show(ctx, |ui| {
            let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 6.0; 

            let next_search: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let next_status: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let ws = &self.col_widths;

            ui.push_id(self.layout_version, |ui| {
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    // Manual Horizontal Scroll Support
                    if ctx.input(|i| i.key_down(egui::Key::ArrowRight)) {
                        ui.scroll_with_delta(egui::vec2(-10.0, 0.0)); // Adjusted speed
                    }
                    if ctx.input(|i| i.key_down(egui::Key::ArrowLeft)) {
                        ui.scroll_with_delta(egui::vec2(10.0, 0.0));
                    }
                    
                    // Export Button
                    if ui.button("📊 Export to Excel").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("Excel", &["xlsx"]).save_file() {
                             // Clone data to move into thread or write immediately (blocking is okay for now)
                             let items = self.filtered_items.clone();
                             let path_clone = path.clone();
                             let status_ref = next_status.clone();
                             
                             std::thread::spawn(move || {
                                 let mut workbook = Workbook::new();
                                 let worksheet = workbook.add_worksheet();
                                 
                                 // Header Format
                                 let bold = Format::new().set_bold();
                                 
                                 // Write Headers
                                 let headers = ["Timestamp", "Type", "Server", "AP IP", "AP Name", "MAC", "User", "Result/Reason"];
                                 for (col, header) in headers.iter().enumerate() {
                                     let _ = worksheet.write_with_format(0, col as u16, *header, &bold);
                                 }
                                 
                                 // Write Data
                                 for (row_idx, item) in items.iter().enumerate() {
                                     let r = (row_idx + 1) as u32;
                                     let _ = worksheet.write(r, 0, &item.timestamp);
                                     let _ = worksheet.write(r, 1, &item.req_type);
                                     let _ = worksheet.write(r, 2, &item.server);
                                     let _ = worksheet.write(r, 3, &item.ap_ip);
                                     let _ = worksheet.write(r, 4, &item.ap_name);
                                     let _ = worksheet.write(r, 5, &item.mac);
                                     let _ = worksheet.write(r, 6, &item.user);
                                     
                                     let res_text = if !item.reason.is_empty() { 
                                         format!("{} ({})", item.resp_type, item.reason) 
                                     } else { 
                                         item.resp_type.clone() 
                                     };
                                     let _ = worksheet.write(r, 7, &res_text);
                                 }
                                 
                                 // Auto-width
                                 let _ = worksheet.autofit();
                                 
                                 if let Err(e) = workbook.save(&path_clone) {
                                     *status_ref.lock().unwrap() = Some(format!("Export failed: {}", e));
                                 } else {
                                     *status_ref.lock().unwrap() = Some("Export successful!".to_string());
                                 }
                             });
                        }
                    }

                    let mut table = TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(ws[0]).resizable(true)) // Timestamp
                        .column(Column::initial(ws[1]).resizable(true)) // Type
                        .column(Column::initial(ws[2]).resizable(true)) // Server
                        .column(Column::initial(ws[3]).resizable(true)) // AP IP
                        .column(Column::initial(ws[4]).resizable(true)) // AP Name
                        .column(Column::initial(ws[5]).resizable(true)) // MAC
                        .column(Column::initial(ws[6]).resizable(true)) // User
                        .column(Column::initial(ws[7]).resizable(true)); // Result (FIXED)

                if let Some(target) = scroll_target {
                    table = table.scroll_to_row(target, Some(egui::Align::Center));
                }

                table.header(22.0, |mut header| {
                        header.col(|ui| { ui.label(egui::RichText::new("Timestamp").strong()); });
                        header.col(|ui| { ui.label(egui::RichText::new("Type").strong()); });
                        header.col(|ui| { ui.label(egui::RichText::new("Server").strong()); });
                        header.col(|ui| { ui.label(egui::RichText::new("AP IP").strong()); });
                        header.col(|ui| { ui.label(egui::RichText::new("AP Name").strong()); });
                        header.col(|ui| { ui.label(egui::RichText::new("MAC").strong()); });
                        header.col(|ui| { ui.label(egui::RichText::new("User").strong()); });
                        header.col(|ui| { ui.label(egui::RichText::new("Result/Reason").strong()); });
                    })
                    .body(|body| {
                        body.rows(text_height, self.filtered_items.len(), |mut row| {
                            let row_index = row.index();
                            let item = &self.filtered_items[row_index];
                            let is_selected = self.selected_row == Some(row_index);
                            
                            let mut text_color = egui::Color32::BLACK;
                            if ctx.style().visuals.dark_mode { text_color = egui::Color32::LIGHT_GRAY; }
                            if is_selected { text_color = egui::Color32::WHITE; }



                            // Draw Cell Logic
                            let mut cell = |ui: &mut egui::Ui, text: &str, col_name: &str| {
                                let rect = ui.max_rect();
                                
                                // Background
                                if is_selected {
                                    ui.painter().rect_filled(rect, 0.0, egui::Color32::from_rgb(0, 120, 215)); 
                                } else if let Some(bg) = item.bg_color {
                                    ui.painter().rect_filled(rect, 0.0, bg);
                                    if !is_selected { text_color = egui::Color32::BLACK; }
                                }

                                // Interaction with distinct ID
                                let response = ui.interact(rect, ui.id().with(row_index).with(col_name), egui::Sense::click());
                                if response.clicked() {
                                    self.selected_row = Some(row_index);
                                }
                                
                                // Text
                                ui.painter().text(
                                    rect.min + egui::vec2(4.0, (rect.height() - 13.0) / 2.0),
                                    egui::Align2::LEFT_TOP,
                                    text,
                                    egui::FontId::proportional(13.0),
                                    text_color,
                                );
                                
                                // Context Menu
                                let text_val = text.to_string(); // Capture owned
                                let row_tsv = item.to_tsv();     // Capture owned
                                let ns = next_search.clone();
                                let status_ref = next_status.clone();
                                
                                response.context_menu(move |ui| {
                                    ui.set_enabled(true); 
                                    // Filter
                                    if ui.button(format!("Filter by '{}'", &text_val)).clicked() {
                                        *ns.lock().unwrap() = Some(text_val.clone());
                                        ui.close_menu();
                                    }
                                    ui.separator();
                                    ui.set_enabled(true); // Reinforce enabled state after separator
                                    // Copy Value
                                    if ui.button("Copy Cell Value").clicked() {
                                        ui.ctx().copy_text(text_val.clone());
                                        *status_ref.lock().unwrap() = Some(format!("Copied to clipboard: '{}'", &text_val));
                                        ui.close_menu();
                                    }
                                    // Copy Row
                                    if ui.button("Copy Entire Row").clicked() {
                                        ui.ctx().copy_text(row_tsv.clone());
                                        *status_ref.lock().unwrap() = Some("Row copied to clipboard".to_string());
                                        ui.close_menu();
                                    }
                                });
                            };

                            row.col(|ui| cell(ui, &item.timestamp, "ts"));
                            row.col(|ui| cell(ui, &item.req_type, "type"));
                            row.col(|ui| cell(ui, &item.server, "srv"));
                            row.col(|ui| cell(ui, &item.ap_ip, "ip"));
                            row.col(|ui| cell(ui, &item.ap_name, "ap"));
                            row.col(|ui| cell(ui, &item.mac, "mac"));
                            row.col(|ui| cell(ui, &item.user, "user"));
                            row.col(|ui| { 
                                let text = if !item.reason.is_empty() { &item.reason } else { &item.resp_type };
                                cell(ui, text, "res");
                            });
                        });
                    });
                }); // Close ScrollArea
            }); // Close PushId
                
            if let Some(s) = next_search.lock().unwrap().take() {
                self.search_text = s;
                self.apply_filter();
            };
            if let Some(msg) = next_status.lock().unwrap().take() {
                self.status = msg;
            };
        });
        
        // Afficher la fenêtre About si ouverte
        self.about_window.show(ctx);
    }
}

fn main() -> eframe::Result<()> {
    // Configuration de human-panic pour des rapports de crash professionnels
    human_panic::setup_panic!();
    
    // 1. System Theme Support (Dark/Light auto-detect)
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "Radius Log Browser (System Theme)",
        options,
        Box::new(|cc| {
            // 2. Modern Windows-like Styling (Subtle)
            // We don't force Light anymore. We just tweak the current visuals (Light or Dark).
            let mut visuals = if cc.egui_ctx.style().visuals.dark_mode {
                egui::Visuals::dark()
            } else {
                egui::Visuals::light()
            };
            
            // Common Tweaks for both modes
            visuals.selection.bg_fill = egui::Color32::from_rgb(0, 120, 215); // Windows Blue
            visuals.striped = true;
            
            cc.egui_ctx.set_visuals(visuals);
            
            // 3. Font Adaptation (Slightly larger for readability)
            let mut style = (*cc.egui_ctx.style()).clone();
            style.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(14.0)); // Default is often 13.0 or small
            style.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
            style.text_styles.insert(egui::TextStyle::Heading, egui::FontId::proportional(20.0));
            cc.egui_ctx.set_style(style);

            Ok(Box::new(RadiusBrowserApp::default()))
        }),
    )
}

fn parse_full_logic(path: &str) -> std::io::Result<Vec<RadiusRequest>> {
    let content = fs::read_to_string(path)?;
    let wrapped_content = format!("<events>{}</events>", content);
    
    #[derive(Deserialize)]
    struct Root {
        #[serde(rename = "Event", default)]
        events: Vec<Event>,
    }

    let root: Root = from_str(&wrapped_content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut events = root.events;
    events.par_sort_unstable_by(|a, b| a.class.cmp(&b.class));
    
    let requests: Vec<RadiusRequest> = events
        .chunk_by(|a, b| a.class == b.class) 
        .map(|group| process_group(group))
        .collect();
        
    let mut final_list = requests;
    final_list.par_sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(final_list)
}

fn process_group(group: &[Event]) -> RadiusRequest {
    let mut req = RadiusRequest::default();
    
    for event in group {
        let p_type = event.packet_type.as_deref().unwrap_or("");
        if p_type == "1" || p_type == "4" {
            if let Some(val) = &event.timestamp { 
                req.timestamp = val.clone();
                req.parsed_time = RadiusRequest::parse_timestamp(val);
            }
            if let Some(val) = &event.acct_session_id { req.session_id = val.clone(); }
            if let Some(val) = &event.server { req.server = val.clone(); }
            if let Some(val) = &event.ap_ip { req.ap_ip = val.clone(); }
            if let Some(val) = &event.ap_ip { req.ap_ip = val.clone(); }
            if let Some(val) = &event.client_friendly_name { req.ap_name = val.clone(); }
            else if let Some(val) = &event.ap_name { req.ap_name = val.clone(); }
            if let Some(val) = &event.mac { req.mac = val.clone(); }
            if let Some(val) = &event.class { req.class_id = val.clone(); }
            req.req_type = map_packet_type(p_type);
            if let Some(user) = &event.sam_account { req.user = user.clone(); } 
            else if let Some(user) = &event.user_name { req.user = user.clone(); } 
            else { req.user = "- UNKNOWN -".to_string(); }
        } else {
            req.resp_type = map_packet_type(p_type);
            req.reason = map_reason(event.reason_code.as_deref().unwrap_or("0"));
            match p_type {
                "2" => req.bg_color = Some(egui::Color32::from_rgb(188, 255, 188)), // Light Green
                "3" => req.bg_color = Some(egui::Color32::from_rgb(255, 188, 188)), // Light Red
                _ => {},
            }
        }
    }
    // Adjust colors for Dark Mode (if needed, but simple RGB works okay usually)
    // Ideally we'd map these to Theme colors, but let's stick to these for now.

    if req.class_id.is_empty() && !group.is_empty() {
         if let Some(c) = &group[0].class { req.class_id = c.clone(); }
    }
    req
}

fn map_packet_type(code: &str) -> String {
    match code {
        "1" => "Access-Request".to_string(),
        "2" => "Access-Accept".to_string(),
        "3" => "Access-Reject".to_string(),
        "4" => "Accounting-Request".to_string(),
        "5" => "Accounting-Response".to_string(),
        "11" => "Access-Challenge".to_string(),
        "12" => "Status-Server".to_string(),
        "13" => "Status-Client".to_string(),
        "255" => "Reserved".to_string(),
        _ => code.to_string(),
    }
}

fn map_reason(code: &str) -> String {
    match code {
        "0" => "The connection request was successfully authenticated and authorized by Network Policy Server.".to_string(),
        "1" => "The connection request failed due to a Network Policy Server error.".to_string(),
        "2" => "There are insufficient access rights to process the request.".to_string(),
        "3" => "The Remote Authentication Dial-In User Service (RADIUS) Access-Request message that NPS received from the network access server was malformed.".to_string(),
        "4" => "The NPS server was unable to access the Active Directory Domain Services (AD DS) global catalog.".to_string(),
        "5" => "The Network Policy Server was unable to connect to a domain controller in the domain where the user account is located.".to_string(),
        "6" => "The NPS server is unavailable. This issue can occur if the NPS server is running low on or is out of random access memory (RAM).".to_string(),
        "7" => "The domain that is specified in the User-Name attribute of the RADIUS message does not exist.".to_string(),
        "8" => "The user account that is specified in the User-Name attribute of the RADIUS message does not exist.".to_string(),
        "9" => "An Internet Authentication Service (IAS) extension dynamic link library (DLL) that is installed on the NPS server discarded the connection request.".to_string(),
        "10" => "An IAS extension dynamic link library (DLL) that is installed on the NPS server has failed and cannot perform its function.".to_string(),
        "16" => "Authentication failed due to a user credentials mismatch. Either the user name provided does not match an existing user account or the password was incorrect.".to_string(),
        "17" => "The user's attempt to change their password has failed.".to_string(),
        "18" => "The authentication method used by the client computer is not supported by Network Policy Server for this connection.".to_string(),
        "20" => "The client attempted to use LAN Manager authentication, which is not supported by Network Policy Server.".to_string(),
        "21" => "An IAS extension dynamic link library (DLL) that is installed on the NPS server rejected the connection request.".to_string(),
        "22" => "Network Policy Server was unable to negotiate the use of an Extensible Authentication Protocol (EAP) type with the client computer.".to_string(),
        "23" => "An error occurred during the Network Policy Server use of the Extensible Authentication Protocol (EAP).".to_string(),
        "32" => "NPS is joined to a workgroup and performs the authentication and authorization of connection requests using the local SAM database.".to_string(),
        "33" => "The user that is attempting to connect to the network must change their password.".to_string(),
        "34" => "The user account that is specified in the RADIUS Access-Request message is disabled.".to_string(),
        "35" => "The user account that is specified in the RADIUS Access-Request message is expired.".to_string(),
        "36" => "The user's authentication attempts have exceeded the maximum allowed number of failed attempts.".to_string(),
        "37" => "According to AD DS user account logon hours, the user is not permitted to access the network on this day and time.".to_string(),
        "38" => "Authentication failed due to a user account restriction or requirement that was not followed.".to_string(),
        "48" => "The connection request did not match a configured network policy, so the connection request was denied by Network Policy Server.".to_string(),
        "49" => "The connection request did not match a configured connection request policy, so the connection request was denied by Network Policy Server.".to_string(),
        "64" => "Remote Access Account Lockout is enabled, and the user's authentication attempts have exceeded the designated lockout count.".to_string(),
        "65" => "The Network Access Permission setting in the dial-in properties of the user account is set to Deny access to the user.".to_string(),
        "66" => "Authentication failed. Either the client computer attempted to use an authentication method that is not enabled on the matching network policy or the client computer attempted to authenticate as Guest.".to_string(),
        "67" => "NPS denied the connection request because the value of the Calling-Station-ID attribute did not match the value of Verify Caller ID.".to_string(),
        "68" => "The user or computer does not have permission to access the network on this day at this time.".to_string(),
        "69" => "The telephone number of the network access server does not match the value of the Calling-Station-ID attribute.".to_string(),
        "70" => "The network access method used by the access client to connect to the network does not match the value of the NAS-Port-Type attribute.".to_string(),
        "72" => "The user password has expired or is about to expire and the user must change their password.".to_string(),
        "73" => "The purposes that are configured in the Application Policies extensions of the user or computer certificate are not valid or are missing.".to_string(),
        "80" => "NPS attempted to write accounting data to the data store, but failed to do so for unknown reasons.".to_string(),
        "96" => "Authentication failed due to an Extensible Authentication Protocol (EAP) session timeout.".to_string(),
        "97" => "The authentication request was not processed because it contained a RADIUS message that was not appropriate for the secure authentication transaction.".to_string(),
        "112" => "The local NPS proxy server forwarded a connection request to a remote RADIUS server, and the remote server rejected the connection request.".to_string(),
        "113" => "The local NPS proxy attempted to forward a connection request to a member of a remote RADIUS server group that does not exist.".to_string(),
        "115" => "The local NPS proxy did not forward a RADIUS message because it is not an accounting request or a connection request.".to_string(),
        "116" => "The local NPS proxy server cannot forward the connection request to the remote RADIUS server (Socket error).".to_string(),
        "117" => "The remote RADIUS server did not respond to the local NPS proxy within an acceptable time period.".to_string(),
        "118" => "The local NPS proxy server received a RADIUS message that is malformed from a remote RADIUS server.".to_string(),
        "256" => "The certificate provided by the user or computer as proof of their identity is a revoked certificate.".to_string(),
        "257" => "NPS cannot access the certificate revocation list to verify whether the user or client computer certificate is valid or is revoked (Missing DLL).".to_string(),
        "258" => "NPS cannot access the certificate revocation list to verify whether the user or client computer certificate is valid or is revoked.".to_string(),
        "259" => "The certification authority that manages the certificate revocation list is not available.".to_string(),
        "260" => "The EAP message has been altered so that the MD5 hash of the entire RADIUS message does not match.".to_string(),
        "261" => "NPS cannot contact Active Directory Domain Services (AD DS) or the local user accounts database.".to_string(),
        "262" => "NPS discarded the RADIUS message because it is incomplete and the signature was not verified.".to_string(),
        "263" => "NPS did not receive complete credentials from the user or computer.".to_string(),
        "264" => "The SSPI called by EAP reports that the system clocks on the NPS server and the access client are not synchronized.".to_string(),
        "265" => "The certificate that the user or client computer provided to NPS chains to an enterprise root CA that is not trusted by the NPS server.".to_string(),
        "266" => "NPS received a message that was either unexpected or incorrectly formatted.".to_string(),
        "267" => "The certificate provided by the connecting user or computer is not valid (Missing Client Authentication purpose).".to_string(),
        "268" => "The certificate provided by the connecting user or computer is expired.".to_string(),
        "269" => "The SSPI called by EAP reports that the NPS server and the access client cannot communicate because they do not possess a common algorithm.".to_string(),
        "270" => "The user is required to log on with a smart card, but they have attempted to log on by using other credentials.".to_string(),
        "271" => "The connection request was not processed because the NPS server was in the process of shutting down or restarting.".to_string(),
        "272" => "The certificate implies multiple user or computer accounts rather than one account.".to_string(),
        "273" => "Authentication failed. NPS called Windows Trust Verification Services, and the trust provider is not recognized.".to_string(),
        "274" => "Authentication failed. NPS called Windows Trust Verification Services, and the trust provider does not support the specified action.".to_string(),
        "275" => "Authentication failed. NPS called Windows Trust Verification Services, and the trust provider does not support the specified form.".to_string(),
        "276" => "Authentication failed. The binary file that calls EAP cannot be verified and is not trusted.".to_string(),
        "277" => "Authentication failed. The binary file that calls EAP is not signed, or the signer certificate cannot be found.".to_string(),
        "278" => "Authentication failed. The certificate that was provided by the connecting user or computer is expired.".to_string(),
        "279" => "Authentication failed. The certificate is not valid because the validity periods of certificates in the chain do not match.".to_string(),
        "280" => "Authentication failed. The certificate is not valid and was not issued by a valid certification authority (CA).".to_string(),
        "281" => "Authentication failed. The path length constraint in the certification chain has been exceeded.".to_string(),
        "282" => "Authentication failed. The certificate contains a critical extension that is unrecognized by NPS.".to_string(),
        "283" => "Authentication failed. The certificate does not contain the Client Authentication purpose in Application Policies extensions.".to_string(),
        "284" => "Authentication failed. The certificate issuer and the parent of the certificate in the certificate chain do not match.".to_string(),
        "285" => "Authentication failed. NPS cannot locate the certificate, or the certificate is incorrectly formed.".to_string(),
        "286" => "Authentication failed. The CA is not trusted by the NPS server.".to_string(),
        "287" => "Authentication failed. The certificate does not chain to an enterprise root CA that NPS trusts.".to_string(),
        "288" => "Authentication failed due to an unspecified trust failure.".to_string(),
        "289" => "Authentication failed. The certificate provided by the connecting user or computer is revoked.".to_string(),
        "290" => "Authentication failed. A test or trial certificate is in use, however the test root CA is not trusted.".to_string(),
        "291" => "Authentication failed because NPS cannot locate and access the certificate revocation list.".to_string(),
        "292" => "Authentication failed. The User-Name attribute does not match the CN in the certificate.".to_string(),
        "293" => "Authentication failed. The certificate is not configured with the Client Authentication purpose.".to_string(),
        "294" => "Authentication failed because the certificate was explicitly marked as untrusted by the Administrator.".to_string(),
        "295" => "Authentication failed. The CA is not trusted by the NPS server.".to_string(),
        "296" => "Authentication failed. The certificate is not configured with the Client Authentication purpose.".to_string(),
        "297" => "Authentication failed. The certificate does not have a valid name.".to_string(),
        "298" => "Authentication failed. Either the certificate does not contain a valid UPN or the User-Name does not match.".to_string(),
        "299" => "Authentication failed. The sequence of information provided by internal components or protocols is incorrect.".to_string(),
        "300" => "Authentication failed. The certificate is malformed and EAP cannot locate credential information.".to_string(),
        "301" => "NPS terminated the authentication process. Invalid crypto-binding TLV (Potential Man-in-the-Middle).".to_string(),
        "302" => "NPS terminated the authentication process. Missing crypto-binding TLV.".to_string(),
         _ => code.to_string(),
    }
}
