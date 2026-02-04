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
use rust_xlsxwriter::{Workbook, Format}; // Excel Support

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
#[derive(Deserialize)]
struct Root {
    #[serde(rename = "Event", default)]
    events: Vec<Event>,
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

#[derive(Default)]
struct AboutWindow {
    open: bool,
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

#[derive(Clone, Copy)]
struct CellParams<'a> {
    row_index: usize,
    is_selected: bool,
    item: &'a RadiusRequest,
    next_search: &'a Arc<Mutex<Option<String>>>,
    next_status: &'a Arc<Mutex<Option<String>>>,
    text_color: egui::Color32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Timestamp,
    Type,
    Server,
    ApIp,
    ApName,
    Mac,
    User,
    Reason,
}

struct RadiusBrowserApp {
    items: Arc<Vec<RadiusRequest>>, 
    filtered_items: Arc<Vec<RadiusRequest>>,
    status: String,
    search_text: String,
    selected_row: Option<usize>,
    // Store calculated widths: [Time, Type, Server, IP, Name, MAC, User]
    // Reason is remainder.
    col_widths: Vec<f32>,
    layout_version: usize,
    show_errors_only: bool, // New Filter State
    about_window: AboutWindow, // About Window
    sort_column: Option<SortColumn>, // Sorting State
    sort_descending: bool,
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
            sort_column: Some(SortColumn::Timestamp),
            sort_descending: true, // Default: Newest first
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
                if item.resp_type == "Access-Reject" && !item.session_id.is_empty() {
                     failed_session_ids.insert(item.session_id.clone());
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
        
        let mut filtered = filtered; // Make mutable for sorting
        
        // 4. Sorting
        if let Some(col) = self.sort_column {
            match col {
                SortColumn::Timestamp => {
                    filtered.par_sort_unstable_by(|a, b| {
                        let ord = a.timestamp.cmp(&b.timestamp);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
                SortColumn::Type => {
                     filtered.par_sort_unstable_by(|a, b| {
                        let ord = a.req_type.cmp(&b.req_type);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
                SortColumn::Server => {
                     filtered.par_sort_unstable_by(|a, b| {
                        let ord = a.server.cmp(&b.server);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
                SortColumn::ApIp => {
                     filtered.par_sort_unstable_by(|a, b| {
                        let ord = a.ap_ip.cmp(&b.ap_ip);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
                SortColumn::ApName => {
                     filtered.par_sort_unstable_by(|a, b| {
                        let ord = a.ap_name.cmp(&b.ap_name);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
                SortColumn::Mac => {
                     filtered.par_sort_unstable_by(|a, b| {
                        let ord = a.mac.cmp(&b.mac);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
                SortColumn::User => {
                     filtered.par_sort_unstable_by(|a, b| {
                        let ord = a.user.cmp(&b.user);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
                SortColumn::Reason => {
                     filtered.par_sort_unstable_by(|a, b| {
                        let r_a = if a.reason.is_empty() { &a.resp_type } else { &a.reason };
                        let r_b = if b.reason.is_empty() { &b.resp_type } else { &b.reason };
                        let ord = r_a.cmp(r_b);
                        if self.sort_descending { ord.reverse() } else { ord }
                    });
                }
            }
        }
            
        self.filtered_items = Arc::new(filtered);
        self.selected_row = None;
    }

    fn calculate_widths(items: &[RadiusRequest]) -> Vec<f32> {
        let mut max_widths = [130.0, 80.0, 100.0, 100.0, 120.0, 120.0, 100.0, 200.0]; 
        
        // Simple Heuristic due to egui locking changes (text.len() * approx_char_width)
        let approx_char_width = 7.0;

        // Measure Headers first
        let headers = ["Timestamp", "Type", "Server", "AP IP", "AP Name", "MAC", "User", "Result/Reason"];
        for (i, h) in headers.iter().enumerate() {
            let w = f32::from(u16::try_from(h.len()).unwrap_or(u16::MAX)) * approx_char_width;
            if w > max_widths[i] { max_widths[i] = w; }
        }

        // Measure sample
        let sample_limit = 5000;
        for item in items.iter().take(sample_limit) {
             let mut measure = |idx: usize, text: &str| {
                 if !text.is_empty() {
                     let w = f32::from(u16::try_from(text.len()).unwrap_or(u16::MAX)) * approx_char_width;
                     if w > max_widths[idx] { max_widths[idx] = w; }
                 }
             };

             measure(0, &item.timestamp);
             measure(1, &item.req_type);
             measure(2, &item.server);
             measure(3, &item.ap_ip);
             measure(4, &item.ap_name);
             measure(5, &item.mac);
             measure(6, &item.user);
             let reason = if item.reason.is_empty() { &item.resp_type } else { &item.reason };
             measure(7, reason);
        }

        // Add padding + Clamping
        max_widths.iter().map(|w| (w + 24.0).clamp(60.0, 800.0)).collect()
    }

    fn render_top_panel(&mut self, ctx: &egui::Context) -> bool {
        let mut filter_changed = false;
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
                                 let new_widths = Self::calculate_widths(&items); 
                                 self.items = Arc::new(items);
                                 self.col_widths = new_widths; 
                                 self.layout_version += 1; 
                                 self.search_text.clear();
                                 self.show_errors_only = false; 
                                 self.apply_filter();
                                 self.status = format!("Loaded {} requests in {:?}", count, start.elapsed());
                                 self.selected_row = None;
                            }
                            Err(e) => {
                                self.status = format!("Error: {e}");
                            }
                        }
                    }
                }

                ui.separator();
                
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
                
                if !self.search_text.is_empty() && ui.button("❌ Clear").clicked() {
                    self.search_text.clear();
                    filter_changed = true;
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
        filter_changed
    }

    fn handle_keyboard_navigation(&mut self, ctx: &egui::Context) -> Option<usize> {
        if ctx.wants_keyboard_input() {
            return None;
        }

        let total = self.filtered_items.len();
        if total == 0 {
            return None;
        }

        let current = self.selected_row.unwrap_or(0);
        let mut next = current;
        
        let changed = if ctx.input(|i| i.key_pressed(egui::Key::ArrowDown)) && current < total - 1 {
            next = current + 1;
            true
        } else if ctx.input(|i| i.key_pressed(egui::Key::ArrowUp)) && current > 0 {
            next = current - 1;
            true
        } else if ctx.input(|i| i.key_pressed(egui::Key::PageDown)) {
            next = (current + 20).min(total - 1);
            true
        } else if ctx.input(|i| i.key_pressed(egui::Key::PageUp)) {
            next = current.saturating_sub(20);
            true
        } else if ctx.input(|i| i.key_pressed(egui::Key::Home)) {
            next = 0;
            true
        } else if ctx.input(|i| i.key_pressed(egui::Key::End)) && total > 0 {
            next = total - 1;
            true
        } else {
            false
        };

        if changed {
            next = next.min(total.saturating_sub(1));
            self.selected_row = Some(next);
            Some(next)
        } else {
            None
        }
    }

    fn trigger_excel_export(&self, ui: &mut egui::Ui, next_status: &Arc<Mutex<Option<String>>>) {
        if ui.button("📊 Export to Excel").clicked() {
            if let Some(path) = rfd::FileDialog::new().add_filter("Excel", &["xlsx"]).save_file() {
                 let items = self.filtered_items.clone();
                 let path_clone = path;
                 let status_ref = next_status.clone();
                 
                 std::thread::spawn(move || {
                     let mut workbook = Workbook::new();
                     let worksheet = workbook.add_worksheet();
                     let bold = Format::new().set_bold();
                     let headers = ["Timestamp", "Type", "Server", "AP IP", "AP Name", "MAC", "User", "Result/Reason"];
                     for (col, header) in headers.iter().enumerate() {
                         let _ = worksheet.write_with_format(0, u16::try_from(col).unwrap_or(u16::MAX), *header, &bold);
                     }
                     for (row_idx, item) in items.iter().enumerate() {
                         let r = u32::try_from(row_idx + 1).unwrap_or(u32::MAX);
                         let _ = worksheet.write(r, 0, &item.timestamp);
                         let _ = worksheet.write(r, 1, &item.req_type);
                         let _ = worksheet.write(r, 2, &item.server);
                         let _ = worksheet.write(r, 3, &item.ap_ip);
                         let _ = worksheet.write(r, 4, &item.ap_name);
                         let _ = worksheet.write(r, 5, &item.mac);
                         let _ = worksheet.write(r, 6, &item.user);
                         
                         let res_text = if item.reason.is_empty() { 
                             item.resp_type.clone() 
                         } else { 
                             format!("{} ({})", item.resp_type, item.reason) 
                         };
                         let _ = worksheet.write(r, 7, &res_text);
                     }
                     let _ = worksheet.autofit();
                     if let Err(e) = workbook.save(&path_clone) {
                         *status_ref.lock().expect("Lock failed") = Some(format!("Export failed: {e}"));
                     } else {
                         *status_ref.lock().expect("Lock failed") = Some("Export successful!".to_string());
                     }
                 });
            }
        }
    }

    
    fn render_table_cell(
        ui: &egui::Ui,
        text: &str,
        col_name: &str,
        params: CellParams,
    ) -> bool {
        let mut clicked = false;
        let rect = ui.max_rect();
        if params.is_selected {
            ui.painter().rect_filled(rect, 0.0, egui::Color32::from_rgb(0, 120, 215)); 
        } else if let Some(bg) = params.item.bg_color {
            ui.painter().rect_filled(rect, 0.0, bg);
        }
        let response = ui.interact(rect, ui.id().with(params.row_index).with(col_name), egui::Sense::click());
        if response.clicked() {
            clicked = true;
        }
        ui.painter().text(
            rect.min + egui::vec2(4.0, (rect.height() - 13.0) / 2.0),
            egui::Align2::LEFT_TOP,
            text,
            egui::FontId::proportional(13.0),
            params.text_color,
        );
        let text_val = text.to_string();
        let row_tsv = params.item.to_tsv();
        let ns = params.next_search.clone();
        let status_ref = params.next_status.clone();
        response.context_menu(move |ui| {
            ui.add_enabled_ui(true, |ui| {
                if ui.button(format!("Filter by '{}'", &text_val)).clicked() {
                    *ns.lock().expect("Lock failed") = Some(text_val.clone());
                    ui.close();
                }
            });
            ui.separator();
            ui.add_enabled_ui(true, |ui| {
                if ui.button("Copy Cell Value").clicked() {
                    ui.ctx().copy_text(text_val.clone());
                    *status_ref.lock().expect("Lock failed") = Some(format!("Copied to clipboard: '{}'", &text_val));
                    ui.close();
                }
                if ui.button("Copy Entire Row").clicked() {
                    ui.ctx().copy_text(row_tsv.clone());
                    *status_ref.lock().expect("Lock failed") = Some("Row copied to clipboard".to_string());
                    ui.close();
                }
            });
        });
        clicked
    }

    fn render_central_table(&mut self, ctx: &egui::Context, ui: &mut egui::Ui, scroll_target: Option<usize>) {
        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 6.0; 

        let next_search = Arc::new(Mutex::new(None));
        let next_status = Arc::new(Mutex::new(None));
        let next_sort_col = Arc::new(Mutex::new(None));
        let ws = self.col_widths.clone();

        ui.push_id(self.layout_version, |ui| {
            egui::ScrollArea::horizontal()
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .show(ui, |ui| {
                if ctx.input(|i| i.key_down(egui::Key::ArrowRight)) {
                    ui.scroll_with_delta(egui::vec2(-50.0, 0.0)); 
                }
                if ctx.input(|i| i.key_down(egui::Key::ArrowLeft)) {
                    ui.scroll_with_delta(egui::vec2(50.0, 0.0));
                }
                
                self.trigger_excel_export(ui, &next_status);

                let mut table = TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(ws[0]).resizable(true)) 
                    .column(Column::initial(ws[1]).resizable(true)) 
                    .column(Column::initial(ws[2]).resizable(true)) 
                    .column(Column::initial(ws[3]).resizable(true)) 
                    .column(Column::initial(ws[4]).resizable(true)) 
                    .column(Column::initial(ws[5]).resizable(true)) 
                    .column(Column::initial(ws[6]).resizable(true)) 
                    .column(Column::initial(ws[7]).resizable(true)); 

                if let Some(target) = scroll_target {
                    table = table.scroll_to_row(target, Some(egui::Align::Center));
                }

                table.header(22.0, |mut header| {
                    let header_btn = |ui: &mut egui::Ui, text: &str, col: SortColumn| {
                        let is_current = self.sort_column == Some(col);
                        let indicator = if is_current {
                            if self.sort_descending { " ⬇" } else { " ⬆" }
                        } else {
                            ""
                        };
                        let label = format!("{}{}", text, indicator);
                        if ui.button(egui::RichText::new(label).strong()).clicked() {
                            *next_sort_col.lock().expect("Lock failed") = Some(col);
                        }
                    };

                    header.col(|ui| header_btn(ui, "Timestamp", SortColumn::Timestamp));
                    header.col(|ui| header_btn(ui, "Type", SortColumn::Type));
                    header.col(|ui| header_btn(ui, "Server", SortColumn::Server));
                    header.col(|ui| header_btn(ui, "AP IP", SortColumn::ApIp));
                    header.col(|ui| header_btn(ui, "AP Name", SortColumn::ApName));
                    header.col(|ui| header_btn(ui, "MAC", SortColumn::Mac));
                    header.col(|ui| header_btn(ui, "User", SortColumn::User));
                    header.col(|ui| header_btn(ui, "Result/Reason", SortColumn::Reason));
                })
                .body(|body| {
                    let next_sel = Arc::new(Mutex::new(None));
                    body.rows(text_height, self.filtered_items.len(), |mut row| {
                        let row_index = row.index();
                        let item = &self.filtered_items[row_index];
                        let is_selected = self.selected_row == Some(row_index);
                        let text_color = if is_selected {
                            egui::Color32::WHITE
                        } else if ctx.style().visuals.dark_mode {
                            egui::Color32::LIGHT_GRAY
                        } else {
                            egui::Color32::BLACK
                        };
                        let mut params = CellParams {
                            row_index,
                            is_selected,
                            item,
                            next_search: &next_search,
                            next_status: &next_status,
                            text_color,
                        };
                        
                        if item.bg_color.is_some() && !is_selected {
                            params.text_color = egui::Color32::BLACK;
                        }

                        let nsel = &next_sel;

                        row.col(|ui| if Self::render_table_cell(ui, &item.timestamp, "ts", params) { *nsel.lock().expect("Lock failed") = Some(row_index); });
                        row.col(|ui| if Self::render_table_cell(ui, &item.req_type, "type", params) { *nsel.lock().expect("Lock failed") = Some(row_index); });
                        row.col(|ui| if Self::render_table_cell(ui, &item.server, "srv", params) { *nsel.lock().expect("Lock failed") = Some(row_index); });
                        row.col(|ui| if Self::render_table_cell(ui, &item.ap_ip, "ip", params) { *nsel.lock().expect("Lock failed") = Some(row_index); });
                        row.col(|ui| if Self::render_table_cell(ui, &item.ap_name, "ap", params) { *nsel.lock().expect("Lock failed") = Some(row_index); });
                        row.col(|ui| if Self::render_table_cell(ui, &item.mac, "mac", params) { *nsel.lock().expect("Lock failed") = Some(row_index); });
                        row.col(|ui| if Self::render_table_cell(ui, &item.user, "user", params) { *nsel.lock().expect("Lock failed") = Some(row_index); });
                        row.col(|ui| { 
                            let text = if item.reason.is_empty() { &item.resp_type } else { &item.reason };
                            if Self::render_table_cell(ui, text, "res", params) {
                                *nsel.lock().expect("Lock failed") = Some(row_index);
                            }
                        });
                    });
                    let sel = next_sel.lock().expect("Lock failed").take();
                    if let Some(idx) = sel {
                        self.selected_row = Some(idx);
                    }
                });
            });
        });

        let sort_update = next_sort_col.lock().expect("Lock failed").take();
        if let Some(col) = sort_update {
            if self.sort_column == Some(col) {
                self.sort_descending = !self.sort_descending;
            } else {
                self.sort_column = Some(col);
                self.sort_descending = false; // Default to Ascending for new column
                if col == SortColumn::Timestamp {
                    self.sort_descending = true; // Exception: Timestamp default to Descending (Newest first)
                }
            }
            self.apply_filter();
        }

        let ns_update = next_search.lock().expect("Lock failed").take();
        let status_update = next_status.lock().expect("Lock failed").take();
        if let Some(s) = ns_update {
            self.search_text = s;
            self.apply_filter();
        }
        if let Some(msg) = status_update {
            self.status = msg;
        }
    }
}

impl eframe::App for RadiusBrowserApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.render_top_panel(ctx) {
            self.apply_filter();
        }

        let scroll_target = self.handle_keyboard_navigation(ctx);

        // --- Central Panel: Virtual Table ---
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_central_table(ctx, ui, scroll_target);
        });
        
        // Afficher la fenêtre About si ouverte
        self.about_window.show(ctx);
    }
}


fn get_windows_system_font() -> (String, f32) {
    use font_kit::source::SystemSource;
    use font_kit::family_name::FamilyName;
    
    let source = SystemSource::new();
    
    // Récupération de la police système UI
    let family = source.select_best_match(
        &[FamilyName::SansSerif],
        &font_kit::properties::Properties::new()
    ).ok();
    
    if let Some(handle) = family {
        if let Ok(font) = handle.load() {
            // Extraction du nom de famille
            let family_name = font.family_name();
            
            // Taille système Windows standard (9pt = 12px à 96 DPI)
            // font-kit nous donne la métrique native
            let size = 12.0;
            
            return (family_name, size);
        }
    }
    
    // Fallback Windows standard
    ("Segoe UI".to_string(), 12.0)
}
fn main() {
    // Configuration de human-panic pour des rapports de crash professionnels
    human_panic::setup_panic!();
    
    // 1. System Theme Support (Dark/Light auto-detect)
    let force_software = std::env::args().any(|x| x == "--software");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0]),
        // Configuration WGPU pour forcer WARP (Rendu logiciel) ou compatibilité maximale
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
            present_mode: eframe::wgpu::PresentMode::Fifo, // VSync activé
            wgpu_setup: eframe::egui_wgpu::WgpuSetup::CreateNew(
                eframe::egui_wgpu::WgpuSetupCreateNew {
                    instance_descriptor: eframe::wgpu::InstanceDescriptor {
                        backends: eframe::wgpu::Backends::all(),
                        ..Default::default()
                    },
                    native_adapter_selector: Some(std::sync::Arc::new(move |adapters, _surface| {
                       // Select adapter based on preference
                       if force_software {
                           // Try to find Software/CPU adapter (WARP on Windows)
                           // WARP often shows as "Microsoft Basic Render Driver"
                           if let Some(adapter) = adapters.iter().find(|a| a.get_info().device_type == eframe::wgpu::DeviceType::Cpu 
                               || a.get_info().name.contains("Basic Render Driver")
                               || a.get_info().name.contains("llvmpipe")) {
                               println!("Selected Software Adapter via --software: {}", adapter.get_info().name);
                               return Ok(adapter.clone());
                           }
                           eprintln!("Warning: --software specified but no explicit software adapter found. Falling back to default.");
                       }
                       
                       // Default: Prefer Discrete, then Integrated, then whatever
                       let adapter = adapters.iter()
                           .find(|a| a.get_info().device_type == eframe::wgpu::DeviceType::DiscreteGpu)
                           .or_else(|| adapters.iter().find(|a| a.get_info().device_type == eframe::wgpu::DeviceType::IntegratedGpu))
                           .or_else(|| adapters.first());
                           
                       adapter.cloned().ok_or_else(|| "No adapter found".to_owned())
                    })),
                    ..Default::default()
                }
            ),
            ..Default::default()
        },
        ..Default::default()
    };
    
    if let Err(e) = eframe::run_native(
        "Radius Log Browser (System Theme)",
        options,
        Box::new(|cc| {
            // 2. Retro Windows 2000 Styling
            let mut style = (*cc.egui_ctx.style()).clone();
            
            // --- Metrics (Square & Chunky) ---
            style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::ZERO;
            style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::ZERO;
            style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::ZERO;
            style.visuals.widgets.active.corner_radius = egui::CornerRadius::ZERO;
            style.visuals.widgets.open.corner_radius = egui::CornerRadius::ZERO;
            style.visuals.window_corner_radius = egui::CornerRadius::ZERO;
            style.visuals.menu_corner_radius = egui::CornerRadius::ZERO;
            
            // --- Scrollbars (The User wants to SEE them) ---
            style.spacing.scroll.bar_width = 16.0; // Classic Windows width
            style.spacing.scroll.handle_min_length = 20.0;
            style.spacing.scroll.floating = false; // Reserve space!
            
            // Track (Background)
            style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_gray(245); // Very light gray track
            style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_gray(180)); // Scrollbar border
            
            // Handle (The thumb you drag) - Make it much more visible
            style.visuals.widgets.inactive.bg_fill = egui::Color32::from_gray(170); // Darker gray handle
            style.visuals.widgets.hovered.bg_fill = egui::Color32::from_gray(140);  // Even darker when hovered
            style.visuals.widgets.active.bg_fill = egui::Color32::from_gray(110);   // Darkest when clicked
            
            // --- Colors (Classic Gray) ---
            let classic_gray = egui::Color32::from_rgb(212, 208, 200);
            let classic_text = egui::Color32::BLACK;
            let classic_blue = egui::Color32::from_rgb(10, 36, 106);
            let classic_white = egui::Color32::WHITE;

            // Panel / Window Background
            style.visuals.panel_fill = classic_gray;
            style.visuals.window_fill = classic_gray;
            style.visuals.faint_bg_color = classic_gray;
            style.visuals.extreme_bg_color = classic_white; // Input fields white

            // Button / Widget Colors
            style.visuals.widgets.inactive.bg_fill = classic_gray;
            style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, classic_text);
            style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_gray(128)); // Darker gray border
            
            // Hovered
            style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(224, 224, 224); // Slightly lighter
            style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, classic_text);
            style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_gray(64));
            
            // Active (Pressed)
            style.visuals.widgets.active.bg_fill = egui::Color32::from_gray(192);
            style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, classic_text);
            style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, egui::Color32::BLACK);

            // Selection
            style.visuals.selection.bg_fill = classic_blue;
            style.visuals.selection.stroke = egui::Stroke::new(1.0, classic_white);

            // Striped Table
            style.visuals.striped = true;

            // Fonts - Récupération dynamique de la police système Windows
            let mut fonts = egui::FontDefinitions::default();
            let (system_font, system_size) = get_windows_system_font();

            fonts.families.insert(
                egui::FontFamily::Proportional,
                vec![system_font.clone()]
            );
            cc.egui_ctx.set_fonts(fonts);

            style.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(system_size));
            style.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(system_size));
            style.text_styles.insert(egui::TextStyle::Heading, egui::FontId::proportional(system_size * 1.33));
            
            cc.egui_ctx.set_style(style);

            Ok(Box::new(RadiusBrowserApp::default()))
        }),
    ) {
        // CRITICAL FIX: Show a Message Box if the Graphics Engine (WGPU) fails to init
        eprintln!("Fatal Graphics Error: {e}");
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("Fatal Graphics Error")
            .set_description(format!(
                "Failed to initialize graphics engine (WGPU/OpenGL).\n\nError: {e}\n\nTry updating your graphics drivers or use the --software flag."
            ))
            .show();
        std::process::exit(1);
    }
}

fn parse_full_logic(path: &str) -> std::io::Result<Vec<RadiusRequest>> {
    let content = fs::read_to_string(path)?;
    let wrapped_content = format!("<events>{content}</events>");
    

    let root: Root = from_str(&wrapped_content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut events = root.events;
    events.par_sort_unstable_by(|a, b| a.class.cmp(&b.class));
    
    let requests: Vec<RadiusRequest> = events
        .chunk_by(|a, b| a.class == b.class) 
        .map(process_group)
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
                req.timestamp.clone_from(val);
                req.parsed_time = RadiusRequest::parse_timestamp(val);
            }
            if let Some(val) = &event.acct_session_id { req.session_id.clone_from(val); }
            if let Some(val) = &event.server { req.server.clone_from(val); }
            if let Some(val) = &event.ap_ip { req.ap_ip.clone_from(val); }
            if let Some(val) = &event.client_friendly_name { req.ap_name.clone_from(val); }
            else if let Some(val) = &event.ap_name { req.ap_name.clone_from(val); }
            if let Some(val) = &event.mac { req.mac.clone_from(val); }
            if let Some(val) = &event.class { req.class_id.clone_from(val); }
            req.req_type = map_packet_type(p_type);
            if let Some(user) = &event.sam_account { req.user.clone_from(user); } 
            else if let Some(user) = &event.user_name { req.user.clone_from(user); } 
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
         if let Some(c) = &group[0].class { req.class_id.clone_from(c); }
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
        "286" | "295" => "Authentication failed. The CA is not trusted by the NPS server.".to_string(),
        "287" => "Authentication failed. The certificate does not chain to an enterprise root CA that NPS trusts.".to_string(),
        "288" => "Authentication failed due to an unspecified trust failure.".to_string(),
        "289" => "Authentication failed. The certificate provided by the connecting user or computer is revoked.".to_string(),
        "290" => "Authentication failed. A test or trial certificate is in use, however the test root CA is not trusted.".to_string(),
        "291" => "Authentication failed because NPS cannot locate and access the certificate revocation list.".to_string(),
        "292" => "Authentication failed. The User-Name attribute does not match the CN in the certificate.".to_string(),
        "293" | "296" => "Authentication failed. The certificate is not configured with the Client Authentication purpose.".to_string(),
        "294" => "Authentication failed because the certificate was explicitly marked as untrusted by the Administrator.".to_string(),
        "297" => "Authentication failed. The certificate does not have a valid name.".to_string(),
        "298" => "Authentication failed. Either the certificate does not contain a valid UPN or the User-Name does not match.".to_string(),
        "299" => "Authentication failed. The sequence of information provided by internal components or protocols is incorrect.".to_string(),
        "300" => "Authentication failed. The certificate is malformed and EAP cannot locate credential information.".to_string(),
        "301" => "NPS terminated the authentication process. Invalid crypto-binding TLV (Potential Man-in-the-Middle).".to_string(),
        "302" => "NPS terminated the authentication process. Missing crypto-binding TLV.".to_string(),
         _ => code.to_string(),
    }
}









