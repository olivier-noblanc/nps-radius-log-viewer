#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap, clippy::significant_drop_tightening, clippy::nursery, clippy::pedantic, clippy::iter_kv_map)]

use winsafe::prelude::*;
use winsafe::{gui, co, msg};
use quick_xml::de::from_str;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::fs;
use std::collections::{HashMap, HashSet};
use std::thread;

use windows::Win32::UI::WindowsAndMessaging::{SetCursor, LoadCursorW, IDC_WAIT, IDC_ARROW};

// --- Internationalization ---
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n/"]
struct Localizations;

static LANGUAGE_LOADER: OnceLock<FluentLanguageLoader> = OnceLock::new();

const WM_LOAD_DONE: co::WM = unsafe { co::WM::from_raw(co::WM::USER.raw() + 1) };
const WM_LOAD_ERROR: co::WM = unsafe { co::WM::from_raw(co::WM::USER.raw() + 2) };

// --- XML Structures ---
#[derive(Debug, Deserialize, Clone)]
#[serde(rename = "Event")]
struct Event {
    #[serde(rename = "Timestamp")]
    timestamp: Option<String>,
    #[serde(rename = "Packet-Type")]
    packet_type: Option<String>,
    #[serde(rename = "Class")]
    class: Option<String>,
    #[serde(rename = "Acct-Session-Id")]
    acct_session_id: Option<String>,
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
    req_type: String,
    server: String,
    ap_ip: String,
    ap_name: String,
    mac: String,
    user: String,
    resp_type: String,
    reason: String,
    class_id: String,
    session_id: String,
    bg_color: Option<(u8, u8, u8)>, // R, G, B
}

#[derive(Serialize, Deserialize, Clone)]
struct AppConfig {
    window_width: i32,
    window_height: i32,
    column_widths: Vec<i32>,
    visible_columns: Vec<LogColumn>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            window_width: 900,
            window_height: 550,
            column_widths: vec![150, 120, 120, 110, 150, 130, 150, 150, 350, 150],
            visible_columns: LogColumn::all(),
        }
    }
}

impl AppConfig {
    fn load() -> Self {
        let mut cfg: Self = fs::read_to_string("config.json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        // Screen-aware safety clamp
        let screen_cx = winsafe::GetSystemMetrics(co::SM::CXSCREEN);
        let screen_cy = winsafe::GetSystemMetrics(co::SM::CYSCREEN);

        // Clean start for resizing: Force 800x600 if oversized or corrupted
        if cfg.window_width <= 100 || cfg.window_width > screen_cx {
            cfg.window_width = 1000;
        }
        if cfg.window_height <= 100 || cfg.window_height > screen_cy {
            cfg.window_height = 700;
        }
        // Resync visible columns order with the canonical order (to apply the "Type + Reason" change)
        // AND ensure any new columns (like ResponseType) are added if missing from the config file
        let canonical_order = LogColumn::all();
        
        for col in &canonical_order {
            if !cfg.visible_columns.contains(col) {
                cfg.visible_columns.push(col.clone());
            }
        }

        cfg.visible_columns.sort_by_key(|col| {
            canonical_order.iter().position(|c| c == col).unwrap_or(999)
        });
        cfg
    }

    fn save(&self) -> anyhow::Result<()> {
        let s = serde_json::to_string_pretty(self)?;
        fs::write("config.json", s)?;
        Ok(())
    }
}

impl RadiusRequest {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
enum LogColumn {
    Timestamp,
    Type,
    Server,
    ApIp,
    ApName,
    Mac,
    User,
    ResponseType,
    Reason,
    Session,
}

impl LogColumn {
    fn all() -> Vec<Self> {
        vec![
            Self::Timestamp, Self::Type, Self::Server, Self::ApIp,
            Self::ApName, Self::Mac, Self::User, Self::ResponseType, Self::Reason, Self::Session
        ]
    }

    const fn ftl_key(self) -> &'static str {
        match self {
            Self::Timestamp => "col-timestamp",
            Self::Type => "col-type",
            Self::Server => "col-server",
            Self::ApIp => "col-ap-ip",
            Self::ApName => "col-ap-name",
            Self::Mac => "col-mac",
            Self::User => "col-user",
            Self::ResponseType => "col-responsetype",
            Self::Reason => "col-reason",
            Self::Session => "col-session",
        }
    }
}

// --- UI Application ---

#[derive(Clone)]
struct MyWindow {
    wnd:          gui::WindowMain,
    lst_logs:     gui::ListView,
    txt_search:   gui::Edit,
    btn_open:     gui::Button,
    btn_open_folder: gui::Button,
    btn_rejects:  gui::Button,
    cb_append:    gui::CheckBox,
    status_bar:   gui::StatusBar,
    
    all_items:    Arc<Mutex<Vec<RadiusRequest>>>,
    raw_count:    Arc<Mutex<usize>>,
    filtered_ids: Arc<Mutex<Vec<usize>>>,
    show_errors:  Arc<Mutex<bool>>,
    sort_col:     Arc<Mutex<LogColumn>>,
    sort_desc:    Arc<Mutex<bool>>,
    visible_cols: Arc<Mutex<Vec<LogColumn>>>,
    config:       Arc<Mutex<AppConfig>>,
    is_busy:      Arc<AtomicBool>,
    bold_font:    Arc<Mutex<Option<winsafe::guard::DeleteObjectGuard<winsafe::HFONT>>>>,
}

// --- RAII Busy Guard ---
struct BusyGuard {
    is_busy: Arc<AtomicBool>,
}

impl BusyGuard {
    fn new(is_busy: Arc<AtomicBool>) -> Self {
        is_busy.store(true, Ordering::SeqCst);
        Self { is_busy }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.is_busy.store(false, Ordering::SeqCst);
        // Next mouse move will restore the normal cursor automatically.
    }
}

impl MyWindow {
    pub fn new() -> Self {
        let config = AppConfig::load();
        
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let wnd = gui::WindowMain::new(
            gui::WindowMainOpts {
                title: &format!("{}{}", loader.get("ui-title"), loader.get("ui-window-suffix")),
                class_icon: gui::Icon::Id(1),
                size: (config.window_width, config.window_height),
                style: co::WS::CAPTION | co::WS::SYSMENU | co::WS::MINIMIZEBOX | co::WS::MAXIMIZEBOX | co::WS::SIZEBOX | co::WS::VISIBLE | co::WS::CLIPCHILDREN,
                ex_style: co::WS_EX::APPWINDOW,
                ..Default::default()
            },
        );

        let new_self = Self {
            wnd: wnd.clone(),
            lst_logs:     gui::ListView::new(&wnd, gui::ListViewOpts {
                position: (10, 50),
                size: (config.window_width - 20, config.window_height - 90),
                control_style: co::LVS::REPORT | co::LVS::SHOWSELALWAYS | co::LVS::OWNERDATA,
                resize_behavior: (gui::Horz::Resize, gui::Vert::Resize),
                ..Default::default()
            }),
            txt_search:   gui::Edit::new(&wnd, gui::EditOpts {
                position: (400, 14),
                width: 150,
                height: 22,
                ..Default::default()
            }),
            btn_open:     gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("ui-open-log"),
                position: (10, 10),
                width: 120,
                height: 30,
                ..Default::default()
            }),
            btn_open_folder: gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("ui-folder"),
                position: (140, 10),
                width: 120,
                height: 30,
                ..Default::default()
            }),
            btn_rejects:  gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("ui-errors"),
                position: (270, 10),
                width: 120,
                height: 30,
                ..Default::default()
            }),
            cb_append:    gui::CheckBox::new(&wnd, gui::CheckBoxOpts {
                text: &loader.get("ui-append"),
                position: (560, 14),
                size: (80, 20),
                ..Default::default()
            }),
            status_bar:   gui::StatusBar::new(&wnd, &[
                gui::SbPart::Fixed(200),
                gui::SbPart::Proportional(1),
            ]),
            all_items:    Arc::new(Mutex::new(Vec::new())),
            raw_count:    Arc::new(Mutex::new(0)),
            filtered_ids: Arc::new(Mutex::new(Vec::new())),
            show_errors:  Arc::new(Mutex::new(false)),
            sort_col:     Arc::new(Mutex::new(LogColumn::Timestamp)),
            sort_desc:    Arc::new(Mutex::new(true)),
            visible_cols: Arc::new(Mutex::new(config.visible_columns.clone())),
            config:       Arc::new(Mutex::new(config)),
            is_busy:      Arc::new(AtomicBool::new(false)),
            bold_font:    Arc::new(Mutex::new(None::<winsafe::guard::DeleteObjectGuard<winsafe::HFONT>>)),
        };

        new_self.on_wm_events();
        new_self.on_events();
        new_self
    }

    fn on_wm_events(&self) {
        self.wnd.on().wm_close({
            let me = self.clone();
            move || {
                let visible = me.visible_cols.lock().expect("Lock failed").clone();
                let all_cols = LogColumn::all();

                let mut config_save = me.config.lock().expect("Lock failed");
                for (i, &col) in visible.iter().enumerate() {
                    let col_idx = all_cols.iter().position(|&c| c == col).unwrap_or(0);
                    unsafe {
                        if let Ok(width) = me.lst_logs.hwnd().SendMessage(msg::lvm::GetColumnWidth { index: i as u32 }) {
                            if col_idx < config_save.column_widths.len() {
                                config_save.column_widths[col_idx] = width as i32;
                            }
                        }
                    }
                }
                config_save.visible_columns.clone_from(&visible);
                
                let rect = me.wnd.hwnd().GetClientRect().expect("Get window rect failed");
                config_save.window_width = rect.right;
                config_save.window_height = rect.bottom;
                
                let _ = config_save.save();
                
                if let Some(hfont) = me.bold_font.lock().expect("Lock failed").take() {
                    let _ = hfont; // Guard will drop and delete the font
                }

                winsafe::PostQuitMessage(0);
                Ok(())
            }
        });

        self.wnd.on().wm_create({
            let me = self.clone();
            move |_| {
                if let Ok(hicon_guard) = winsafe::HINSTANCE::GetModuleHandle(None).expect("Failed to get module handle").LoadIcon(winsafe::IdIdiStr::Id(1)) {
                     unsafe {
                        let _ = me.wnd.hwnd().SendMessage(msg::wm::SetIcon { hicon: winsafe::HICON::from_ptr(hicon_guard.ptr()), size: co::ICON_SZ::BIG });
                    }
                }

                // Extended styles for ListView
                unsafe {
                    me.lst_logs.hwnd().SendMessage(msg::lvm::SetExtendedListViewStyle {
                        mask: co::LVS_EX::FULLROWSELECT | co::LVS_EX::DOUBLEBUFFER,
                        style: co::LVS_EX::FULLROWSELECT | co::LVS_EX::DOUBLEBUFFER,
                    });
                    // Disable Explorer theme (switch to Classic mode) to ensure background colors work over RDP
                    // let _ = winsafe::HWND::from_ptr(me.lst_logs.hwnd().ptr()).SetWindowTheme("", None);

                    // Create Bold Font
                    let hfont = me.lst_logs.hwnd().SendMessage(msg::wm::GetFont {}).unwrap_or_else(|| {
                        winsafe::HFONT::GetStockObject(co::STOCK_FONT::DEFAULT_GUI).expect("Failed to get default GUI font")
                    });
                    
                    let mut lf = hfont.GetObject().unwrap_or_default();
                    lf.lfWeight = co::FW::BOLD;
                    if let Ok(hfont_bold) = winsafe::HFONT::CreateFontIndirect(&lf) {
                        *me.bold_font.lock().expect("Lock failed") = Some(hfont_bold);
                    }

                }
                
                // Initializing columns dynamically
                me.refresh_columns();

                Ok(0)
            }
        });
        
        self.wnd.on().wm(WM_LOAD_DONE, {
            let me = self.clone();
            move |_| {
                let count = me.filtered_ids.lock().expect("Lock failed").len();
                let raw = *me.raw_count.lock().expect("Lock failed");
                me.lst_logs.items().set_count(count as u32, None).expect("Set count failed");
                
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                let mut args = HashMap::new();
                args.insert("count", count.to_string());
                args.insert("raw", raw.to_string());
                
                let msg = loader.get_args("ui-status-display", args);
                let _ = me.status_bar.parts().get(1).set_text(&clean_tr(&msg));
                let _ = me.status_bar.parts().get(0).set_text("");
                me.lst_logs.hwnd().InvalidateRect(None, true).expect("Invalidate rect failed");
                unsafe {
                    if let Ok(h_cursor) = LoadCursorW(None, IDC_ARROW) {
                        SetCursor(Some(h_cursor));
                    }
                }
                Ok(0)
            }
        });

        self.wnd.on().wm(WM_LOAD_ERROR, {
            let me = self.clone();
            move |_| {
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                let _ = me.status_bar.parts().get(1).set_text(&loader.get("ui-status-error"));
                unsafe {
                    if let Ok(h_cursor) = LoadCursorW(None, IDC_ARROW) {
                        SetCursor(Some(h_cursor));
                    }
                }
                Ok(0)
            }
        });


    }

    fn on_events(&self) {
        self.btn_open.on().bn_clicked({
            let me = self.clone();
            move || me.on_btn_open_clicked()
        });

        self.btn_open_folder.on().bn_clicked({
            let me = self.clone();
            move || me.on_btn_open_folder_clicked()
        });

        self.wnd.on().wm_context_menu({
            let me = self.clone();
            move |p| {
                let h_header = unsafe { me.lst_logs.hwnd().SendMessage(msg::lvm::GetHeader {}) }.unwrap_or(winsafe::HWND::NULL);
                if p.hwnd == *me.lst_logs.hwnd() || p.hwnd == h_header {
                    me.on_lst_context_menu(p.cursor_pos, p.hwnd)?;
                }
                Ok(())
            }
        });

        self.lst_logs.on().lvn_get_disp_info({
            let me = self.clone();
            move |p| me.on_lst_lvn_get_disp_info(p)
        });

        self.lst_logs.on().lvn_column_click({
            let me = self.clone();
            move |p| me.on_lst_lvn_column_click(p)
        });

        self.txt_search.on().en_change({
            let me = self.clone();
            move || me.on_txt_search_en_change()
        });

        self.btn_rejects.on().bn_clicked({
            let me = self.clone();
            move || me.on_btn_rejects_clicked()
        });

        self.lst_logs.on().nm_custom_draw({
            let me = self.clone();
            move |p| Ok(me.on_lst_nm_custom_draw(p))
        });

        // --- HIGH-LEVEL SUBCLASSING FOR WAIT CURSOR ---
        // Only subclass the ListView to avoid interfering with window resizing (borders/frame)
        let is_busy_flag2 = self.is_busy.clone();
        self.lst_logs.on_subclass().wm_set_cursor(move |p| {
            if is_busy_flag2.load(Ordering::SeqCst) && p.hit_test == co::HT::CLIENT {
                unsafe {
                    if let Ok(h_cursor) = LoadCursorW(None, IDC_WAIT) {
                        SetCursor(Some(h_cursor));
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        });
    }

    fn on_btn_open_clicked(&self) -> winsafe::AnyResult<()> {
        let file_dialog = winsafe::CoCreateInstance::<winsafe::IFileOpenDialog>(
            &co::CLSID::FileOpenDialog,
            None::<&winsafe::IUnknown>,
            co::CLSCTX::INPROC_SERVER,
        )?;
        
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let sz_log = loader.get("ui-file-log");
        let sz_all = loader.get("ui-file-all");
        file_dialog.SetFileTypes(&[
            (sz_log.as_str(), "*.log"), 
            (sz_all.as_str(), "*.*")
        ])?;
        
        if file_dialog.Show(self.wnd.hwnd())? {
            let result = file_dialog.GetResult()?;
            let path = result.GetDisplayName(co::SIGDN::FILESYSPATH)?;
            
            // Proactive safety: Clear list view count before background update starts (if not appending)
            if !self.cb_append.is_checked() {
                let _ = self.lst_logs.items().set_count(0, None);
            }
            
            let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
            let _ = self.status_bar.parts().get(1).set_text(&loader.get("ui-status-loading"));
            
            let query = self.txt_search.text().unwrap_or_default();
            let show_err_val = *self.show_errors.lock().expect("Lock failed");
            let sort_col_val = *self.sort_col.lock().expect("Lock failed");
            let sort_desc_val = *self.sort_desc.lock().expect("Lock failed");

            let is_busy_bg = self.is_busy.clone();
            let all_items_bg = self.all_items.clone();
            let raw_count_bg = self.raw_count.clone();
            let filt_ids_bg = self.filtered_ids.clone();
            let is_append = self.cb_append.is_checked();

            let hwnd_raw = self.wnd.hwnd().ptr() as usize;

            thread::spawn(move || {
                let (res, _raw) = {
                    let _busy = BusyGuard::new(is_busy_bg);
                    let _hwnd_bg = unsafe { winsafe::HWND::from_ptr(hwnd_raw as _) };
                    match parse_full_logic(&path) {
                        Ok((items, raw_total)) => {
                            let mut all_guard = all_items_bg.lock().expect("Lock failed");
                            if is_append {
                                all_guard.extend(items);
                            } else {
                                *all_guard = items;
                            }
                            drop(all_guard);
                            
                            let mut raw_guard = raw_count_bg.lock().expect("Lock failed");
                            if is_append {
                                *raw_guard += raw_total;
                            } else {
                                *raw_guard = raw_total;
                            }
                            drop(raw_guard);
    
                            apply_filter_logic(
                                &all_items_bg, 
                                &filt_ids_bg, 
                                &query, 
                                show_err_val,
                                sort_col_val,
                                sort_desc_val
                            );
                            (true, 0)
                        }
                        Err(_) => (false, 0)
                    }
                }; // _busy drops here, so is_busy becomes false BEFORE we post the message
                
                let hwnd_bg = unsafe { winsafe::HWND::from_ptr(hwnd_raw as _) };
                if res {
                    unsafe {
                        let _ = hwnd_bg.PostMessage(msg::WndMsg {
                            msg_id: WM_LOAD_DONE,
                            wparam: 0,
                            lparam: 0,
                        });
                    }
                } else {
                    unsafe {
                        let _ = hwnd_bg.PostMessage(msg::WndMsg {
                            msg_id: WM_LOAD_ERROR,
                            wparam: 0,
                            lparam: 0,
                        });
                    }
                }
            });
        }
        Ok(())
    }

    fn on_btn_open_folder_clicked(&self) -> winsafe::AnyResult<()> {
        let file_dialog = winsafe::CoCreateInstance::<winsafe::IFileOpenDialog>(
            &co::CLSID::FileOpenDialog,
            None::<&winsafe::IUnknown>,
            co::CLSCTX::INPROC_SERVER,
        )?;
        
        file_dialog.SetOptions(file_dialog.GetOptions()? | co::FOS::PICKFOLDERS)?;
        
        if file_dialog.Show(self.wnd.hwnd())? {
            let result = file_dialog.GetResult()?;
            let folder_path = result.GetDisplayName(co::SIGDN::FILESYSPATH)?;
            
            
            // Proactive safety: Clear list view count before background update starts (if not appending)
            if !self.cb_append.is_checked() {
                let _ = self.lst_logs.items().set_count(0, None);
            }
            
            let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
            let _ = self.status_bar.parts().get(1).set_text(&loader.get("ui-status-loading-folder"));
            
            let query = self.txt_search.text().unwrap_or_default();
            let show_err_val = *self.show_errors.lock().expect("Lock failed");
            let sort_col_val = *self.sort_col.lock().expect("Lock failed");
            let sort_desc_val = *self.sort_desc.lock().expect("Lock failed");
            let is_append = self.cb_append.is_checked();

            let is_busy_bg = self.is_busy.clone();
            let all_items_bg = self.all_items.clone();
            let raw_count_bg = self.raw_count.clone();
            let filt_ids_bg = self.filtered_ids.clone();
            let hwnd_raw = self.wnd.hwnd().ptr() as usize;

            thread::spawn(move || {
                let (res, _raw) = {
                    let _busy = BusyGuard::new(is_busy_bg);
                    let _hwnd_bg = unsafe { winsafe::HWND::from_ptr(hwnd_raw as _) };
                    
                    let mut files: Vec<(std::path::PathBuf, std::time::SystemTime)> = Vec::new();
                    if let Ok(entries) = fs::read_dir(&folder_path) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_file() && path.extension().is_some_and(|ext| ext == "log") {
                                if let Ok(meta) = fs::metadata(&path) {
                                    if let Ok(modified) = meta.modified() {
                                        files.push((path, modified));
                                    }
                                }
                            }
                        }
                    }
                    
                    files.sort_by_key(|f| f.1); 
                    
                    let mut total_items = Vec::new();
                    let mut total_raw_count = 0;
                    
                    for (file_path, _) in files {
                        if let Ok((items, raw_c)) = parse_full_logic(file_path.to_str().unwrap_or("")) {
                            total_items.extend(items);
                            total_raw_count += raw_c;
                        }
                    }
    
                    if !total_items.is_empty() {
                         let mut all_guard = all_items_bg.lock().expect("Lock failed");
                        if is_append {
                            all_guard.extend(total_items);
                        } else {
                            *all_guard = total_items;
                        }
                        drop(all_guard);
                        
                        let mut raw_guard = raw_count_bg.lock().expect("Lock failed");
                        if is_append {
                            *raw_guard += total_raw_count;
                        } else {
                            *raw_guard = total_raw_count;
                        }
                        drop(raw_guard);
    
                        apply_filter_logic(
                            &all_items_bg, 
                            &filt_ids_bg, 
                            &query, 
                            show_err_val,
                            sort_col_val,
                            sort_desc_val
                        );
                        (true, 0)
                    } else {
                        (true, 0) // Empty folder is not an error per se
                    }
                }; // _busy drops here
                
                let hwnd_bg = unsafe { winsafe::HWND::from_ptr(hwnd_raw as _) };
                if res {
                    unsafe {
                        let _ = hwnd_bg.PostMessage(msg::WndMsg {
                            msg_id: WM_LOAD_DONE,
                            wparam: 0,
                            lparam: 0,
                        });
                    }
                } else {
                     unsafe {
                        let _ = hwnd_bg.PostMessage(msg::WndMsg {
                            msg_id: WM_LOAD_ERROR,
                            wparam: 0,
                            lparam: 0,
                        });
                    }
                }
            });
        }
        Ok(())
    }

    fn on_lst_context_menu(&self, pt_screen: winsafe::POINT, _target_hwnd: winsafe::HWND) -> winsafe::AnyResult<()> {
        let h_header = unsafe { self.lst_logs.hwnd().SendMessage(msg::lvm::GetHeader {}) }.unwrap_or(winsafe::HWND::NULL);
        
        // Priority 1: Physical check of header area
        let rc_header = h_header.GetWindowRect().unwrap_or_default();
        if pt_screen.x >= rc_header.left && pt_screen.x <= rc_header.right
            && pt_screen.y >= rc_header.top && pt_screen.y <= rc_header.bottom {
            self.show_column_context_menu()?;
            return Ok(());
        }

        let pt_client = self.lst_logs.hwnd().ScreenToClient(pt_screen).expect("ScreenToClient failed");
        let mut lvhti = winsafe::LVHITTESTINFO {
            pt: pt_client,
            ..Default::default()
        };

        if unsafe { self.lst_logs.hwnd().SendMessage(msg::lvm::HitTest { info: &mut lvhti }).is_some() }
            && lvhti.iItem != -1 {
                // Cell menu
                let h_menu = winsafe::HMENU::CreatePopupMenu()?;
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1001), winsafe::BmpPtrStr::from_str(&clean_tr(&loader.get("ui-menu-copy-cell"))))?;
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1003), winsafe::BmpPtrStr::from_str(&clean_tr(&loader.get("ui-menu-copy-row"))))?;
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1002), winsafe::BmpPtrStr::from_str(&clean_tr(&loader.get("ui-menu-filter-cell"))))?;

                if let Some(cmd_id) = h_menu.TrackPopupMenu(co::TPM::RETURNCMD | co::TPM::LEFTALIGN, pt_screen, self.lst_logs.hwnd())? {
                    match cmd_id {
                        1001 => { 
                            let cell_text = self.lst_logs.items().get(lvhti.iItem as _).text(lvhti.iSubItem as _);
                            let _ = clipboard_win::set_clipboard_string(&cell_text); 
                        },
                        1002 => {
                            let cell_text = self.lst_logs.items().get(lvhti.iItem as _).text(lvhti.iSubItem as _);
                            let _ = self.txt_search.hwnd().SetWindowText(&cell_text);
                            self.on_txt_search_en_change()?;
                        },
                        1003 => {
                            let items = self.all_items.lock().expect("Lock failed");
                            let ids = self.filtered_ids.lock().expect("Lock failed");
                            if let Some(&idx) = ids.get(lvhti.iItem as usize) {
                                let tsv = items[idx].to_tsv();
                                let _ = clipboard_win::set_clipboard_string(&tsv);
                            }
                        }
                        _ => {}
                    }
                }
        } else {
            // Background or Header edge cases - show column menu
            self.show_column_context_menu()?;
        }
        Ok(())
    }

    fn show_column_context_menu(&self) -> winsafe::AnyResult<isize> {
        let h_menu = winsafe::HMENU::CreatePopupMenu()?;
        let all_cols = LogColumn::all();
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        
        // Clone visible list and release lock immediately to avoid deadlocks while menu is open
        let visible_now = self.visible_cols.lock().expect("Lock failed").clone();

        for (i, col) in all_cols.iter().enumerate() {
            let is_visible = visible_now.contains(col);
            let mut flags = co::MF::STRING;
            if is_visible {
                flags |= co::MF::CHECKED;
            }
            let text = clean_tr(&loader.get(col.ftl_key()));
            h_menu.AppendMenu(flags, winsafe::IdMenu::Id(2000 + i as u16), winsafe::BmpPtrStr::from_str(&text))?;
        }

        let pt = winsafe::GetCursorPos().expect("GetCursorPos failed");
        if let Some(cmd_id) = h_menu.TrackPopupMenu(co::TPM::RETURNCMD | co::TPM::LEFTALIGN, pt, self.wnd.hwnd())? {
            let col_idx = (cmd_id - 2000) as usize;
            if col_idx < all_cols.len() {
                let clicked_col = all_cols[col_idx];
                self.toggle_column_visibility(clicked_col);
            }
        }
        Ok(0)
    }

    fn toggle_column_visibility(&self, col: LogColumn) {
        println!("Toggling column visibility: {col:?}");
        let mut visible = self.visible_cols.lock().expect("Lock failed");
        if visible.contains(&col) {
            if visible.len() > 1 { 
                visible.retain(|&c| c != col);
            }
        } else {
            let all_cols = LogColumn::all();
            let mut new_visible = Vec::new();
            for &c in &all_cols {
                if visible.contains(&c) || c == col {
                    new_visible.push(c);
                }
            }
            *visible = new_visible;
        }
        drop(visible);
        self.refresh_columns();
        let _ = self.on_txt_search_en_change();
    }

    #[allow(clippy::unnecessary_wraps)]
    fn on_lst_lvn_get_disp_info(&self, p: &winsafe::NMLVDISPINFO) -> winsafe::AnyResult<()> {
        let item_idx = p.item.iItem;
        let real_idx = {
            let filtered = self.filtered_ids.lock().expect("Lock failed");
            if item_idx < 0 || item_idx >= filtered.len() as i32 { return Ok(()); }
            filtered[item_idx as usize]
        };

        let log_col = {
            let visible = self.visible_cols.lock().expect("Lock failed");
            let col_idx = p.item.iSubItem;
            let Some(&c) = visible.get(col_idx as usize) else { return Ok(()); };
            c
        };

        let items = self.all_items.lock().expect("Lock failed");
        if real_idx >= items.len() { return Ok(()); }
        let req = &items[real_idx];

        let text = match log_col {
            LogColumn::Timestamp => req.timestamp.clone(),
            LogColumn::Type => req.req_type.clone(),
            LogColumn::Server => req.server.clone(),
            LogColumn::ApIp => req.ap_ip.clone(),
            LogColumn::ApName => req.ap_name.clone(),
            LogColumn::Mac => req.mac.clone(),
            LogColumn::User => req.user.clone(),
            LogColumn::ResponseType => req.resp_type.clone(),
            LogColumn::Reason => req.reason.clone(),
            LogColumn::Session => req.session_id.clone(),
        };

        use std::cell::RefCell;
        thread_local! {
            static DATA: RefCell<winsafe::WString> = const { RefCell::new(winsafe::WString::new()) };
        }

        DATA.with(|buf| {
            let mut buf_guard = buf.borrow_mut();
            *buf_guard = winsafe::WString::from_str(text);
            let p_ptr = std::ptr::from_ref(p) as *mut winsafe::NMLVDISPINFO;
            unsafe {
                (*p_ptr).item.mask |= co::LVIF::TEXT;
                (*p_ptr).item.set_pszText(Some(&mut buf_guard));
            }
        });
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn on_lst_lvn_column_click(&self, p: &winsafe::NMLISTVIEW) -> winsafe::AnyResult<()> {
        let mut sort_col_g = self.sort_col.lock().expect("Lock failed");
        let mut sort_desc_g = self.sort_desc.lock().expect("Lock failed");

        let visible = self.visible_cols.lock().expect("Lock failed");
        let Some(&new_col) = visible.get(p.iSubItem as usize) else {
            return Ok(());
        };
        drop(visible);

        if *sort_col_g == new_col {
            *sort_desc_g = !*sort_desc_g;
        } else {
            *sort_col_g = new_col;
            *sort_desc_g = false;
        }
        
        let cur_query = self.txt_search.text().unwrap_or_default();
        let cur_show_err = *self.show_errors.lock().expect("Lock failed");
        let cur_sort_col = *sort_col_g;
        let cur_sort_desc = *sort_desc_g;
        
        apply_filter_logic(
            &self.all_items, 
            &self.filtered_ids, 
            &cur_query, 
            cur_show_err,
            cur_sort_col,
            cur_sort_desc
        );
        self.lst_logs.items().set_count(self.filtered_ids.lock().expect("Lock failed").len() as _, None)?;
        drop(sort_col_g);
        drop(sort_desc_g);
        self.update_headers();
        let _ = self.lst_logs.hwnd().InvalidateRect(None, true);
        Ok(())
    }

    fn on_txt_search_en_change(&self) -> winsafe::AnyResult<()> {
        let query = self.txt_search.text().unwrap_or_default();
        let show_err = *self.show_errors.lock().expect("Lock failed");
        let sort_col_val = *self.sort_col.lock().expect("Lock failed");
        let sort_desc_val = *self.sort_desc.lock().expect("Lock failed");

        apply_filter_logic(
            &self.all_items, 
            &self.filtered_ids, 
            &query, 
            show_err,
            sort_col_val,
            sort_desc_val
        );
        self.lst_logs.items().set_count(self.filtered_ids.lock().expect("Lock failed").len() as _, None)?;
        let _ = self.lst_logs.hwnd().InvalidateRect(None, true);
        Ok(())
    }

    fn on_btn_rejects_clicked(&self) -> winsafe::AnyResult<()> {
        let mut show_err_g = self.show_errors.lock().expect("Lock failed");
        *show_err_g = !*show_err_g;
        let is_on = *show_err_g;
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let txt = if is_on { loader.get("ui-btn-show-all") } else { loader.get("ui-btn-errors-only") };
        let _ = self.btn_rejects.hwnd().SetWindowText(&txt);
        drop(show_err_g);
        
        let query = self.txt_search.text().unwrap_or_default();
        let sort_col_v = *self.sort_col.lock().expect("Lock failed");
        let sort_desc_v = *self.sort_desc.lock().expect("Lock failed");
        
        apply_filter_logic(
            &self.all_items, 
            &self.filtered_ids, 
            &query, 
            is_on,
            sort_col_v,
            sort_desc_v
        );
        self.lst_logs.items().set_count(self.filtered_ids.lock().expect("Lock failed").len() as _, None)?;
        let _ = self.lst_logs.hwnd().InvalidateRect(None, true);
        Ok(())
    }


    fn on_lst_nm_custom_draw(&self, p: &winsafe::NMLVCUSTOMDRAW) -> co::CDRF {
        match p.mcd.dwDrawStage {
            co::CDDS::PREPAINT => co::CDRF::NOTIFYITEMDRAW,
            co::CDDS::ITEMPREPAINT => {
                let color = {
                    let items = self.all_items.lock().expect("Lock failed");
                    let ids = self.filtered_ids.lock().expect("Lock failed");
                    ids.get(p.mcd.dwItemSpec).and_then(|&idx| items[idx].bg_color)
                };
                if let Some(clr) = color {
                    let color_ref = winsafe::COLORREF::from_rgb(clr.0, clr.1, clr.2);
                    
                    // Force GDI background fill (Hyper-V/RDP safety)
                    if let Ok(brush) = winsafe::HBRUSH::CreateSolidBrush(color_ref) {
                        let _ = p.mcd.hdc.FillRect(p.mcd.rc, &brush);
                    }

                    // Select Bold Font
                    if let Some(hfont_guard) = self.bold_font.lock().expect("Lock failed").as_ref() {
                        let _ = p.mcd.hdc.SelectObject(&**hfont_guard);
                    }

                    let p_ptr = std::ptr::from_ref(p).cast_mut();
                    unsafe {
                        (*p_ptr).clrTextBk = color_ref;
                        
                        // Use dark colors for better contrast and requested style
                        let text_color = if clr == (220, 255, 220) {
                            winsafe::COLORREF::from_rgb(0, 64, 0) // Very Dark Green
                        } else if clr == (255, 220, 220) {
                            winsafe::COLORREF::from_rgb(102, 0, 0) // Very Dark Red
                        } else if clr.0 as u16 + clr.1 as u16 + clr.2 as u16 > 380 { 
                            winsafe::COLORREF::from_rgb(0, 0, 0)
                        } else {
                            winsafe::COLORREF::from_rgb(255, 255, 255)
                        };
                        (*p_ptr).clrText = text_color;
                        
                        let _ = p.mcd.hdc.SetBkColor(color_ref);
                        let _ = p.mcd.hdc.SetTextColor(text_color);
                    }
                    unsafe { co::CDRF::from_raw(co::CDRF::NOTIFYSUBITEMDRAW.raw() | co::CDRF::NEWFONT.raw()) }
                } else {
                    co::CDRF::NOTIFYSUBITEMDRAW
                }
            },
            _ if p.mcd.dwDrawStage.raw() == co::CDDS::ITEMPREPAINT.raw() | co::CDDS::SUBITEM.raw() => {
                let color = {
                    let items = self.all_items.lock().expect("Lock failed");
                    let ids = self.filtered_ids.lock().expect("Lock failed");
                    ids.get(p.mcd.dwItemSpec).and_then(|&idx| items[idx].bg_color)
                };
                
                if let Some(clr) = color {
                    let color_ref = winsafe::COLORREF::from_rgb(clr.0, clr.1, clr.2);
                    
                    // Select Bold Font for subitems too
                    if let Some(hfont_guard) = self.bold_font.lock().expect("Lock failed").as_ref() {
                        let _ = p.mcd.hdc.SelectObject(&**hfont_guard);
                    }

                    let p_ptr = std::ptr::from_ref(p).cast_mut();
                    unsafe {
                        (*p_ptr).clrTextBk = color_ref;
                        
                        let text_color = if clr == (220, 255, 220) {
                            winsafe::COLORREF::from_rgb(0, 64, 0) // Very Dark Green
                        } else if clr == (255, 220, 220) {
                            winsafe::COLORREF::from_rgb(102, 0, 0) // Very Dark Red
                        } else if clr.0 as u16 + clr.1 as u16 + clr.2 as u16 > 380 { 
                            winsafe::COLORREF::from_rgb(0, 0, 0)
                        } else {
                            winsafe::COLORREF::from_rgb(255, 255, 255)
                        };
                        (*p_ptr).clrText = text_color;
                        
                        let _ = p.mcd.hdc.SetBkColor(color_ref);
                        let _ = p.mcd.hdc.SetTextColor(text_color);
                    }
                    co::CDRF::NEWFONT 
                } else {
                    co::CDRF::DODEFAULT
                }
            },
            _ => co::CDRF::DODEFAULT,
        }
    }

    pub fn run(&self) -> winsafe::AnyResult<i32> {
        self.wnd.run_main(None)
    }

    fn refresh_columns(&self) {
        while self.lst_logs.cols().count().unwrap_or(0) > 0 {
            unsafe {
                let _ = self.lst_logs.hwnd().SendMessage(msg::lvm::DeleteColumn { index: 0 });
            }
        }
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let visible = self.visible_cols.lock().expect("Lock failed").clone();
        let all_cols = LogColumn::all();
        
        {
            let config = self.config.lock().expect("Lock failed");
            for &col in &visible {
                let col_idx = all_cols.iter().position(|&c| c == col).unwrap_or(0);
                let width = config.column_widths.get(col_idx).copied().filter(|&w| w > 0).unwrap_or(150);
                let text = clean_tr(&loader.get(col.ftl_key()));
                self.lst_logs.cols().add(&text, width).expect("Add col failed");
            }
        }
        self.update_headers();
        let _ = self.lst_logs.hwnd().InvalidateRect(None, true);
    }
    fn update_headers(&self) {
        let h_header = unsafe { self.lst_logs.hwnd().SendMessage(msg::lvm::GetHeader {}) }.unwrap_or(winsafe::HWND::NULL);
        if h_header == winsafe::HWND::NULL { return; }

        let (visible, sort_col, sort_desc) = {
            let v = self.visible_cols.lock().expect("Lock failed").clone();
            let sc = *self.sort_col.lock().expect("Lock failed");
            let sd = *self.sort_desc.lock().expect("Lock failed");
            (v, sc, sd)
        };

        let count = unsafe { h_header.SendMessage(msg::hdm::GetItemCount {}) }.unwrap_or(0);

        for i in 0..count {
            let mut hdi = winsafe::HDITEM::default();
            hdi.mask = co::HDI::FORMAT;
            
            unsafe { h_header.SendMessage(msg::hdm::GetItem { index: i as _, hditem: &mut hdi }) };
            
            hdi.fmt &= !(co::HDF::SORTUP | co::HDF::SORTDOWN); // Clear existing sort flags
            
            if let Some(&col) = visible.get(i as usize) {
                if col == sort_col {
                    hdi.fmt |= if sort_desc { co::HDF::SORTDOWN } else { co::HDF::SORTUP };
                }
            }
            
            let _ = unsafe { h_header.SendMessage(msg::hdm::SetItem { index: i as _, hditem: &hdi }) };
        }
    }
}

// --- LOGIC FUNCTIONS ---

fn apply_filter_logic(
    all_items: &Arc<Mutex<Vec<RadiusRequest>>>,
    filtered_ids: &Arc<Mutex<Vec<usize>>>,
    query: &str,
    show_errors_only: bool,
    sort_col: LogColumn,
    sort_descending: bool,
) {
    let q = query.trim().to_lowercase();
    
    let ids: Vec<usize> = {
        let items = all_items.lock().expect("Lock failed");
        
        let mut failed_session_ids = HashSet::new();
        if show_errors_only {
            for item in items.iter() {
                if item.resp_type == "Access-Reject" && !item.session_id.is_empty() {
                    failed_session_ids.insert(item.session_id.clone());
                }
            }
        }

        let mut ids: Vec<usize> = (0..items.len())
            .filter(|&i| {
                let item = &items[i];
                if show_errors_only {
                    if item.session_id.is_empty() || !failed_session_ids.contains(&item.session_id) {
                        return false;
                    }
                    if item.resp_type == "Access-Accept" || item.resp_type == "Accounting-Response" {
                        return false;
                    }
                }
                if q.is_empty() { return true; }
                item.matches(&q)
            })
            .collect();

        // Sorting
        ids.sort_unstable_by(|&a_idx, &b_idx| {
            let a = &items[a_idx];
            let b = &items[b_idx];
            let ord = match sort_col {
                LogColumn::Timestamp => a.timestamp.cmp(&b.timestamp),
                LogColumn::Type => a.req_type.cmp(&b.req_type),
                LogColumn::Server => a.server.cmp(&b.server),
                LogColumn::ApIp => a.ap_ip.cmp(&b.ap_ip),
                LogColumn::ApName => a.ap_name.cmp(&b.ap_name),
                LogColumn::Mac => a.mac.cmp(&b.mac),
                LogColumn::User => a.user.cmp(&b.user),
                LogColumn::ResponseType => a.resp_type.cmp(&b.resp_type),
                LogColumn::Reason => {
                    let r_a = if a.reason.is_empty() { &a.resp_type } else { &a.reason };
                    let r_b = if b.reason.is_empty() { &b.resp_type } else { &b.reason };
                    r_a.cmp(r_b)
                }
                LogColumn::Session => a.session_id.cmp(&b.session_id),
            };
            if sort_descending { ord.reverse() } else { ord }
        });
        drop(items);
        ids
    };

    let mut filt_guard = filtered_ids.lock().expect("Lock failed");
    *filt_guard = ids;
}


fn parse_full_logic(path: &str) -> anyhow::Result<(Vec<RadiusRequest>, usize)> {
    let content = fs::read_to_string(path)?;
    
    use quick_xml::reader::Reader;
    use quick_xml::events::Event as XmlEvent;

    let mut reader = Reader::from_str(&content);
    let mut buf = Vec::new();
    let mut event_blobs = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) if e.name().as_ref() == b"Event" => {
                let start_pos = reader.buffer_position() - (e.name().as_ref().len() as u64) - 2;
                reader.read_to_end_into(e.name(), &mut Vec::new())?;
                let end_pos = reader.buffer_position();
                event_blobs.push(content[start_pos as usize..end_pos as usize].to_string());
            }
            Ok(XmlEvent::Eof) => break,
            _ => (),
        }
        buf.clear();
    }

    let events_all: Vec<Event> = event_blobs.into_par_iter()
        .filter_map(|blob| from_str::<Event>(&blob).ok())
        .collect();

    let raw_event_count = events_all.len();
    if events_all.is_empty() {
        return Ok((Vec::new(), 0));
    }

    // Grouping events logic
    let mut groups: Vec<Vec<Event>> = Vec::new();
    let mut class_map: HashMap<String, usize> = HashMap::new();

    for ev in events_all {
        let key_opt = ev.class.as_deref()
            .or(ev.acct_session_id.as_deref())
            .filter(|s: &&str| !s.is_empty());
        
        if let Some(k) = key_opt {
            if let Some(&idx) = class_map.get(k) {
                groups[idx].push(ev);
            } else {
                class_map.insert(k.to_string(), groups.len());
                groups.push(vec![ev]);
            }
        } else {
            groups.push(vec![ev]);
        }
    }

    let requests: Vec<RadiusRequest> = groups.into_par_iter()
        .map(|g| process_group(&g))
        .collect();
        
    Ok((requests, raw_event_count))
}

fn process_group(group: &[Event]) -> RadiusRequest {
    let mut req = RadiusRequest::default();
    for event in group {
        let p_type = event.packet_type.as_deref().unwrap_or("");
        if p_type == "1" || p_type == "4" {
            if let Some(val) = &event.timestamp { req.timestamp.clone_from(val); }
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
            else { 
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                req.user = loader.get("ui-unknown-user"); 
            }
        } else {
            let this_resp_type = map_packet_type(p_type);
            let code = event.reason_code.as_deref().unwrap_or("0");
            // If this is a better reason (error vs success) or we have nothing yet
            if req.reason.is_empty() || code != "0" {
                 req.resp_type = this_resp_type.clone();
                 req.reason = map_reason(code);
            }
            match p_type {
                "2" => req.bg_color = Some((220, 255, 220)), // Pastel light green
                "3" => req.bg_color = Some((255, 220, 220)), // Pastel light red
                _ => {},
            }
        }
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
        _ => format!("Type {code}"),
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
        _ => format!("Code {code}")
    }
}

fn clean_tr(s: &str) -> String {
    s.chars().filter(|&c| !('\u{2066}'..='\u{2069}').contains(&c)).collect()
}

fn main() {
    let loader: FluentLanguageLoader = fluent_language_loader!();
    loader.set_use_isolating(false);
    
    // Choose requested languages based on system locale
    let requested_languages = DesktopLanguageRequester::requested_languages();
    let _ = i18n_embed::select(&loader, &Localizations, &requested_languages);
    
    LANGUAGE_LOADER.set(loader).ok();

    let app = MyWindow::new();
    if let Err(e) = app.run() {
        eprintln!("{e}");
    }
}
