#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap, clippy::significant_drop_tightening, clippy::nursery, clippy::pedantic, clippy::iter_kv_map)]

use winsafe::prelude::*;
use winsafe::{gui, co, msg};
use quick_xml::de::from_str;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};
use std::fs;
use std::collections::{HashMap, HashSet};
use std::thread;

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

#[derive(Deserialize)]
struct Root {
    #[serde(rename = "Event", default)]
    events: Vec<Event>,
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
            column_widths: vec![150, 120, 120, 110, 150, 130, 150, 350, 150],
            visible_columns: LogColumn::all(),
        }
    }
}

impl AppConfig {
    fn load() -> Self {
        fs::read_to_string("config.json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
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
    Reason,
    Session,
}

impl LogColumn {
    fn all() -> Vec<Self> {
        vec![
            Self::Timestamp, Self::Type, Self::Server, Self::ApIp,
            Self::ApName, Self::Mac, Self::User, Self::Reason, Self::Session
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
            Self::Reason => "col-reason",
            Self::Session => "col-session",
        }
    }
}

// --- FFI for SetCursor (missing in winsafe 0.0.27) ---
extern "system" {
    fn SetCursor(hcursor: winsafe::HCURSOR) -> winsafe::HCURSOR;
}

/// RAII helper to show wait cursor.
struct BusyCursor;

impl BusyCursor {
    fn new() -> Self {
        if let Ok(hcursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::WAIT)) {
            unsafe { SetCursor(hcursor.raw_copy()); }
        }
        Self
    }
}

impl Drop for BusyCursor {
    fn drop(&mut self) {
        if let Ok(hcursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::ARROW)) {
            unsafe { SetCursor(hcursor.raw_copy()); }
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
    btn_copy:     gui::Button,
    lbl_status:   gui::Label,
    
    all_items:    Arc<Mutex<Vec<RadiusRequest>>>,
    raw_count:    Arc<Mutex<usize>>,
    filtered_ids: Arc<Mutex<Vec<usize>>>,
    show_errors:  Arc<Mutex<bool>>,
    sort_col:     Arc<Mutex<LogColumn>>,
    sort_desc:    Arc<Mutex<bool>>,
    visible_cols: Arc<Mutex<Vec<LogColumn>>>,
    config:       Arc<Mutex<AppConfig>>,
    is_busy:      Arc<Mutex<bool>>,
    bold_font:    Arc<Mutex<Option<winsafe::guard::DeleteObjectGuard<winsafe::HFONT>>>>,
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
                ..Default::default()
            },
        );

        let new_self = Self {
            wnd: wnd.clone(),
            lst_logs:     gui::ListView::new(&wnd, gui::ListViewOpts {
                position: (10, 50),
                size: (config.window_width - 20, config.window_height - 90),
                control_style: co::LVS::REPORT | co::LVS::NOSORTHEADER | co::LVS::SHOWSELALWAYS | co::LVS::OWNERDATA,
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
            btn_copy:     gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("ui-copy"),
                position: (650, 10),
                width: 100,
                height: 30,
                ..Default::default()
            }),
            lbl_status:   gui::Label::new(&wnd, gui::LabelOpts {
                text: &loader.get("ui-status-ready"),
                position: (10, config.window_height - 30),
                size: (400, 20),
                resize_behavior: (gui::Horz::None, gui::Vert::Repos),
                ..Default::default()
            }),
            all_items:    Arc::new(Mutex::new(Vec::new())),
            raw_count:    Arc::new(Mutex::new(0)),
            filtered_ids: Arc::new(Mutex::new(Vec::new())),
            show_errors:  Arc::new(Mutex::new(false)),
            sort_col:     Arc::new(Mutex::new(LogColumn::Timestamp)),
            sort_desc:    Arc::new(Mutex::new(true)),
            visible_cols: Arc::new(Mutex::new(config.visible_columns.clone())),
            config:       Arc::new(Mutex::new(config)),
            is_busy:      Arc::new(Mutex::new(false)),
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
                let mut config_save = me.config.lock().expect("Lock failed");
                let visible = me.visible_cols.lock().expect("Lock failed");
                let all_cols = LogColumn::all();

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
                drop(visible);
                
                let rect = me.wnd.hwnd().GetWindowRect().expect("Get window rect failed");
                config_save.window_width = rect.right - rect.left;
                config_save.window_height = rect.bottom - rect.top;
                
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
                    let _ = winsafe::HWND::from_ptr(me.lst_logs.hwnd().ptr()).SetWindowTheme("", None);

                    // Create Bold Font
                    if let Some(hfont) = me.lst_logs.hwnd().SendMessage(msg::wm::GetFont {}) {
                        let mut lf = hfont.GetObject().unwrap_or_default();
                        lf.lfWeight = co::FW::BOLD;
                        if let Ok(hfont_bold) = winsafe::HFONT::CreateFontIndirect(&lf) {
                            *me.bold_font.lock().expect("Lock failed") = Some(hfont_bold);
                        }
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
                *me.is_busy.lock().expect("Lock failed") = false;
                if let Ok(hcursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::ARROW)) {
                    unsafe { SetCursor(hcursor.raw_copy()); }
                }
                
                let count = me.filtered_ids.lock().expect("Lock failed").len();
                let raw_str = me.raw_count.lock().expect("Lock failed").to_string();
                me.lst_logs.items().set_count(count as u32, None).expect("Set count failed");
                
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                let count_str = count.to_string();
                
                let status_fmt = clean_tr(&loader.get("ui-status-display"))
                    .replace("{ $count }", &count_str)
                    .replace("{$count}", &count_str)
                    .replace("{ $raw }", &raw_str)
                    .replace("{$raw}", &raw_str);
                
                let _ = me.lbl_status.hwnd().SetWindowText(&status_fmt);
                me.lst_logs.hwnd().InvalidateRect(None, true).expect("Invalidate rect failed");
                Ok(0)
            }
        });

        self.wnd.on().wm(WM_LOAD_ERROR, {
            let me = self.clone();
            move |_| {
                *me.is_busy.lock().expect("Lock failed") = false;
                if let Ok(hcursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::ARROW)) {
                    unsafe { SetCursor(hcursor.raw_copy()); }
                }
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                let _ = me.lbl_status.hwnd().SetWindowText(&loader.get("ui-status-error"));
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

        self.btn_copy.on().bn_clicked({
            let me = self.clone();
            move || me.on_btn_copy_clicked()
        });

        self.lst_logs.on().nm_custom_draw({
            let me = self.clone();
            move |p| Ok(me.on_lst_nm_custom_draw(p))
        });

        self.wnd.on().wm_set_cursor({
            let me = self.clone();
            move |p| {
                if p.hit_test != co::HT::CLIENT {
                    return Ok(false); // Let system handle border cursors
                }
                if *me.is_busy.lock().expect("Lock failed") {
                    if let Ok(hcursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::WAIT)) {
                        unsafe { SetCursor(hcursor.raw_copy()); }
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
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
            
            let _busy = BusyCursor::new();
            *self.is_busy.lock().expect("Lock failed") = true;
            
            let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
            let _ = self.lbl_status.hwnd().SetWindowText(&loader.get("ui-status-loading"));
            
            let query = self.txt_search.text().unwrap_or_default();
            let show_err_val = *self.show_errors.lock().expect("Lock failed");
            let sort_col_val = *self.sort_col.lock().expect("Lock failed");
            let sort_desc_val = *self.sort_desc.lock().expect("Lock failed");

            let all_items_bg = self.all_items.clone();
            let raw_count_bg = self.raw_count.clone();
            let filt_ids_bg = self.filtered_ids.clone();
            let is_append = self.cb_append.is_checked();

            let hwnd_raw = self.wnd.hwnd().ptr() as usize;

            thread::spawn(move || {
                let hwnd_bg = unsafe { winsafe::HWND::from_ptr(hwnd_raw as _) };
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
                        
                        unsafe {
                            let _ = hwnd_bg.PostMessage(msg::WndMsg {
                                msg_id: WM_LOAD_DONE,
                                wparam: 0,
                                lparam: 0,
                            });
                        }
                    }
                    Err(_) => {
                        unsafe {
                            let _ = hwnd_bg.PostMessage(msg::WndMsg {
                                msg_id: WM_LOAD_ERROR,
                                wparam: 0,
                                lparam: 0,
                            });
                        }
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
            
            let _busy = BusyCursor::new();
            *self.is_busy.lock().expect("Lock failed") = true;
            
            let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
            let _ = self.lbl_status.hwnd().SetWindowText(&loader.get("ui-status-loading-folder"));
            
            let query = self.txt_search.text().unwrap_or_default();
            let show_err_val = *self.show_errors.lock().expect("Lock failed");
            let sort_col_val = *self.sort_col.lock().expect("Lock failed");
            let sort_desc_val = *self.sort_desc.lock().expect("Lock failed");
            let is_append = self.cb_append.is_checked();

            let all_items_bg = self.all_items.clone();
            let raw_count_bg = self.raw_count.clone();
            let filt_ids_bg = self.filtered_ids.clone();
            let hwnd_raw = self.wnd.hwnd().ptr() as usize;

            thread::spawn(move || {
                let hwnd_bg = unsafe { winsafe::HWND::from_ptr(hwnd_raw as _) };
                
                let mut files = Vec::new();
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
                let mut total_raw = 0;
                
                for (path, _) in files {
                    if let Ok((items, raw)) = parse_full_logic(&path.to_string_lossy()) {
                        total_items.extend(items);
                        total_raw += raw;
                    }
                }

                let mut all_guard = all_items_bg.lock().expect("Lock failed");
                if is_append {
                    all_guard.extend(total_items);
                } else {
                    *all_guard = total_items;
                }
                drop(all_guard);

                let mut raw_guard = raw_count_bg.lock().expect("Lock failed");
                if is_append {
                    *raw_guard += total_raw;
                } else {
                    *raw_guard = total_raw;
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
                
                unsafe {
                    let _ = hwnd_bg.PostMessage(msg::WndMsg {
                        msg_id: WM_LOAD_DONE,
                        wparam: 0,
                        lparam: 0,
                    });
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
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1002), winsafe::BmpPtrStr::from_str(&clean_tr(&loader.get("ui-menu-filter-cell"))))?;

                if let Some(cmd_id) = h_menu.TrackPopupMenu(co::TPM::RETURNCMD | co::TPM::LEFTALIGN, pt_screen, self.lst_logs.hwnd())? {
                    let cell_text = self.lst_logs.items().get(lvhti.iItem as _).text(lvhti.iSubItem as _);
                    match cmd_id {
                        1001 => { let _ = clipboard_win::set_clipboard_string(&cell_text); },
                        1002 => {
                            let _ = self.txt_search.hwnd().SetWindowText(&cell_text);
                            self.on_txt_search_en_change()?;
                        },
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
        let req = &items[real_idx];

        let text = match log_col {
            LogColumn::Timestamp => req.timestamp.clone(),
            LogColumn::Type => req.req_type.clone(),
            LogColumn::Server => req.server.clone(),
            LogColumn::ApIp => req.ap_ip.clone(),
            LogColumn::ApName => req.ap_name.clone(),
            LogColumn::Mac => req.mac.clone(),
            LogColumn::User => req.user.clone(),
            LogColumn::Reason => {
                use std::cell::RefCell;
                thread_local! {
                    static REASON_CACHE: RefCell<std::collections::HashMap<String, String>> = RefCell::new(std::collections::HashMap::new());
                }
                
                REASON_CACHE.with(|cache| {
                    let mut cache = cache.borrow_mut();
                    if let Some(val) = cache.get(&req.reason) {
                        val.clone()
                    } else {
                        let val = map_reason(&req.reason);
                        cache.insert(req.reason.clone(), val.clone());
                        val
                    }
                })
            }
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

    #[allow(clippy::unnecessary_wraps)]
    fn on_btn_copy_clicked(&self) -> winsafe::AnyResult<()> {
        if let Some(iitem) = self.lst_logs.items().iter_selected().next() {
            let items = self.all_items.lock().expect("Lock failed");
            let ids = self.filtered_ids.lock().expect("Lock failed");
            if let Some(&idx) = ids.get(iitem.index() as usize) {
                let tsv = items[idx].to_tsv();
                let _ = clipboard_win::set_clipboard_string(&tsv);
            }
        }
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
                    
                    // RDP optimization: Set background color and text color explicitly
                    // This helps when FillRect is optimized away
                    let p_ptr = std::ptr::from_ref(p).cast_mut();
                    unsafe {
                        (*p_ptr).clrTextBk = color_ref;
                        // Use contrast colors for text
                        let text_color = if clr.1 > 200 { 
                            winsafe::COLORREF::from_rgb(0, 128, 0) // Dark Green for Green bg
                        } else if clr.0 > 200 {
                            winsafe::COLORREF::from_rgb(128, 0, 0) // Dark Red for Red bg
                        } else {
                            winsafe::COLORREF::from_rgb(0, 0, 0)
                        };
                        (*p_ptr).clrText = text_color;
                        
                        let _ = p.mcd.hdc.SetBkColor(color_ref);
                        let _ = p.mcd.hdc.SetTextColor(text_color);
                        
                        // Select bold font if available
                        if let Some(hfont) = self.bold_font.lock().expect("Lock failed").as_ref() {
                            let _ = p.mcd.hdc.SelectObject(&**hfont);
                        }
                    }
                    
                    if let Ok(brush) = winsafe::HBRUSH::CreateSolidBrush(color_ref) {
                        let _ = p.mcd.hdc.FillRect(p.mcd.rc, &brush);
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
                    let p_ptr = std::ptr::from_ref(p).cast_mut();
                    unsafe {
                        (*p_ptr).clrTextBk = color_ref;
                        let text_color = if clr.1 > 200 { 
                            winsafe::COLORREF::from_rgb(0, 128, 0)
                        } else if clr.0 > 200 {
                            winsafe::COLORREF::from_rgb(128, 0, 0)
                        } else {
                            winsafe::COLORREF::from_rgb(0, 0, 0)
                        };
                        (*p_ptr).clrText = text_color;
                        
                        let _ = p.mcd.hdc.SetBkColor(color_ref);
                        let _ = p.mcd.hdc.SetTextColor(text_color);

                        if let Some(hfont) = self.bold_font.lock().expect("Lock failed").as_ref() {
                            let _ = p.mcd.hdc.SelectObject(&**hfont);
                        }
                    }
                    
                    if let Ok(brush) = winsafe::HBRUSH::CreateSolidBrush(color_ref) {
                        let _ = p.mcd.hdc.FillRect(p.mcd.rc, &brush);
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
        let _ = self.lst_logs.hwnd().InvalidateRect(None, true);
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
        ids.par_sort_unstable_by(|&a_idx, &b_idx| {
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
    // Wrap to make it a valid XML if it's just a list of fragments
    let wrapped = if content.trim().starts_with("<events>") {
        content
    } else {
        format!("<events>{content}</events>")
    };

    let root: Root = from_str(&wrapped)?;
    let events = root.events;
    let raw_event_count = events.len();
    
    if events.is_empty() {
        return Ok((Vec::new(), 0));
    }

    // Grouping events by Class or Session ID
    // If both are missing, we don't group (each event stays individual)
    let mut groups: Vec<Vec<Event>> = Vec::new();
    let mut class_map: HashMap<String, usize> = HashMap::new(); // maps class/session_id to index in groups

    for ev in events {
        let key = ev.class.as_deref()
            .or(ev.acct_session_id.as_deref())
            .filter(|&s| !s.is_empty());
        
        if let Some(k) = key {
            if let Some(&idx) = class_map.get(k) {
                groups[idx].push(ev);
            } else {
                class_map.insert(k.to_string(), groups.len());
                groups.push(vec![ev]);
            }
        } else {
            // No grouping key, add as standalone
            groups.push(vec![ev]);
        }
    }

    let mut requests: Vec<RadiusRequest> = groups.into_par_iter()
        .map(|g| process_group(&g))
        .collect();
        
    requests.par_sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));
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
            req.resp_type = map_packet_type(p_type);
            req.reason = map_reason(event.reason_code.as_deref().unwrap_or("0"));
            match p_type {
                "2" => req.bg_color = Some((204, 255, 204)), // Web-safe light green
                "3" => req.bg_color = Some((255, 204, 204)), // Web-safe light red
                _ => {},
            }
        }
    }
    req
}

fn map_packet_type(code: &str) -> String {
    let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
    let key = format!("radius-packet-types-{code}");
    let val = loader.get(&key);
    // Case-insensitive check for common missing localization signals
    if val == key || val.to_lowercase().contains("localization") { 
        code.to_string() 
    } else { 
        val 
    }
}

fn map_reason(code: &str) -> String {
    let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
    let key = format!("nps-reasons-{code}");
    let val = loader.get(&key);
    // Case-insensitive check for common missing localization signals
    if val == key || val.to_lowercase().contains("localization") { 
        clean_tr(&loader.get("ui-map-code"))
            .replace("{ $code }", code)
            .replace("{$code}", code)
    } else { 
        clean_tr(&val)
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
