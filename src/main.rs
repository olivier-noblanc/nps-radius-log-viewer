#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap, clippy::significant_drop_tightening, clippy::nursery, clippy::pedantic, clippy::iter_kv_map)]

use winsafe::prelude::*;
use winsafe::{gui, co, msg};
use quick_xml::de::from_str;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::fs;
use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::Duration;
use notify::{Watcher, RecursiveMode};

// Manual FFI declaration for SetCursor (not exported by winsafe)
// This allows us to use winsafe's HCURSOR with the native SetCursor function
#[link(name = "user32")]
extern "system" {
    fn SetCursor(hcursor: isize) -> isize;
}

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
const WM_FILTER_DONE: co::WM = unsafe { co::WM::from_raw(co::WM::USER.raw() + 3) }; // New message
const WM_PROGRESS: co::WM = unsafe { co::WM::from_raw(co::WM::USER.raw() + 10) }; // For progress bar
const WM_FILE_CHANGED: co::WM = unsafe { co::WM::from_raw(co::WM::USER.raw() + 11) }; // For Tail mode
const WM_FORCE_WAIT: co::WM = unsafe { co::WM::from_raw(co::WM::USER.raw() + 20) };
const WM_FORCE_NORMAL: co::WM = unsafe { co::WM::from_raw(co::WM::USER.raw() + 21) };

// Wrapper to satisfy the compiler for cross-thread usage.
// We use isize to ensure Copy, and reconstruct inside the thread/closure.
#[derive(Clone, Copy)]
struct SafeHWND(isize);
unsafe impl Send for SafeHWND {}
unsafe impl Sync for SafeHWND {}

impl SafeHWND {
    fn from_hwnd(h: &winsafe::HWND) -> Self {
        Self(h.ptr() as isize)
    }
    fn h(&self) -> winsafe::HWND {
        unsafe { winsafe::HWND::from_ptr(self.0 as *mut _) }
    }
    
    /// Send a custom WM_USER message synchronously
    /// Encapsulates the unsafe block for cleaner thread code
    fn send(&self, msg_id: co::WM, wparam: usize, lparam: isize) {
        let h = self.h();
        unsafe {
            let _ = h.SendMessage(msg::WndMsg {
                msg_id,
                wparam,
                lparam,
            });
        }
    }
    
    /// Post a custom WM_USER message asynchronously
    /// Encapsulates the unsafe block for cleaner thread code
    fn post(&self, msg_id: co::WM, wparam: usize, lparam: isize) {
        let h = self.h();
        unsafe {
            let _ = h.PostMessage(msg::WndMsg {
                msg_id,
                wparam,
                lparam,
            });
        }
    }
}
const IDT_SEARCH_TIMER: usize = 100; // ID for search timer

// IDs pour le menu Font


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
    bg_color: Option<(u8, u8, u8)>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AppConfig {
    window_x: i32,
    window_y: i32,
    window_width: i32,
    window_height: i32,
    column_widths: Vec<i32>,
    visible_columns: Vec<LogColumn>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            window_x: 0,
            window_y: 0,
            window_width: 1000, // Slightly larger default value
            window_height: 700,
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

        let screen_cx = winsafe::GetSystemMetrics(co::SM::CXSCREEN);
        let screen_cy = winsafe::GetSystemMetrics(co::SM::CYSCREEN);

        if cfg.window_width <= 100 || cfg.window_width > screen_cx { cfg.window_width = 1000; }
        if cfg.window_height <= 100 || cfg.window_height > screen_cy { cfg.window_height = 700; }
        
        // If window_x or window_y is 0 (or out of bounds), reset to 0 (default centering might be better in MyWindow::new)
        if cfg.window_x < -2000 || cfg.window_x > screen_cx { cfg.window_x = 0; }
        if cfg.window_y < -2000 || cfg.window_y > screen_cy { cfg.window_y = 0; }

        if cfg.visible_columns.is_empty() {
            cfg.visible_columns = LogColumn::all();
        }
        cfg
    }

    fn save(&self) -> anyhow::Result<()> {
        let s = serde_json::to_string_pretty(self)?;
        fs::write("config.json", s)?;
        Ok(())
    }
}

impl RadiusRequest {
    // OPTIMIZATION: Case-insensitive search without massive intermediate allocation
    // Change signature to accept &str (already lowercase)
    fn matches(&self, query_lower: &str) -> bool {
        if query_lower.is_empty() { return true; }
        
        // Helper to check a field (convert field to lowercase for comparison)
        let check = |s: &str| s.to_ascii_lowercase().contains(query_lower);

        check(&self.user) 
        || check(&self.mac)
        || check(&self.ap_ip)
        || check(&self.ap_name)
        || check(&self.server)
        || check(&self.reason)
        || check(&self.req_type)
        || check(&self.resp_type)
    }

    fn to_tsv(&self) -> String {
        format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", 
            self.timestamp, self.req_type, self.server, self.ap_ip, 
            self.ap_name, self.mac, self.user, self.reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
enum LogColumn {
    Timestamp, Type, Server, ApIp, ApName, Mac, User, ResponseType, Reason, Session,
}

impl LogColumn {
    fn all() -> Vec<Self> {
        vec![Self::Timestamp, Self::Type, Self::Server, Self::ApIp,
             Self::ApName, Self::Mac, Self::User, Self::ResponseType, Self::Reason, Self::Session]
    }

    const fn ftl_key(self) -> &'static str {
        match self {
            Self::Timestamp => "col-timestamp", Self::Type => "col-type", Self::Server => "col-server",
            Self::ApIp => "col-ap-ip", Self::ApName => "col-ap-name", Self::Mac => "col-mac",
            Self::User => "col-user", Self::ResponseType => "col-responsetype", Self::Reason => "col-reason",
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
    btn_prev_err: gui::Button, // Navigation erreur
    btn_next_err: gui::Button, // Navigation erreur
    btn_about:    gui::Button,
    cb_append:    gui::CheckBox,
    status_bar:   gui::StatusBar,
    progress_bar: gui::ProgressBar,
    
    all_items:    Arc<RwLock<Vec<RadiusRequest>>>,
    raw_count:    Arc<RwLock<usize>>,
    filtered_ids: Arc<RwLock<Vec<usize>>>,
    show_errors:  Arc<RwLock<bool>>,
    sort_col:     Arc<RwLock<LogColumn>>,
    sort_desc:    Arc<RwLock<bool>>,
    visible_cols: Arc<RwLock<Vec<LogColumn>>>,
    config:       Arc<RwLock<AppConfig>>,
    is_busy:      Arc<AtomicBool>,
    
    // Pour le Tail mode
    current_file_path: Arc<Mutex<Option<String>>>,
    last_file_size:    Arc<Mutex<u64>>,
    watcher:           Arc<Mutex<Option<notify::RecommendedWatcher>>>,
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
                position: (510, 14), width: 150, height: 22, ..Default::default()
            }),
            btn_open:     gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("ui-open-log"), position: (10, 10), width: 110, height: 30, ..Default::default()
            }),
            btn_open_folder: gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("ui-folder"), position: (125, 10), width: 110, height: 30, ..Default::default()
            }),
            btn_rejects:  gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("ui-errors"), position: (240, 10), width: 110, height: 30, ..Default::default()
            }),
            btn_prev_err: gui::Button::new(&wnd, gui::ButtonOpts {
                text: "< Error",
                position: (355, 10),
                width: 70, height: 30,
                ..Default::default()
            }),
            btn_next_err: gui::Button::new(&wnd, gui::ButtonOpts {
                text: "Error >",
                position: (430, 10),
                width: 70, height: 30,
                ..Default::default()
            }),
            btn_about: gui::Button::new(&wnd, gui::ButtonOpts {
                text: &loader.get("about_title"), position: (config.window_width - 130, 10), width: 120, height: 30,
                resize_behavior: (gui::Horz::Repos, gui::Vert::None), ..Default::default()
            }),
            cb_append:    gui::CheckBox::new(&wnd, gui::CheckBoxOpts {
                text: &loader.get("ui-append"), position: (780, 14), size: (80, 20), ..Default::default()
            }),
            status_bar:   gui::StatusBar::new(&wnd, &[
                gui::SbPart::Fixed(200), gui::SbPart::Proportional(1),
            ]),
            progress_bar: gui::ProgressBar::new(
                &wnd,
                gui::ProgressBarOpts {
                    position: (10, config.window_height - 45),
                    size: (config.window_width - 20, 20),
                    window_style: co::WS::CHILD | co::WS::VISIBLE | co::PBS::SMOOTH.into(),
                    resize_behavior: (gui::Horz::Resize, gui::Vert::Repos),
                    ..Default::default()
                },
            ),
            all_items:    Arc::new(RwLock::new(Vec::new())),
            raw_count:    Arc::new(RwLock::new(0)),
            filtered_ids: Arc::new(RwLock::new(Vec::new())),
            show_errors:  Arc::new(RwLock::new(false)),
            sort_col:     Arc::new(RwLock::new(LogColumn::Timestamp)),
            sort_desc:    Arc::new(RwLock::new(true)),
            visible_cols: Arc::new(RwLock::new(config.visible_columns.clone())),
            config:       Arc::new(RwLock::new(config)),
            is_busy:      Arc::new(AtomicBool::new(false)),
            current_file_path: Arc::new(Mutex::new(None)),
            last_file_size:    Arc::new(Mutex::new(0)),
            watcher:           Arc::new(Mutex::new(None)),
        };

        new_self.on_wm_events();
        new_self.on_events();
        new_self
    }

    fn on_wm_events(&self) {
        let me = self.clone();
        
        // Restore window position on creation
        self.wnd.on().wm_create(move |_| {
            let config = me.config.read().expect("Lock failed");
            if config.window_x != 0 || config.window_y != 0 {
                let mut pt = winsafe::POINT::default();
                pt.x = config.window_x;
                pt.y = config.window_y;
                let mut sz = winsafe::SIZE::default();
                sz.cx = config.window_width;
                sz.cy = config.window_height;

                me.wnd.hwnd().SetWindowPos(
                    winsafe::HwndPlace::Place(co::HWND_PLACE::NOTOPMOST),
                    pt,
                    sz,
                    co::SWP::NOZORDER,
                ).ok();
            }
            Ok(0)
        });

        let me = self.clone();
        self.wnd.on().wm_close(move || {
            // Save config (Read-only on RwLock here)
            let visible = me.visible_cols.read().expect("Lock failed").clone();
            let config_read = me.config.read().expect("Lock failed");
            let all_cols = LogColumn::all();

            let mut config_save = config_read.clone(); // Local clone for modification
            drop(config_read);

            for (i, &col) in visible.iter().enumerate() {
                let col_idx = all_cols.iter().position(|&c| c == col).unwrap_or(0);
                let width = me.lst_logs.cols().get(i as u32).width().unwrap_or(100);
                if col_idx < config_save.column_widths.len() {
                    config_save.column_widths[col_idx] = width as i32;
                }
            }
            config_save.visible_columns.clone_from(&visible);
            
            let rect = me.wnd.hwnd().GetWindowRect().expect("Get window rect failed");
            config_save.window_x = rect.left;
            config_save.window_y = rect.top;
            config_save.window_width = rect.right - rect.left;
            config_save.window_height = rect.bottom - rect.top;
            
            let _ = config_save.save();
            
            
            winsafe::PostQuitMessage(0);
            Ok(())
        });

        let me = self.clone();
        self.wnd.on().wm_create(move |_| {
           // On passe une chaîne vide pour désactiver le thème visuel (repasser en "Classique")
           let _ = me.lst_logs.hwnd().SetWindowTheme("", Some(""));

            if let Ok(hicon_guard) = winsafe::HINSTANCE::GetModuleHandle(None).and_then(|h| h.LoadIcon(winsafe::IdIdiStr::Id(1))) {
                 let _ = unsafe { me.wnd.hwnd().SendMessage(msg::wm::SetIcon { 
                     hicon: winsafe::HICON::from_ptr(hicon_guard.ptr()), 
                     size: co::ICON_SZ::BIG 
                 }) };
            }

            // 2. Next, enable extended styles (FullRowSelect, DoubleBuffer, etc.)
            let ex_styles = co::LVS_EX::FULLROWSELECT 
                | co::LVS_EX::DOUBLEBUFFER
                | co::LVS_EX::HEADERDRAGDROP;
            me.lst_logs.set_extended_style(true, ex_styles);

            // 3. Force a refresh
            me.lst_logs.hwnd().InvalidateRect(None, true).ok();

            
            // Hide progress bar initially
            me.progress_bar.hwnd().ShowWindow(co::SW::HIDE);
            
            me.refresh_columns();
            Ok(0)
        });
        
        // Handle loading completion
        let me = self.clone();
        self.wnd.on().wm(WM_LOAD_DONE, move |_| {
            let count = me.filtered_ids.read().expect("Lock failed").len();
            let raw = *me.raw_count.read().expect("Lock failed");
            me.lst_logs.items().set_count(count as u32, None).expect("Set count failed");
            
            let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
            let mut args = HashMap::new();
            args.insert("count", count.to_string());
            args.insert("raw", raw.to_string());
            
            let msg = loader.get_args("ui-status-display", args);
            let _ = me.status_bar.parts().get(1).set_text(&clean_tr(&msg));
            let _ = me.status_bar.parts().get(0).set_text("");
            me.lst_logs.hwnd().InvalidateRect(None, true).expect("Invalidate rect failed");
            

            Ok(0)
        });

        // Handle loading errors
        let me = self.clone();
        self.wnd.on().wm(WM_LOAD_ERROR, move |_| {
            let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
            let _ = me.status_bar.parts().get(1).set_text(&loader.get("ui-status-error"));
            

            me.is_busy.store(false, Ordering::SeqCst);
            me.trigger_async_filter(); // Initial filter
            Ok(0)
        });

        // Handle filter completion (Search)
        let me = self.clone();
        self.wnd.on().wm(WM_FILTER_DONE, move |_| {
            if let Ok(ids) = me.filtered_ids.read() {
                 me.lst_logs.items().set_count(ids.len() as u32, None).expect("Set count failed");
            }
            me.lst_logs.hwnd().InvalidateRect(None, true).expect("Invalidate rect failed");
            Ok(0)
        });


        
        let me = self.clone();
        self.wnd.on().wm_timer(IDT_SEARCH_TIMER as usize, move || {
            me.wnd.hwnd().KillTimer(IDT_SEARCH_TIMER as usize).ok();
            me.trigger_async_filter();
            Ok(())
        });

        // --- Gestion de la Progression ---
        let me = self.clone();
        self.wnd.on().wm(WM_PROGRESS, move |p| {
            let percent = p.wparam as u32;
            
            // Manage progress bar visibility and position
            if percent == 0 {
                // Start of loading: show progress bar
                let _ = me.progress_bar.hwnd().ShowWindow(co::SW::SHOW);
                me.progress_bar.set_position(0);
                
                // Optional: also show in status bar
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                let _ = me.status_bar.parts().get(0).set_text(&loader.get("ui-status-loading"));
            } else if percent >= 100 {
                // End of loading: hide progress bar
                let _ = me.progress_bar.hwnd().ShowWindow(co::SW::HIDE);
                
                // Reset status bar
                let _ = me.status_bar.parts().get(0).set_text("");
            } else {
                // Mise à jour de la progression
                me.progress_bar.set_position(percent);
            }
            Ok(0)
        });

        // --- Handle file change (Tail) ---
        let me = self.clone();
        self.wnd.on().wm(WM_FILE_CHANGED, move |_| {
             me.handle_file_change();
            Ok(0)
        });

        // --- Handle Keyboard Shortcuts ---
        let me = self.clone();
        self.wnd.on().wm_key_down(move |p| {
            let v = p.vkey_code;
            let ctrl = (winsafe::GetAsyncKeyState(co::VK::CONTROL) as u16 & 0x8000) != 0;
            
            if v.raw() == 'F' as u16 && ctrl {
                let _ = me.txt_search.hwnd().SetFocus();
            } else if v.raw() == 'O' as u16 && ctrl {
                 let _ = me.on_btn_open_clicked();
            } else if v == co::VK::F5 {
                 if let Ok(guard) = me.current_file_path.lock() {
                     if guard.is_some() {
                         if let Ok(mut size_guard) = me.last_file_size.lock() {
                             *size_guard = 0;
                         }
                         me.handle_file_change();
                     }
                 }
            }
            Ok(())
        });

        // --- Handle Cursor Forcing (Immediate) ---
        let me = self.clone();
        
        // Message: Force Wait Cursor
        self.wnd.on().wm(WM_FORCE_WAIT, move |_| {
            // Get current mouse position
            let pt = winsafe::GetCursorPos().unwrap_or_default();
            let lst_hwnd = me.lst_logs.hwnd();
            
            // Convert screen coordinates to ListView
            if let Ok(client_pt) = lst_hwnd.ScreenToClient(pt) {
                if let Ok(rc) = lst_hwnd.GetClientRect() {
                    // CRUCIAL: Check IF mouse is INSIDE the list client area
                    // If mouse is over a button or border, don't force anything.
                    if client_pt.x >= 0 && client_pt.y >= 0 && client_pt.x < rc.right && client_pt.y < rc.bottom {
                        if let Ok(h_cursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::WAIT)) {
                            unsafe { SetCursor(h_cursor.ptr() as isize); }
                        }
                    }
                }
            }
            Ok(0)
        });

        // Message: Force Arrow Cursor (Normal)
        self.wnd.on().wm(WM_FORCE_NORMAL, move |_| {
            if let Ok(h_cursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::ARROW)) {
                unsafe { SetCursor(h_cursor.ptr() as isize); }
            }
            Ok(0)
        });
        
    }

    fn on_events(&self) {
        self.btn_open.on().bn_clicked({ let me = self.clone(); move || me.on_btn_open_clicked() });
        self.btn_open_folder.on().bn_clicked({ let me = self.clone(); move || me.on_btn_open_folder_clicked() });
        
        // --- ListView Subclassing for Wait Cursor ---
        let me = self.clone();
        self.lst_logs.on_subclass().wm_set_cursor(move |p| {
            if me.is_busy.load(Ordering::SeqCst) && p.hit_test == co::HT::CLIENT {
                if let Ok(h_cursor) = winsafe::HINSTANCE::NULL.LoadCursor(winsafe::IdIdcStr::Idc(co::IDC::WAIT)) {
                    unsafe { SetCursor(h_cursor.ptr() as isize); }
                    return Ok(true);
                }
            }
            Ok(false)
        });
        
        self.wnd.on().wm_context_menu({ let me = self.clone(); move |p| {
            let h_header_opt = me.lst_logs.header().map(|h| h.hwnd());
            let is_header = h_header_opt.map_or(false, |h| p.hwnd == *h);
            if p.hwnd == *me.lst_logs.hwnd() || is_header {
                me.on_lst_context_menu(p.cursor_pos, p.hwnd)?;
            }
            Ok(())
        }});

        self.lst_logs.on().lvn_get_disp_info({ let me = self.clone(); move |p| me.on_lst_lvn_get_disp_info(p) });
        self.lst_logs.on().lvn_column_click({ let me = self.clone(); move |p| me.on_lst_lvn_column_click(p) });
        
        // Search: Start a timer instead of filtering directly
        self.txt_search.on().en_change({ let me = self.clone(); move || {
            // 300ms delay (Debounce)
            let _ = me.wnd.hwnd().SetTimer(IDT_SEARCH_TIMER, 300, None);
            Ok(())
        }});

        // --- Tooltips ---
        self.lst_logs.on().lvn_get_info_tip({
            let me = self.clone();
            move |p| {
                let item_idx = p.iItem;
                let subitem_idx = p.iSubItem as usize;

                if let Ok(real_idx) = me.filtered_ids.read().map(|ids| ids.get(item_idx as usize).copied()) {
                    if let Some(idx) = real_idx {
                        if let Ok(items) = me.all_items.read() {
                            if let Some(req) = items.get(idx) {
                                let _text = match subitem_idx {
                                    0 => req.timestamp.clone(),
                                    1 => req.req_type.clone(),
                                    2 => req.server.clone(),
                                    3 => req.ap_ip.clone(),
                                    4 => req.ap_name.clone(),
                                    5 => req.mac.clone(),
                                    6 => req.user.clone(),
                                    7 => req.resp_type.clone(),
                                    8 => req.reason.clone(),
                                    9 => req.session_id.clone(),
                                    _ => String::new(),
                                };
                                // copy info tip text to p.pszText
                                // p.pszText is LPWSTR (mut pointer to buffer of cchTextMax chars)
                                // Winsafe NMLVGETINFOTIP likely exposes it.
                                // If p.pszText() returns Option<String>, it's read-only wrapper?
                                // Let's try unsafe pointer write if we can get the pointer.
                                // But struct fields are private.
                                // If there is no setter, we might be stuck with unsafe transmute or just skipping it for now 
                                // if we can't find the proper way.
                                // TODO: Fix tooltips properly.
                                // let _ = p.set_text(&text); 
                            }
                        }
                    }
                }
                Ok(())
            }
        });

        // --- Navigation Erreur ---
        self.btn_prev_err.on().bn_clicked({
            let me = self.clone();
            move || { me.navigate_error(-1); Ok(()) }
        });

        self.btn_next_err.on().bn_clicked({
            let me = self.clone();
            move || { me.navigate_error(1); Ok(()) }
        });

        self.btn_rejects.on().bn_clicked({ let me = self.clone(); move || me.on_btn_rejects_clicked() });
        self.btn_about.on().bn_clicked({ let me = self.clone(); move || me.on_btn_about_clicked() });
        self.lst_logs.on().nm_custom_draw({ let me = self.clone(); move |p| Ok(me.on_lst_nm_custom_draw(p)) });
    }

    // --- Logique de filtrage asynchrone ---
    fn on_btn_about_clicked(&self) -> winsafe::AnyResult<()> {
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let about_msg = format!("{}\n\n{}", 
            clean_tr(&loader.get("about_text")),
            clean_tr(&loader.get("about_shortcuts"))
        );
        self.wnd.hwnd().MessageBox(
            &about_msg,
            &clean_tr(&loader.get("about_title")),
            co::MB::OK | co::MB::ICONINFORMATION,
        )?;
        Ok(())
    }

    // --- Navigation Erreur ---
    fn navigate_error(&self, direction: i32) {
        // 1. Trouver l'index sélectionné actuel
        let selected = self.lst_logs.items().selected_count();
        if selected == 0 {
            let len = self.lst_logs.items().count() as i32;
            // If nothing selected, start BEFORE first or AFTER last to check the whole range
            self.jump_to_error(if direction > 0 { -1 } else { len }, direction);
            return;
        }
        
        // Get first selected index
        let start_idx = self.lst_logs.items().iter_selected().next().map(|item| item.index()).unwrap_or(std::u32::MAX);
        
        // start_idx is u32 from GetNextItem (some impls). If it's Option<u32>, unwrap gives u32.
        // If message returns Option<u32>, check signature. Usually Option<u32>.
        // Winsafe returns Option<u32>. u32::MAX is weird if not found. Let's use logic.
        
        let start_i32 = if start_idx == std::u32::MAX { -1 } else { start_idx as i32 };
        
        self.jump_to_error(start_i32, direction);
    }

    fn jump_to_error(&self, start_idx: i32, direction: i32) {
        let filtered = self.filtered_ids.read().expect("Lock failed");
        let items = self.all_items.read().expect("Lock failed");

        let len = filtered.len() as i32;
        if len == 0 { return; }

        let mut current = start_idx + direction;
        let mut found_idx: Option<i32> = None;
        
        // Loop to find next line with log error
        // Limit to avoid infinite loop if 0 errors found
        for _ in 0..len {
            if current < 0 { current = len - 1; } // Wrap to end
            if current >= len { current = 0; }   // Wrap to start

            if let Some(&real_idx) = filtered.get(current as usize) {
                if let Some(req) = items.get(real_idx) {
                    if req.resp_type == "Access-Reject" { // Target only rejects (Red)
                        found_idx = Some(current);
                        break; // Found it, exit loop
                    }
                }
            }
            current += direction;
        }

        if let Some(current) = found_idx {
            // Select item via safe API
            let _ = self.lst_logs.items().select_all(false);
            
            // Select and Focus new item
            let item = self.lst_logs.items().get(current as u32);
            item.select(true).ok();
            item.focus().ok();
            let _ = item.ensure_visible();
            
            self.lst_logs.hwnd().SetFocus();
            return;
        }
    }

    // --- Tail Mode ---
    fn handle_file_change(&self) {
        let path_opt = self.current_file_path.lock().unwrap().clone();
        if let Some(path) = path_opt {
            // Update size for next time
            if let Ok(metadata) = fs::metadata(&path) {
                let new_size = metadata.len();
                let mut last_size = self.last_file_size.lock().unwrap();
                
                if new_size > *last_size {
                    // File grew: reload everything for now (safer for XML)
                    // Ideally: read delta and parse fragment
                    *last_size = new_size;
                    
                    // Trigger a reload as if Open was clicked, 
                    // but without dialog and in background
                    let me = self.clone();
                    // Reuse existing loading logic but adapted
                    // Simplified: simulate Open click if possible without dialog,
                    // but since on_btn_open_clicked opens a dialog, we extract the logic.
                    
                    // Call loading logic directly in a thread
                    // Note: handle is_busy flag
                        if !me.is_busy.load(Ordering::SeqCst) {
                            let _ = me.status_bar.parts().get(1).set_text("File changed, reloading...");
                            
                            let is_busy_bg = me.is_busy.clone();
                            let all_items_bg = me.all_items.clone();
                            let raw_count_bg = me.raw_count.clone();
                            let safe_hwnd = SafeHWND::from_hwnd(&me.wnd.hwnd());
                            let path_bg = path.clone();

                            thread::spawn(move || {
                                // 1. Start busy guard
                                let busy = BusyGuard::new(is_busy_bg);
                                
                                // 2. FORCE CURSOR IMMEDIATELY
                                safe_hwnd.send(WM_FORCE_WAIT, 0, 0);

                                // Parse entire file
                                match parse_full_logic(&path_bg, Some(safe_hwnd)) { 
                                    Ok((reqs, raw)) => {
                                        {
                                            let mut items = all_items_bg.write().expect("Lock failed");
                                            *items = reqs;
                                            let mut r = raw_count_bg.write().expect("Lock failed");
                                            *r = raw;
                                        }
                                        
                                        drop(busy); // Release is_busy flag

                                        // 4. FORCE ARROW RETURN
                                        safe_hwnd.send(WM_FORCE_NORMAL, 0, 0);

                                        // Notify UI that it's done
                                        safe_hwnd.post(WM_LOAD_DONE, 0, 0);
                                    }
                                    Err(e) => {
                                        eprintln!("Reload error: {:?}", e);
                                        drop(busy); 

                                        safe_hwnd.send(WM_FORCE_NORMAL, 0, 0);

                                        safe_hwnd.post(WM_LOAD_ERROR, 0, 0);
                                    }
                                }
                            });
                        }
                }
            }
        }
    }

    fn trigger_async_filter(&self) {
        // Capture current values
        let query = self.txt_search.text().unwrap_or_default();
        let show_err_val = *self.show_errors.read().expect("Lock failed");
        let sort_col_val = *self.sort_col.read().expect("Lock failed");
        let sort_desc_val = *self.sort_desc.read().expect("Lock failed");

        let all_items_bg = self.all_items.clone();
        let filt_ids_bg = self.filtered_ids.clone();
        let safe_hwnd = SafeHWND::from_hwnd(&self.wnd.hwnd());

        // We don't use BusyGuard here to avoid locking the mouse during simple search
        thread::spawn(move || {
            let h = safe_hwnd.h();
            apply_filter_logic(
                &all_items_bg, 
                &filt_ids_bg, 
                &query, 
                show_err_val,
                sort_col_val,
                sort_desc_val
            );
            
            unsafe {
                let _ = h.PostMessage(msg::WndMsg {
                    msg_id: WM_FILTER_DONE,
                    wparam: 0,
                    lparam: 0,
                });
            }
        });
    }


    fn on_btn_open_clicked(&self) -> winsafe::AnyResult<()> {
        // ... (Same as original, but uses trigger_async_filter at end if needed)
        // Briefly, omitting duplication, the idea is:
        // 1. File Dialog
        // 2. Thread Spawn (load) -> Apply Filter Logic -> Post WM_LOAD_DONE
        // Note: File loading remains synchronous in the background thread, which is fine.
        
        let file_dialog = winsafe::CoCreateInstance::<winsafe::IFileOpenDialog>(
            &co::CLSID::FileOpenDialog, None::<&winsafe::IUnknown>, co::CLSCTX::INPROC_SERVER,
        )?;
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        file_dialog.SetFileTypes(&[(loader.get("ui-file-log"), "*.log".to_owned()), (loader.get("ui-file-all"), "*.*".to_owned())])?;
        
        if file_dialog.Show(self.wnd.hwnd())? {
            let result = file_dialog.GetResult()?;
            let path = result.GetDisplayName(co::SIGDN::FILESYSPATH)?;

            // --- WATCHER SETUP ---
            // Deactivate the previous watcher
            *self.watcher.lock().unwrap() = None;
            
            if !self.cb_append.is_checked() {
                *self.current_file_path.lock().unwrap() = Some(path.clone());
                 if let Ok(meta) = fs::metadata(&path) {
                     *self.last_file_size.lock().unwrap() = meta.len();
                }

                let safe_hwnd_watcher = SafeHWND::from_hwnd(&self.wnd.hwnd());
                let mut new_watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
                    match res {
                        Ok(event) => {
                             if event.kind.is_modify() || event.kind.is_create() {
                                std::thread::sleep(Duration::from_millis(500));
                                unsafe {
                                    let h = safe_hwnd_watcher.h();
                                    let _ = h.PostMessage(msg::WndMsg {
                                        msg_id: WM_FILE_CHANGED,
                                        wparam: 0,
                                        lparam: 0,
                                    });
                                }
                             }
                        }
                        Err(e) => eprintln!("Watch error: {:?}", e),
                    }
                }).ok(); 

                if let Some(w) = &mut new_watcher {
                    if let Some(parent) = std::path::Path::new(&path).parent() {
                        let _ = w.watch(parent, RecursiveMode::NonRecursive);
                    }
                }
                *self.watcher.lock().unwrap() = new_watcher;
            } else {
                 *self.current_file_path.lock().unwrap() = None;
            }
            
            if !self.cb_append.is_checked() {
                let _ = self.lst_logs.items().set_count(0, None);
            }
            
            let _ = self.status_bar.parts().get(1).set_text(&loader.get("ui-status-loading"));
            
            let is_busy_bg = self.is_busy.clone();
            let all_items_bg = self.all_items.clone();
            let raw_count_bg = self.raw_count.clone();
            let filt_ids_bg = self.filtered_ids.clone();
            let is_append = self.cb_append.is_checked();
            let safe_hwnd = SafeHWND::from_hwnd(&self.wnd.hwnd());
            let query = self.txt_search.text().unwrap_or_default();
            let show_err_val = *self.show_errors.read().expect("Lock failed");
            let sort_col_val = *self.sort_col.read().expect("Lock failed");
            let sort_desc_val = *self.sort_desc.read().expect("Lock failed");
            let path_bg = path.clone();

            thread::spawn(move || {
                // 1. Start busy guard
                let busy = BusyGuard::new(is_busy_bg);
                
                // 2. FORCE CURSOR IMMEDIATELY
                safe_hwnd.send(WM_FORCE_WAIT, 0, 0);

                match parse_full_logic(&path_bg, Some(safe_hwnd)) {
                    Ok((items, raw_total)) => {
                        {
                            let mut all_guard = all_items_bg.write().expect("Lock failed");
                            if is_append { all_guard.extend(items); } else { *all_guard = items; }
                        }
                        {
                            let mut raw_guard = raw_count_bg.write().expect("Lock failed");
                            if is_append { *raw_guard += raw_total; } else { *raw_guard = raw_total; }
                        }
                        apply_filter_logic(&all_items_bg, &filt_ids_bg, &query, show_err_val, sort_col_val, sort_desc_val);
                        
                        drop(busy); // Release is_busy flag

                        // 4. FORCE ARROW RETURN
                        safe_hwnd.send(WM_FORCE_NORMAL, 0, 0);

                        // 5. Notify UI
                        safe_hwnd.post(WM_LOAD_DONE, 0, 0);
                    }
                    Err(_) => {
                        drop(busy);
                        safe_hwnd.send(WM_FORCE_NORMAL, 0, 0);
                        safe_hwnd.post(WM_LOAD_ERROR, 0, 0);
                    }
                }
            });
        }
        Ok(())
    }

    // ... (on_btn_open_folder, on_btn_about, on_lst_context_menu, etc. remain similar)
    // Shortened for readability, main logic is in the optimizations above.
    // Make sure to convert Mutex::lock into RwLock::read or write in other functions.
    
    fn on_btn_open_folder_clicked(&self) -> winsafe::AnyResult<()> {
        let file_dialog = winsafe::CoCreateInstance::<winsafe::IFileOpenDialog>(
            &co::CLSID::FileOpenDialog, None::<&winsafe::IUnknown>, co::CLSCTX::INPROC_SERVER,
        )?;
        file_dialog.SetOptions(file_dialog.GetOptions()? | co::FOS::PICKFOLDERS)?;
        
        if file_dialog.Show(self.wnd.hwnd())? {
            let result = file_dialog.GetResult()?;
            let folder_path = result.GetDisplayName(co::SIGDN::FILESYSPATH)?;
            
            if !self.cb_append.is_checked() {
                let _ = self.lst_logs.items().set_count(0, None);
            }
            
            let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
            let _ = self.status_bar.parts().get(1).set_text(&loader.get("ui-status-loading-folder"));
            
            let folder_path_str = folder_path.clone();
            let is_append = self.cb_append.is_checked();
            let is_busy_bg = self.is_busy.clone();
            let all_items_bg = self.all_items.clone();
            let raw_count_bg = self.raw_count.clone();
            let filt_ids_bg = self.filtered_ids.clone();
            let query = self.txt_search.text().unwrap_or_default();
            let show_err_val = *self.show_errors.read().expect("Lock failed");
            let sort_col_val = *self.sort_col.read().expect("Lock failed");
            let sort_desc_val = *self.sort_desc.read().expect("Lock failed");
            let safe_hwnd = SafeHWND::from_hwnd(&self.wnd.hwnd());

            thread::spawn(move || {
                // 1. Start busy guard
                let busy = BusyGuard::new(is_busy_bg);
                
                // 2. FORCE CURSOR IMMEDIATELY
                safe_hwnd.send(WM_FORCE_WAIT, 0, 0);

                let mut files: Vec<(std::path::PathBuf, std::time::SystemTime)> = Vec::new();
                if let Ok(entries) = fs::read_dir(&folder_path_str) {
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
                    if let Ok((items, raw_c)) = parse_full_logic(file_path.to_str().unwrap_or(""), None) {
                        total_items.extend(items);
                        total_raw_count += raw_c;
                    }
                }
    
                if !total_items.is_empty() {
                     {
                        let mut all_guard = all_items_bg.write().expect("Lock failed");
                        if is_append { all_guard.extend(total_items); } else { *all_guard = total_items; }
                    }
                    {
                        let mut raw_guard = raw_count_bg.write().expect("Lock failed");
                        if is_append { *raw_guard += total_raw_count; } else { *raw_guard = total_raw_count; }
                    }
    
                    apply_filter_logic(&all_items_bg, &filt_ids_bg, &query, show_err_val, sort_col_val, sort_desc_val);
                    
                    drop(busy); // Release is_busy flag

                    // 4. FORCE ARROW RETURN
                    safe_hwnd.send(WM_FORCE_NORMAL, 0, 0);

                    // 5. Notify UI
                    safe_hwnd.post(WM_LOAD_DONE, 0, 0);
                } else {
                     drop(busy); // Release is_busy flag

                     safe_hwnd.send(WM_FORCE_NORMAL, 0, 0);

                     safe_hwnd.post(WM_LOAD_DONE, 0, 0);
                }
            });
        }
        Ok(())
    }

    fn on_lst_lvn_get_disp_info(&self, p: &winsafe::NMLVDISPINFO) -> winsafe::AnyResult<()> {
        let item_idx = p.item.iItem;
        let real_idx = {
            let filtered = self.filtered_ids.read().expect("Lock failed");
            if item_idx < 0 || item_idx >= filtered.len() as i32 { return Ok(()); }
            filtered[item_idx as usize]
        };

        let log_col = {
            let visible = self.visible_cols.read().expect("Lock failed");
            let col_idx = p.item.iSubItem;
            let Some(&c) = visible.get(col_idx as usize) else { return Ok(()); };
            c
        };

        let items = self.all_items.read().expect("Lock failed");
        if real_idx >= items.len() { return Ok(()); }
        let req = &items[real_idx];

        let text = match log_col {
            LogColumn::Timestamp => &req.timestamp,
            LogColumn::Type => &req.req_type,
            LogColumn::Server => &req.server,
            LogColumn::ApIp => &req.ap_ip,
            LogColumn::ApName => &req.ap_name,
            LogColumn::Mac => &req.mac,
            LogColumn::User => &req.user,
            LogColumn::ResponseType => &req.resp_type,
            LogColumn::Reason => &req.reason,
            LogColumn::Session => &req.session_id,
        };

        // FINAL FIX: Use UnsafeCell to avoid borrow lifetime issues
        // The thread_local buffer stays alive, and we access it via unsafe
        use std::cell::UnsafeCell;
        thread_local! {
            static WSTR_BUF: UnsafeCell<winsafe::WString> = UnsafeCell::new(winsafe::WString::new());
        }
        
        WSTR_BUF.with(|cell| {
            // SAFETY: We are in a thread_local, so only one thread accesses it
            // Windows does not modify the buffer, it only reads it
            unsafe {
                let ws_ptr = cell.get();
                *ws_ptr = winsafe::WString::from_str(text);
                
                let p_ptr = std::ptr::from_ref(p).cast_mut();
                (*p_ptr).item.mask |= co::LVIF::TEXT;
                (*p_ptr).item.set_pszText(Some(&mut *ws_ptr));
            }
        });
        
        Ok(())
    }
    
    // ... (Other UI methods: on_lst_context_menu, show_column_context_menu, toggle_column_visibility, 
    //      on_lst_lvn_column_click, on_btn_rejects_clicked, on_lst_nm_custom_draw, run, refresh_columns, update_headers)
    //      The structure is identical, only .lock() calls change to .read() or .write().
    
    // Example modification for on_lst_lvn_column_click
    fn on_lst_lvn_column_click(&self, p: &winsafe::NMLISTVIEW) -> winsafe::AnyResult<()> {
        let mut sort_col_g = self.sort_col.write().expect("Lock failed");
        let mut sort_desc_g = self.sort_desc.write().expect("Lock failed");

        let visible = self.visible_cols.read().expect("Lock failed");
        let Some(&new_col) = visible.get(p.iSubItem as usize) else { return Ok(()); };
        drop(visible);

        if *sort_col_g == new_col {
            *sort_desc_g = !*sort_desc_g;
        } else {
            *sort_col_g = new_col;
            *sort_desc_g = false;
        }
        
        // Drop locks before triggering async filter
        drop(sort_col_g);
        drop(sort_desc_g);
        
        // Trigger async filter again
        self.trigger_async_filter();
        
        self.update_headers();
        // Note: we no longer do InvalidateRect here, WM_FILTER_DONE will handle it
        Ok(())
    }
    
    fn on_btn_rejects_clicked(&self) -> winsafe::AnyResult<()> {
        let mut show_err_g = self.show_errors.write().expect("Lock failed");
        *show_err_g = !*show_err_g;
        let is_on = *show_err_g;
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let txt = if is_on { loader.get("ui-btn-show-all") } else { loader.get("ui-btn-errors-only") };
        let _ = self.btn_rejects.hwnd().SetWindowText(&txt);
        drop(show_err_g);
        
        self.trigger_async_filter();
        Ok(())
    }

    // Adaptation of other methods omitted for brevity...
    fn on_lst_context_menu(&self, pt_screen: winsafe::POINT, _target_hwnd: winsafe::HWND) -> winsafe::AnyResult<()> {
        // Identical to original, but watch out for locks (read for visible_cols)
        let h_header = if let Some(header) = self.lst_logs.header() {
            unsafe { winsafe::HWND::from_ptr(header.hwnd().ptr()) }
        } else {
            winsafe::HWND::NULL
        };
        let rc_header = h_header.GetWindowRect().unwrap_or_default();
        if pt_screen.x >= rc_header.left && pt_screen.x <= rc_header.right
            && pt_screen.y >= rc_header.top && pt_screen.y <= rc_header.bottom {
            self.show_column_context_menu()?;
            return Ok(());
        }

        let pt_client = self.lst_logs.hwnd().ScreenToClient(pt_screen).expect("ScreenToClient failed");
        
        // Use hit_test() to get the item, but we still need LVHITTESTINFO for iSubItem
        if let Some(hit_item) = self.lst_logs.items().hit_test(pt_client) {
            let item_index = hit_item.index();
            
            // Get subitem info manually since winsafe doesn't expose it
            let mut lvhti = winsafe::LVHITTESTINFO { pt: pt_client, ..Default::default() };
            unsafe { self.lst_logs.hwnd().SendMessage(msg::lvm::HitTest { info: &mut lvhti }); }
            let subitem_index = lvhti.iSubItem;
                let h_menu = winsafe::HMENU::CreatePopupMenu()?;
                let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1001), winsafe::BmpPtrStr::from_str(&clean_tr(&loader.get("ui-menu-copy-cell"))))?;
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1003), winsafe::BmpPtrStr::from_str(&clean_tr(&loader.get("ui-menu-copy-row"))))?;
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1002), winsafe::BmpPtrStr::from_str(&clean_tr(&loader.get("ui-menu-filter-cell"))))?;

                if let Some(cmd_id) = h_menu.TrackPopupMenu(co::TPM::RETURNCMD | co::TPM::LEFTALIGN, pt_screen, self.lst_logs.hwnd())? {
                    match cmd_id {
                        1001 => { 
                            let cell_text = hit_item.text(subitem_index as _);
                            let _ = clipboard_win::set_clipboard_string(&cell_text); 
                        },
                        1002 => {
                            let cell_text = hit_item.text(subitem_index as _);
                            let _ = self.txt_search.hwnd().SetWindowText(&cell_text);
                            // Force search refresh
                             let _ = self.wnd.hwnd().SetTimer(IDT_SEARCH_TIMER, 100, None); 
                        },
                        1003 => {
                            let items = self.all_items.read().expect("Lock failed");
                            let ids = self.filtered_ids.read().expect("Lock failed");
                            if let Some(&idx) = ids.get(item_index as usize) {
                                let tsv = items[idx].to_tsv();
                                let _ = clipboard_win::set_clipboard_string(&tsv);
                            }
                        }
                        _ => {}
                    }
                }
        } else {
            self.show_column_context_menu()?;
        }
        Ok(())
    }

    fn show_column_context_menu(&self) -> winsafe::AnyResult<isize> {
        let h_menu = winsafe::HMENU::CreatePopupMenu()?;
        let all_cols = LogColumn::all();
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let visible_now = self.visible_cols.read().expect("Lock failed").clone();

        for (i, col) in all_cols.iter().enumerate() {
            let is_visible = visible_now.contains(col);
            let mut flags = co::MF::STRING;
            if is_visible { flags |= co::MF::CHECKED; }
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
        let mut visible = self.visible_cols.write().expect("Lock failed");
        if visible.contains(&col) {
            if visible.len() > 1 { visible.retain(|&c| c != col); }
        } else {
            let all_cols = LogColumn::all();
            let mut new_visible = Vec::new();
            for &c in &all_cols {
                if visible.contains(&c) || c == col { new_visible.push(c); }
            }
            *visible = new_visible;
        }
        
        // Save to config immediately for persistence
        if let Ok(mut config) = self.config.write() {
            config.visible_columns.clone_from(&visible);
            let _ = config.save();
        }

        drop(visible);
        self.refresh_columns();
        self.trigger_async_filter();
    }

    fn on_lst_nm_custom_draw(&self, p: &winsafe::NMLVCUSTOMDRAW) -> co::CDRF {
        match p.mcd.dwDrawStage {
            co::CDDS::PREPAINT => co::CDRF::NOTIFYITEMDRAW,
            co::CDDS::ITEMPREPAINT => {
                // SELECTION DETECTION
                let is_selected = p.mcd.uItemState.has(co::CDIS::SELECTED);

                // 1. Get specific log color (Green/Red) if exists
                let item_color = {
                    let items = self.all_items.read().expect("Lock failed");
                    let ids = self.filtered_ids.read().expect("Lock failed");
                    ids.get(p.mcd.dwItemSpec).and_then(|&idx| items.get(idx).and_then(|it| it.bg_color))
                };
                
                // 2. Compute final colors
                if let Some(clr) = item_color {
                    // Basic masking to help with Visibility
                    if is_selected {
                        let p_ptr = std::ptr::from_ref(p).cast_mut();
                        unsafe {
                            let mut state = (*p_ptr).mcd.uItemState;
                            state &= !co::CDIS::SELECTED; // Mask selection
                            std::ptr::write_volatile(&mut (*p_ptr).mcd.uItemState, state);
                        }
                    }

                    let bg = if is_selected {
                        if clr.0 == 209 || clr.0 == 165 { // Green log
                             winsafe::COLORREF::from_rgb(110, 231, 183) // Emerald 300 (Medium Green)
                        } else { // Red log
                             winsafe::COLORREF::from_rgb(254, 205, 211) // Rose 200
                        }
                    } else {
                        winsafe::COLORREF::from_rgb(clr.0, clr.1, clr.2)
                    };

                    let p_ptr = std::ptr::from_ref(p).cast_mut();
                    unsafe {
                        std::ptr::write_volatile(&mut (*p_ptr).clrTextBk, bg);
                        std::ptr::write_volatile(&mut (*p_ptr).clrText, winsafe::COLORREF::from_rgb(0, 0, 0)); // Black Text
                    }
                    co::CDRF::NEWFONT
                } else {
                    // --- CASE B: STANDARD LINE ---
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
            let _ = unsafe { self.lst_logs.hwnd().SendMessage(msg::lvm::DeleteColumn { index: 0 }) };
        }
        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");
        let visible = self.visible_cols.read().expect("Lock failed").clone();
        let all_cols = LogColumn::all();
        
        {
            let config = self.config.read().expect("Lock failed");
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
        // 1. Get handle of the Header control (title bar)
        let h_header = self.lst_logs.header().map(|h| h.hwnd()).expect("Failed to get header");

        let (visible, sort_col, sort_desc) = {
            let v = self.visible_cols.read().expect("Lock failed").clone();
            let sc = *self.sort_col.read().expect("Lock failed");
            let sd = *self.sort_desc.read().expect("Lock failed");
            (v, sc, sd)
        };

        let loader = LANGUAGE_LOADER.get().expect("Loader not initialized");

        for (i, &col) in visible.iter().enumerate() {
            // 2. Prepare HDITEM structure
            let mut hdi = winsafe::HDITEM::default();
            
            // We want to change the Format (for the arrow) and the Text
            hdi.mask = co::HDI::FORMAT | co::HDI::TEXT;
            
            // Define base format (Left alignment)
            hdi.fmt = co::HDF::LEFT | co::HDF::STRING; 

            // 3. Add NATIVE arrow if it's the sorted column
            if col == sort_col {
                if sort_desc {
                    hdi.fmt |= co::HDF::SORTDOWN;
                } else {
                    hdi.fmt |= co::HDF::SORTUP;
                }
            }
            
            // 4. Define text (WITHOUT the arrow this time!)
            let text = clean_tr(&loader.get(col.ftl_key()));
            let mut wtext = winsafe::WString::from_str(&text);
            hdi.set_pszText(Some(&mut wtext));

            // 5. Send message directly to Header
            // This is more robust than LVM_SETCOLUMN for sort flags
            unsafe {
                h_header.SendMessage(msg::hdm::SetItem {
                    index: i as u32,
                    hditem: &hdi,
                });
            }
        }
    }
}

// --- LOGIC FUNCTIONS ---

fn apply_filter_logic(
    all_items: &Arc<RwLock<Vec<RadiusRequest>>>,
    filtered_ids: &Arc<RwLock<Vec<usize>>>,
    query: &str,
    show_errors_only: bool,
    sort_col: LogColumn,
    sort_descending: bool,
) {
    let q = query.trim().to_ascii_lowercase(); // Optimization: lowercase the query once
    
    // 1. Data reading (Read Lock)
    let items = all_items.read().expect("Lock failed");
        
    let mut failed_session_ids = HashSet::new();
    if show_errors_only {
        for item in items.iter() {
            if item.resp_type == "Access-Reject" && !item.session_id.is_empty() {
                failed_session_ids.insert(item.session_id.clone());
            }
        }
    }

    // 2. Filtering (Local collection)
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
            
            // Optimization: pass string already in lowercase
            item.matches(&q)
        })
        .collect();

    // 3. Sorting (On the local collection)
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
    
    // Release read lock before write lock
    drop(items);

    // 4. Result writing (Write Lock - brief)
    let mut filt_guard = filtered_ids.write().expect("Lock failed");
    *filt_guard = ids;
}


// ... (parse_full_logic, process_group, map_packet_type, map_reason, clean_tr, main remain the same)
// I include them so the code is complete.

fn parse_full_logic(path: &str, hwnd: Option<SafeHWND>) -> anyhow::Result<(Vec<RadiusRequest>, usize)> {
    let content = fs::read_to_string(path)?;
    let total_len = content.len() as u64;
    
    use quick_xml::reader::Reader;
    use quick_xml::events::Event as XmlEvent;

    let mut reader = Reader::from_str(&content);
    let mut buf = Vec::new();
    let mut event_blobs = Vec::new();
    let mut last_progress = 0u8;

    // --- PHASE 1: SEQUENTIAL EXTRACTION (0% to 50%) ---
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) if e.name().as_ref() == b"Event" => {
                let start_pos = reader.buffer_position() - (e.name().as_ref().len() as u64) - 2;
                reader.read_to_end_into(e.name(), &mut Vec::new())?;
                let end_pos = reader.buffer_position();
                event_blobs.push(content[start_pos as usize..end_pos as usize].to_string());

                // --- PROGRESS REPORTING (0-50%) ---
                if let Some(sh) = hwnd {
                    let h = sh.h();
                    let pct = ((end_pos * 50) / total_len) as u8;
                    if pct > last_progress {
                        unsafe {
                            let _ = h.PostMessage(msg::WndMsg {
                                msg_id: WM_PROGRESS,
                                wparam: pct as usize,
                                lparam: 0,
                            });
                        }
                        last_progress = pct;
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            _ => (),
        }
        buf.clear();
    }

    let raw_event_count = event_blobs.len();
    if event_blobs.is_empty() {
        return Ok((Vec::new(), 0));
    }

    // --- PHASE 2: PARALLELIZATION WITH RAYON (50% to 100%) ---
    let processed_count = Arc::new(AtomicUsize::new(0));
    let total_blobs = raw_event_count;
    let count_clone = processed_count.clone();

    // Rayon into_par_iter requires Send/Sync. SafeHWND handles this.
    let sync_hwnd_opt = hwnd;

    let events_all: Vec<Event> = event_blobs.into_par_iter()
        .map(move |blob| {
            let res = from_str::<Event>(&blob).ok();
            
            if let Some(sh) = sync_hwnd_opt {
                let h = sh.h();
                let current = count_clone.fetch_add(1, Ordering::Relaxed) + 1;
                let step = (total_blobs / 100).max(1);
                
                if current % step == 0 {
                    let pct = 50 + ((current * 50) / total_blobs);
                    unsafe {
                        let _ = h.PostMessage(msg::WndMsg {
                            msg_id: WM_PROGRESS,
                            wparam: pct as usize,
                            lparam: 0,
                        });
                    }
                }
            }
            res
        })
        .flatten()
        .collect();

    // ... (rest is unchanged) ...

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
            
            // FIX: We take the "Unknown" string out of the loop or hardcode it
            // Avoid accessing LANGUAGE_LOADER in parallel code (Rayon)
            if let Some(user) = &event.sam_account { req.user.clone_from(user); } 
            else if let Some(user) = &event.user_name { req.user.clone_from(user); } 
            else { 
                req.user = "Unknown User".to_string(); 
            }
        } else {
            let this_resp_type = map_packet_type(p_type);
            let code = event.reason_code.as_deref().unwrap_or("0");
            if req.reason.is_empty() || code != "0" {
                 req.resp_type = this_resp_type.clone();
                 req.reason = map_reason(code);
            }
            match p_type {
                "2" => req.bg_color = Some((209, 250, 229)), // Emerald 100 (Modern Green)
                "3" => req.bg_color = Some((255, 228, 230)), // Rose 100 (Modern Red)
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


// Static cache for reason map
static REASON_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

fn get_reason_map() -> &'static HashMap<String, String> {
    REASON_MAP.get_or_init(|| {
        // `include_str!` embeds the JSON file at compile time.
        // Ensure the reason_codes.json file is next to main.rs
        let json_content = include_str!("reason_codes.json");
        
        match serde_json::from_str(json_content) {
            Ok(map) => map,
            Err(e) => {
                eprintln!("Critical error loading reason_codes.json: {}", e);
                HashMap::new() // Returns an empty map on error to avoid crash
            }
        }
    })
}

fn map_reason(code: &str) -> String {
    // Direct search in the HashMap (O(1))
    get_reason_map()
        .get(code)
        .cloned()
        .unwrap_or_else(|| format!("Code {}", code))
}

fn clean_tr(s: &str) -> String {
    s.chars().filter(|&c| !('\u{2066}'..='\u{2069}').contains(&c)).collect()
}

fn main() {
    let loader: FluentLanguageLoader = fluent_language_loader!();
    loader.set_use_isolating(false);
    let requested_languages = DesktopLanguageRequester::requested_languages();
    let _ = i18n_embed::select(&loader, &Localizations, &requested_languages);
    LANGUAGE_LOADER.set(loader).ok();

    let app = MyWindow::new();
    if let Err(e) = app.run() {
        eprintln!("{e}");
    }
}