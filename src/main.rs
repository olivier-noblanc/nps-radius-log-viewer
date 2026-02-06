#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unsafe_code)]

use winsafe::prelude::*;
use winsafe::{gui, co, msg};
use quick_xml::de::from_str;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::fs;
use std::collections::{HashSet, HashMap};
use std::thread;

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
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            window_width: 1200,
            window_height: 800,
            column_widths: vec![150, 120, 120, 110, 150, 130, 150, 350],
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Timestamp, Type, Server, ApIp, ApName, Mac, User, Reason
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
    sort_col:     Arc<Mutex<SortColumn>>,
    sort_desc:    Arc<Mutex<bool>>,
    config:       Arc<Mutex<AppConfig>>,
}

impl MyWindow {
    pub fn new() -> Self {
        let config = AppConfig::load();
        
        let wnd = gui::WindowMain::new(
            gui::WindowMainOpts {
                title: "RADIUS Log Browser - WinSafe Edition",
                class_icon: gui::Icon::Id(1),
                size: (config.window_width, config.window_height),
                style: co::WS::OVERLAPPEDWINDOW,
                ..Default::default()
            },
        );

        let new_self = Self {
            wnd: wnd.clone(),
            lst_logs:     gui::ListView::new(&wnd, gui::ListViewOpts { ..Default::default() }),
            txt_search:   gui::Edit::new(&wnd, gui::EditOpts { ..Default::default() }),
            btn_open:     gui::Button::new(&wnd, gui::ButtonOpts { ..Default::default() }),
            btn_open_folder: gui::Button::new(&wnd, gui::ButtonOpts { ..Default::default() }),
            btn_rejects:  gui::Button::new(&wnd, gui::ButtonOpts { ..Default::default() }),
            cb_append:    gui::CheckBox::new(&wnd, gui::CheckBoxOpts { ..Default::default() }),
            btn_copy:     gui::Button::new(&wnd, gui::ButtonOpts { ..Default::default() }),
            lbl_status:   gui::Label::new(&wnd, gui::LabelOpts { ..Default::default() }),
            all_items:    Arc::new(Mutex::new(Vec::new())),
            raw_count:    Arc::new(Mutex::new(0)),
            filtered_ids: Arc::new(Mutex::new(Vec::new())),
            show_errors:  Arc::new(Mutex::new(false)),
            sort_col:     Arc::new(Mutex::new(SortColumn::Timestamp)),
            sort_desc:    Arc::new(Mutex::new(true)),
            config:       Arc::new(Mutex::new(config.clone())),
        };

        new_self.setup_widgets(&config);
        new_self.on_init();
        new_self.on_events();
        new_self
    }

    fn setup_widgets(&self, _config: &AppConfig) {
        let _ = self.btn_open.hwnd().SetWindowText("📂 Ouvrir Log");
        self.btn_open.hwnd().SetWindowPos(winsafe::HwndPlace::None, winsafe::POINT { x: 10, y: 10 }, winsafe::SIZE { cx: 120, cy: 30 }, co::SWP::NOZORDER).expect("Pos failed");

        let _ = self.btn_open_folder.hwnd().SetWindowText("📂 Dossier");
        self.btn_open_folder.hwnd().SetWindowPos(winsafe::HwndPlace::None, winsafe::POINT { x: 140, y: 10 }, winsafe::SIZE { cx: 120, cy: 30 }, co::SWP::NOZORDER).expect("Pos failed");

        let _ = self.btn_rejects.hwnd().SetWindowText("⚠️ Erreurs");
        self.btn_rejects.hwnd().SetWindowPos(winsafe::HwndPlace::None, winsafe::POINT { x: 270, y: 10 }, winsafe::SIZE { cx: 120, cy: 30 }, co::SWP::NOZORDER).expect("Pos failed");

        self.txt_search.hwnd().SetWindowPos(winsafe::HwndPlace::None, winsafe::POINT { x: 400, y: 14 }, winsafe::SIZE { cx: 200, cy: 22 }, co::SWP::NOZORDER).expect("Pos failed");

        let _ = self.cb_append.hwnd().SetWindowText("Append");
        self.cb_append.hwnd().SetWindowPos(winsafe::HwndPlace::None, winsafe::POINT { x: 610, y: 14 }, winsafe::SIZE { cx: 80, cy: 20 }, co::SWP::NOZORDER).expect("Pos failed");

        let _ = self.btn_copy.hwnd().SetWindowText("📋 Copier");
        self.btn_copy.hwnd().SetWindowPos(winsafe::HwndPlace::None, winsafe::POINT { x: 700, y: 10 }, winsafe::SIZE { cx: 100, cy: 30 }, co::SWP::NOZORDER).expect("Pos failed");

        // Extended styles for ListView
        unsafe {
            self.lst_logs.hwnd().SendMessage(msg::lvm::SetExtendedListViewStyle {
                mask: co::LVS_EX::FULLROWSELECT | co::LVS_EX::DOUBLEBUFFER,
                style: co::LVS_EX::FULLROWSELECT | co::LVS_EX::DOUBLEBUFFER,
            });
        }

        let _ = self.lbl_status.hwnd().SetWindowText("Prêt. Ouvrez un fichier log.");
    }

    fn on_init(&self) {
        let config_init = self.config.lock().expect("Lock failed");
        
        for (i, &w) in config_init.column_widths.iter().enumerate() {
            self.lst_logs.cols().add("", w as _).expect("Add column failed");
            if i == 8 { break; } 
        }
        
        let _cols = self.lst_logs.cols();
        let cw = &config_init.column_widths;
        
        // Titles are added during the first add or via LVM_SETCOLUMN
        // For simplicity, let's just use the Titles in cols().add in a WM_CREATE or here if not already added.
        // Actually, let's clear and re-add to be sure.
        while self.lst_logs.cols().count().expect("Count failed") > 0 {
            unsafe {
                let _ = self.lst_logs.hwnd().SendMessage(msg::lvm::DeleteColumn { index: 0 });
            }
        }

        self.lst_logs.cols().add("Horodatage", cw.get(0).copied().unwrap_or(150)).expect("Add col failed");
        self.lst_logs.cols().add("Type de Paquet", cw.get(1).copied().unwrap_or(120)).expect("Add col failed");
        self.lst_logs.cols().add("Serveur", cw.get(2).copied().unwrap_or(120)).expect("Add col failed");
        self.lst_logs.cols().add("IP AP", cw.get(3).copied().unwrap_or(110)).expect("Add col failed");
        self.lst_logs.cols().add("Nom AP", cw.get(4).copied().unwrap_or(150)).expect("Add col failed");
        self.lst_logs.cols().add("MAC Client", cw.get(5).copied().unwrap_or(130)).expect("Add col failed");
        self.lst_logs.cols().add("Utilisateur", cw.get(6).copied().unwrap_or(150)).expect("Add col failed");
        self.lst_logs.cols().add("Résultat/Raison", cw.get(7).copied().unwrap_or(350)).expect("Add col failed");
        self.lst_logs.cols().add("Session ID", cw.get(8).copied().unwrap_or(150)).expect("Add col failed");
        
        self.wnd.on().wm_close({
            let me = self.clone();
            move || {
                let mut config_save = me.config.lock().expect("Lock failed");
                let mut cw_v = Vec::new();
                for i in 0..9 {
                    unsafe {
                        cw_v.push(me.lst_logs.hwnd().SendMessage(msg::lvm::GetColumnWidth { index: i as _ }).expect("Get column width failed") as i32);
                    }
                }
                config_save.column_widths = cw_v;
                
                let rect = me.wnd.hwnd().GetWindowRect().expect("Get window rect failed");
                config_save.window_width = rect.right - rect.left;
                config_save.window_height = rect.bottom - rect.top;
                
                let _ = config_save.save();
                winsafe::PostQuitMessage(0);
                Ok(())
            }
        });

        self.wnd.on().wm_create({
            let me = self.clone();
            move |_| {
                if let Ok(hicon_guard) = winsafe::HINSTANCE::GetModuleHandle(None).unwrap().LoadIcon(winsafe::IdIdiStr::Id(1)) {
                     unsafe {
                        let _ = me.wnd.hwnd().SendMessage(msg::wm::SetIcon { hicon: winsafe::HICON::from_ptr(hicon_guard.ptr()), size: co::ICON_SZ::BIG });
                    }
                }
                Ok(0)
            }
        });
        
        self.wnd.on().wm(WM_LOAD_DONE, {
            let me = self.clone();
            move |_| {
                let count = me.filtered_ids.lock().expect("Lock failed").len();
                let raw = me.raw_count.lock().expect("Lock failed");
                me.lst_logs.items().set_count(count as _, None).expect("Set count failed");
                let _ = me.lbl_status.hwnd().SetWindowText(&format!("Affichage : {count} sessions ({raw} événements bruts)."));
                me.lst_logs.hwnd().InvalidateRect(None, true).expect("Invalidate rect failed");
                Ok(0)
            }
        });

        self.wnd.on().wm(WM_LOAD_ERROR, {
            let me = self.clone();
            move |_| {
                let _ = me.lbl_status.hwnd().SetWindowText("Erreur lors du chargement.");
                Ok(0)
            }
        });

        self.wnd.on().wm_size({
            let me = self.clone();
            move |p| {
                if p.request != co::SIZE_R::MINIMIZED {
                    let _ = me.lst_logs.hwnd().SetWindowPos(
                        winsafe::HwndPlace::None,
                        winsafe::POINT { x: 10, y: 50 },
                        winsafe::SIZE { cx: p.client_area.cx - 20, cy: p.client_area.cy - 100 },
                        co::SWP::NOZORDER,
                    );
                    
                    let _ = me.lbl_status.hwnd().SetWindowPos(
                        winsafe::HwndPlace::None,
                        winsafe::POINT { x: 10, y: p.client_area.cy - 30 },
                        winsafe::SIZE { cx: p.client_area.cx - 20, cy: 25 },
                        co::SWP::NOZORDER,
                    );
                }
                Ok(())
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

        self.lst_logs.on().nm_r_click({
            let me = self.clone();
            move |_| me.on_lst_nm_r_click().map(|r| r as i32)
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
            move |p| me.on_lst_nm_custom_draw(p)
        });
    }

    fn on_btn_open_clicked(&self) -> winsafe::AnyResult<()> {
        let file_dialog = winsafe::CoCreateInstance::<winsafe::IFileOpenDialog>(
            &co::CLSID::FileOpenDialog,
            None::<&winsafe::IUnknown>,
            co::CLSCTX::INPROC_SERVER,
        )?;
        
        file_dialog.SetFileTypes(&[("Log files", "*.log"), ("All files", "*.*")])?;
        
        if file_dialog.Show(self.wnd.hwnd())? {
            let result = file_dialog.GetResult()?;
            let path = result.GetDisplayName(co::SIGDN::FILESYSPATH)?;
            
            let _ = self.lbl_status.hwnd().SetWindowText("Chargement en cours...");
            
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
            
            let _ = self.lbl_status.hwnd().SetWindowText("Chargement du dossier...");
            
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

    fn on_lst_nm_r_click(&self) -> winsafe::AnyResult<isize> {
        let mut pt = winsafe::GetCursorPos().expect("GetCursorPos failed");
        pt = self.lst_logs.hwnd().ScreenToClient(pt).expect("ScreenToClient failed");

        let mut lvhti = winsafe::LVHITTESTINFO {
            pt,
            ..Default::default()
        };

        if unsafe { self.lst_logs.hwnd().SendMessage(msg::lvm::HitTest { info: &mut lvhti }).is_some() }
            && lvhti.iItem != -1 {
                let h_menu = winsafe::HMENU::CreatePopupMenu()?;
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1001), winsafe::BmpPtrStr::from_str("📋 Copier la cellule"))?;
                h_menu.AppendMenu(co::MF::STRING, winsafe::IdMenu::Id(1002), winsafe::BmpPtrStr::from_str("🔍 Filtrer par cette valeur"))?;

                let cursor_pos = winsafe::GetCursorPos().expect("GetCursorPos failed");
                if let Some(cmd_id) = h_menu.TrackPopupMenu(co::TPM::RETURNCMD | co::TPM::LEFTALIGN, cursor_pos, self.lst_logs.hwnd())? {
                    let cell_text = self.lst_logs.items().get(lvhti.iItem as _).text(lvhti.iSubItem as _);
                    match cmd_id as u16 {
                        1001 => {
                            let _ = clipboard_win::set_clipboard_string(&cell_text);
                        },
                        1002 => {
                            let _ = self.txt_search.hwnd().SetWindowText(&cell_text);
                            self.on_txt_search_en_change()?;
                        },
                        _ => {}
                    }
                }
        }
        Ok(0)
    }

    fn on_lst_lvn_get_disp_info(&self, p: &winsafe::NMLVDISPINFO) -> winsafe::AnyResult<()> {
        let items = self.all_items.lock().expect("Lock failed");
        let filtered = self.filtered_ids.lock().expect("Lock failed");
        
        let item_idx = p.item.iItem;
        if item_idx < 0 || item_idx >= filtered.len() as i32 { return Ok(()); }

        let real_idx = filtered[item_idx as usize];
        let req = &items[real_idx];

        let col_idx = p.item.iSubItem;
        let text = match col_idx {
            0 => &req.timestamp,
            1 => &req.req_type,
            2 => &req.server,
            3 => &req.ap_ip,
            4 => &req.ap_name,
            5 => &req.mac,
            6 => &req.user,
            7 => if req.reason.is_empty() { &req.resp_type } else { &req.reason },
            8 => &req.session_id,
            _ => "",
        };
        let mut wstr = winsafe::WString::from_str(text);
        let p_ptr = p as *const _ as *mut winsafe::NMLVDISPINFO;
        unsafe {
            (*p_ptr).item.set_pszText(Some(&mut wstr));
        }
        Ok(())
    }

    fn on_lst_lvn_column_click(&self, p: &winsafe::NMLISTVIEW) -> winsafe::AnyResult<()> {
        let mut sort_col_g = self.sort_col.lock().expect("Lock failed");
        let mut sort_desc_g = self.sort_desc.lock().expect("Lock failed");

        let new_col = match p.iSubItem {
            0 => SortColumn::Timestamp,
            1 => SortColumn::Type,
            2 => SortColumn::Server,
            3 => SortColumn::ApIp,
            4 => SortColumn::ApName,
            5 => SortColumn::Mac,
            6 => SortColumn::User,
            7 => SortColumn::Reason,
            8 => SortColumn::Timestamp, // Session ID, use timestamp for now
            _ => return Ok(()),
        };

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
        let _ = self.btn_rejects.hwnd().SetWindowText(if is_on { "⚠️ Tout afficher" } else { "⚠️ Erreurs" });
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

    fn on_lst_nm_custom_draw(&self, p: &winsafe::NMLVCUSTOMDRAW) -> winsafe::AnyResult<co::CDRF> {
        if p.mcd.dwDrawStage == co::CDDS::PREPAINT {
            Ok(co::CDRF::NOTIFYITEMDRAW)
        } else if p.mcd.dwDrawStage == co::CDDS::ITEMPREPAINT {
            let items = self.all_items.lock().expect("Lock failed");
            let ids = self.filtered_ids.lock().expect("Lock failed");
            if let Some(&idx) = ids.get(p.mcd.dwItemSpec) {
                if let Some((r, g, b)) = items[idx].bg_color {
                    let p_ptr = p as *const _ as *mut winsafe::NMLVCUSTOMDRAW;
                    unsafe {
                        (*p_ptr).clrTextBk = winsafe::COLORREF::from_rgb(r, g, b);
                    }
                }
            }
            Ok(co::CDRF::DODEFAULT)
        } else {
            Ok(co::CDRF::DODEFAULT)
        }
    }

    pub fn run(&self) -> winsafe::AnyResult<i32> {
        self.wnd.run_main(None)
    }
}

// --- LOGIC FUNCTIONS ---

fn apply_filter_logic(
    all_items: &Arc<Mutex<Vec<RadiusRequest>>>,
    filtered_ids: &Arc<Mutex<Vec<usize>>>,
    query: &str,
    show_errors_only: bool,
    sort_col: SortColumn,
    sort_descending: bool,
) {
    let q = query.trim().to_lowercase();
    
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
            SortColumn::Timestamp => a.timestamp.cmp(&b.timestamp),
            SortColumn::Type => a.req_type.cmp(&b.req_type),
            SortColumn::Server => a.server.cmp(&b.server),
            SortColumn::ApIp => a.ap_ip.cmp(&b.ap_ip),
            SortColumn::ApName => a.ap_name.cmp(&b.ap_name),
            SortColumn::Mac => a.mac.cmp(&b.mac),
            SortColumn::User => a.user.cmp(&b.user),
            SortColumn::Reason => {
                let r_a = if a.reason.is_empty() { &a.resp_type } else { &a.reason };
                let r_b = if b.reason.is_empty() { &b.resp_type } else { &b.reason };
                r_a.cmp(r_b)
            }
        };
        if sort_descending { ord.reverse() } else { ord }
    });

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
            else { req.user = "- INCONNU -".to_string(); }
        } else {
            req.resp_type = map_packet_type(p_type);
            req.reason = map_reason(event.reason_code.as_deref().unwrap_or("0"));
            match p_type {
                "2" => req.bg_color = Some((188, 255, 188)),
                "3" => req.bg_color = Some((255, 188, 188)),
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
        _ => format!("Code {code}"),
    }
}

fn main() {
    let app = MyWindow::new();
    if let Err(e) = app.run() {
        eprintln!("{e}");
    }
}
