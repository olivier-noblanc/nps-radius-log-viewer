#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use winsafe::prelude::*;
use winsafe::{gui, co, msg};
use quick_xml::de::from_str;
use rayon::prelude::*;
use serde::Deserialize;
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

struct MyWindow {
    wnd:          gui::WindowMain,
    lst_logs:     gui::ListView,
    txt_search:   gui::Edit,
    btn_open:     gui::Button,
    btn_rejects:  gui::Button,
    btn_copy:     gui::Button,
    lbl_status:   gui::Label,
    
    all_items:    Arc<Mutex<Vec<RadiusRequest>>>,
    raw_count:    Arc<Mutex<usize>>,
    filtered_ids: Arc<Mutex<Vec<usize>>>,
    show_errors:  Arc<Mutex<bool>>,
    sort_col:     Arc<Mutex<SortColumn>>,
    sort_desc:    Arc<Mutex<bool>>,
}

impl MyWindow {
    pub fn new() -> Self {
        let wnd = gui::WindowMain::new(
            gui::WindowMainOpts {
                title: "RADIUS Log Browser - WinSafe Edition",
                class_icon: gui::Icon::Id(1),
                size: (1200, 800),
                style: co::WS::OVERLAPPEDWINDOW,
                ..Default::default()
            },
        );

        let btn_open = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "📂 Ouvrir Log",
                position: (10, 10),
                width: 110,
                height: 30,
                ..Default::default()
            },
        );

        let btn_rejects = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "⚠️ Sessions échouées",
                position: (130, 10),
                width: 150,
                height: 30,
                ..Default::default()
            },
        );

        let txt_search = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                position: (290, 13),
                width: 300,
                ..Default::default()
            },
        );

        let btn_copy = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "📋 Copier Ligne",
                position: (600, 10),
                width: 110,
                height: 30,
                ..Default::default()
            },
        );

        let lst_logs = gui::ListView::new(
            &wnd,
            gui::ListViewOpts {
                position: (10, 50),
                size: (1180, 710),
                control_style: co::LVS::REPORT | co::LVS::SHOWSELALWAYS | co::LVS::OWNERDATA,
                ..Default::default()
            },
        );

        let lbl_status = gui::Label::new(
            &wnd,
            gui::LabelOpts {
                text: "Prêt. Ouvrez un fichier log.",
                position: (10, 765),
                ..Default::default()
            },
        );

        let new_self = Self {
            wnd,
            lst_logs,
            txt_search,
            btn_open,
            btn_rejects,
            btn_copy,
            lbl_status,
            all_items:    Arc::new(Mutex::new(Vec::new())),
            raw_count:    Arc::new(Mutex::new(0)),
            filtered_ids: Arc::new(Mutex::new(Vec::new())),
            show_errors: Arc::new(Mutex::new(false)),
            sort_col: Arc::new(Mutex::new(SortColumn::Timestamp)),
            sort_desc: Arc::new(Mutex::new(true)),
        };

        new_self.on_init();
        new_self.on_events();
        new_self
    }

    fn on_init(&self) {
        let lst = self.lst_logs.clone();
        self.wnd.on().wm_create(move |_| {
            let cols = lst.cols();
            cols.add("Timestamp", 150)?;
            cols.add("Type", 120)?;
            cols.add("Serveur", 120)?;
            cols.add("AP IP", 110)?;
            cols.add("Nom AP", 150)?;
            cols.add("MAC", 130)?;
            cols.add("Utilisateur", 150)?;
            cols.add("Résultat/Raison", 350)?;
            lst.set_extended_style(true, co::LVS_EX::FULLROWSELECT | co::LVS_EX::GRIDLINES | co::LVS_EX::DOUBLEBUFFER);
            Ok(0)
        });
        
        let lbl = self.lbl_status.clone();
        let all_it = self.all_items.clone();
        let filt_id = self.filtered_ids.clone();
        let raw_count = self.raw_count.clone();
        let wnd = self.wnd.clone();
        let lst = self.lst_logs.clone();

        // --- CUSTOM MESSAGES ---
        wnd.on().wm(WM_LOAD_DONE, {
            let lst = lst.clone();
            let lbl = lbl.clone();
            let all_it = all_it.clone();
            let raw_c = raw_count.clone();
            let filt_id = filt_id.clone();
            move |_| {
                let count = filt_id.lock().unwrap().len();
                let total = all_it.lock().unwrap().len();
                let raw = *raw_c.lock().unwrap();
                lst.items().set_count(count as _, None).unwrap();
                lbl.hwnd().SetWindowText(&format!("{} événements décodés en {} sessions ({} affichées).", raw, total, count)).unwrap();
                Ok(0)
            }
        });

        wnd.on().wm(WM_LOAD_ERROR, {
            let lbl = lbl.clone();
            move |_| {
                lbl.hwnd().SetWindowText("Erreur lors du chargement.").unwrap();
                Ok(0)
            }
        });

        self.wnd.on().wm_size({
            let lst_logs = self.lst_logs.clone();
            let lbl_status = self.lbl_status.clone();
            move |p| {
                if p.request != co::SIZE_R::MINIMIZED {
                    lst_logs.hwnd().SetWindowPos(
                        winsafe::HwndPlace::Place(co::HWND_PLACE::TOP),
                        winsafe::POINT { x: 10, y: 50 },
                        winsafe::SIZE { cx: p.client_area.cx - 20, cy: p.client_area.cy - 100 },
                        co::SWP::NOZORDER,
                    ).unwrap();
                    
                    lbl_status.hwnd().SetWindowPos(
                        winsafe::HwndPlace::Place(co::HWND_PLACE::TOP),
                        winsafe::POINT { x: 10, y: p.client_area.cy - 30 },
                        winsafe::SIZE { cx: p.client_area.cx - 20, cy: 25 },
                        co::SWP::NOZORDER,
                    ).unwrap();
                }
                Ok(())
            }
        });
    }

    fn on_events(&self) {
        let wnd = self.wnd.clone();
        let lst = self.lst_logs.clone();
        let txt = self.txt_search.clone();
        let lbl = self.lbl_status.clone();
        let all_it = self.all_items.clone();
        let filt_id = self.filtered_ids.clone();
        let raw_count = self.raw_count.clone();
        let show_err = self.show_errors.clone();
        let sort_c = self.sort_col.clone();
        let sort_d = self.sort_desc.clone();

        // --- BUTTON: OPEN ---
        let wnd_c = wnd.clone();
        let lst_c = lst.clone();
        let lbl_c = lbl.clone();
        let all_it_c = all_it.clone();
        let filt_id_c = filt_id.clone();
        let raw_count_c = raw_count.clone();
        let show_err_c = show_err.clone();
        let sort_c_c = sort_c.clone();
        let sort_d_c = sort_d.clone();
        let txt_c = txt.clone();

        self.btn_open.on().bn_clicked(move || {
            let file_dialog = winsafe::CoCreateInstance::<winsafe::IFileOpenDialog>(
                &co::CLSID::FileOpenDialog,
                None::<&winsafe::IUnknown>,
                co::CLSCTX::INPROC_SERVER,
            )?;
            
            file_dialog.SetFileTypes(&[("Log files", "*.log"), ("All files", "*.*")])?;
            
            if file_dialog.Show(&wnd_c.hwnd())? {
                let result = file_dialog.GetResult()?;
                let path = result.GetDisplayName(co::SIGDN::FILESYSPATH)?;
                
                lbl_c.hwnd().SetWindowText("Chargement en cours...")?;
                
                let query = txt_c.text().unwrap_or_default();
                let show_err_val = *show_err_c.lock().unwrap();
                let sort_c_val = *sort_c_c.lock().unwrap();
                let sort_d_val = *sort_d_c.lock().unwrap();

                let all_it_bg = all_it_c.clone();
                let raw_c_bg = raw_count_c.clone();
                let filt_id_bg = filt_id_c.clone();
                let show_err_bg = show_err_c.clone();

                let hwnd_raw = wnd_c.hwnd().ptr() as usize;

                thread::spawn(move || {
                    let hwnd_bg = unsafe { winsafe::HWND::from_ptr(hwnd_raw as _) };
                    match parse_full_logic(&path) {
                        Ok((items, raw_total)) => {
                            let mut all_guard = all_it_bg.lock().unwrap();
                            *all_guard = items;
                            drop(all_guard);
                            
                            *raw_c_bg.lock().unwrap() = raw_total;

                            apply_filter_logic(
                                &all_it_bg, 
                                &filt_id_bg, 
                                &query, 
                                show_err_val,
                                sort_c_val,
                                sort_d_val
                            );
                            
                            unsafe {
                                hwnd_bg.PostMessage(msg::WndMsg {
                                    msg_id: WM_LOAD_DONE,
                                    wparam: 0,
                                    lparam: 0,
                                }).unwrap();
                            }
                        }
                        Err(e) => {
                            let _err_msg = e.to_string();
                            unsafe {
                                hwnd_bg.PostMessage(msg::WndMsg {
                                    msg_id: WM_LOAD_ERROR,
                                    wparam: 0,
                                    lparam: 0,
                                }).unwrap();
                            }
                        }
                    }
                });
            }
            Ok(())
        });

        // --- SEARCH INPUT ---
        let lst_c = lst.clone();
        let lbl_c = lbl.clone();
        let all_it_c = all_it.clone();
        let filt_id_c = filt_id.clone();
        let txt_c = txt.clone();
        let show_err_c = show_err.clone();
        let sort_c_c = sort_c.clone();
        let sort_d_c = sort_d.clone();

        self.txt_search.on().en_change(move || {
            apply_filter_logic(
                &all_it_c, 
                &filt_id_c, 
                &txt_c.text().unwrap_or_default(), 
                *show_err_c.lock().unwrap(),
                *sort_c_c.lock().unwrap(),
                *sort_d_c.lock().unwrap()
            );
            let count = filt_id_c.lock().unwrap().len();
            lst_c.items().set_count(count as _, None)?;
            lbl_c.hwnd().SetWindowText(&format!("Affichage : {} événements.", count))?;
            Ok(())
        });

        // --- BUTTON: REJECTS ---
        let btn_rejects_c = self.btn_rejects.clone();
        let lst_c = lst.clone();
        let txt_c = txt.clone();
        let all_it_c = all_it.clone();
        let filt_id_c = filt_id.clone();
        let show_err_c = show_err.clone();
        let sort_c_c = sort_c.clone();
        let sort_d_c = sort_d.clone();

        self.btn_rejects.on().bn_clicked(move || {
            let mut guard = show_err_c.lock().unwrap();
            *guard = !*guard;
            let is_on = *guard;
            btn_rejects_c.hwnd().SetWindowText(if is_on { "⚠️ Tout afficher" } else { "⚠️ Sessions échouées" })?;
            drop(guard);

            apply_filter_logic(
                &all_it_c, 
                &filt_id_c, 
                &txt_c.text().unwrap_or_default(), 
                is_on,
                *sort_c_c.lock().unwrap(),
                *sort_d_c.lock().unwrap()
            );
            lst_c.items().set_count(filt_id_c.lock().unwrap().len() as _, None)?;
            Ok(())
        });

        // --- LIST VIEW: VIRTUAL DATA ---
        let all_it_c = all_it.clone();
        let filt_id_c = filt_id.clone();
        self.lst_logs.on().lvn_get_disp_info(move |p| {
            let items = all_it_c.lock().unwrap();
            let ids = filt_id_c.lock().unwrap();
            if let Some(&idx) = ids.get(p.item.iItem as usize) {
                let item = &items[idx];
                let val = match p.item.iSubItem {
                    0 => &item.timestamp,
                    1 => &item.req_type,
                    2 => &item.server,
                    3 => &item.ap_ip,
                    4 => &item.ap_name,
                    5 => &item.mac,
                    6 => &item.user,
                    7 => if item.reason.is_empty() { &item.resp_type } else { &item.reason },
                    _ => "",
                };
                if p.item.mask.has(co::LVIF::TEXT) {
                    let (ptr, len) = p.item.raw_pszText();
                    if !ptr.is_null() && len > 0 {
                        let wide = val.encode_utf16().collect::<Vec<_>>();
                        let copy_len = wide.len().min(len as usize - 1);
                        unsafe {
                            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, copy_len);
                            std::ptr::write(ptr.add(copy_len), 0);
                        }
                    }
                }
            }
            Ok(())
        });

        // --- LIST VIEW: CUSTOM DRAW (Colors) ---
        let all_it_c = all_it.clone();
        let filt_id_c = filt_id.clone();
        lst.on().nm_custom_draw(move |p| {
            if p.mcd.dwDrawStage == co::CDDS::PREPAINT {
                return Ok(co::CDRF::NOTIFYITEMDRAW);
            } else if p.mcd.dwDrawStage == co::CDDS::ITEMPREPAINT {
                let items = all_it_c.lock().unwrap();
                let ids = filt_id_c.lock().unwrap();
                if let Some(&idx) = ids.get(p.mcd.dwItemSpec as usize) {
                    if let Some((r, g, b)) = items[idx].bg_color {
                        p.clrTextBk = winsafe::COLORREF::from_rgb(r, g, b);
                    }
                }
            }
            Ok(co::CDRF::DODEFAULT)
        });

        // --- LIST VIEW: SORTING ---
        let lst_c = lst.clone();
        let all_it_c = all_it.clone();
        let filt_id_c = filt_id.clone();
        let txt_c = txt.clone();
        let show_err_c = show_err.clone();
        let sort_c_c = sort_c.clone();
        let sort_d_c = sort_d.clone();

        lst.on().lvn_column_click(move |p| {
            let col = match p.iSubItem {
                0 => SortColumn::Timestamp,
                1 => SortColumn::Type,
                2 => SortColumn::Server,
                3 => SortColumn::ApIp,
                4 => SortColumn::ApName,
                5 => SortColumn::Mac,
                6 => SortColumn::User,
                7 => SortColumn::Reason,
                _ => return Ok(()),
            };

            let mut sc = sort_c_c.lock().unwrap();
            let mut sd = sort_d_c.lock().unwrap();
            if *sc == col {
                *sd = !*sd;
            } else {
                *sc = col;
                *sd = col == SortColumn::Timestamp;
            }
            let desc = *sd;
            drop(sc);
            drop(sd);

            apply_filter_logic(&all_it_c, &filt_id_c, &txt_c.text().unwrap_or_default(), *show_err_c.lock().unwrap(), col, desc);
            lst_c.items().set_count(filt_id_c.lock().unwrap().len() as _, None)?;
            // Scroll to top by ensuring index 0 is visible
            lst_c.items().get(0).ensure_visible()?;
            Ok(())
        });

        // --- BUTTON: COPY ---
        let lst_c = lst.clone();
        let all_it_c = all_it.clone();
        let filt_id_c = filt_id.clone();
        self.btn_copy.on().bn_clicked(move || {
            if let Some(iitem) = lst_c.items().iter_selected().next() {
                let items = all_it_c.lock().unwrap();
                let ids = filt_id_c.lock().unwrap();
                if let Some(&idx) = ids.get(iitem.index() as usize) {
                    let tsv = items[idx].to_tsv();
                    let hwnd = winsafe::HWND::GetDesktopWindow();
                    let hclip = hwnd.OpenClipboard()?;
                    hclip.EmptyClipboard()?;
                    
                    let bytes = tsv.as_bytes(); // SetClipboardData expects bytes
                    hclip.SetClipboardData(co::CF::TEXT, bytes)?;
                }
            }
            Ok(())
        });
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
    let items = all_items.lock().unwrap();
    let q = query.trim().to_lowercase();
    
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

    let mut filt_guard = filtered_ids.lock().unwrap();
    *filt_guard = ids;
}

fn parse_full_logic(path: &str) -> anyhow::Result<(Vec<RadiusRequest>, usize)> {
    let content = fs::read_to_string(path)?;
    // Wrap to make it a valid XML if it's just a list of fragments
    let wrapped = if content.trim().starts_with("<events>") {
        content
    } else {
        format!("<events>{}</events>", content)
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
        "0" => "Succès".to_string(),
        "1" => "Erreur NPS".to_string(),
        "8" => "Utilisateur inexistant".to_string(),
        "16" => "Mauvais identifiants".to_string(),
        "22" => "Erreur EAP".to_string(),
        _ => format!("Code {}", code),
    }
}

fn main() {
    let app = MyWindow::new();
    if let Err(e) = app.run() {
        eprintln!("{}", e);
    }
}
