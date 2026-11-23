//! egui desktop front-end.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use eframe::egui;
use egui::{Color32, CornerRadius, FontId, Margin, RichText, Stroke};

use pcap_rw::analyze::{analyze, proto_name};
use pcap_rw::capture::{self, format_size};
use pcap_rw::link::{parse_ip_any, Ip};
use pcap_rw::rewrite::{Mapping, Rewriter};
use pcap_rw::verify::verify;

use crate::cli::{derive_output, Naming};

const BG: Color32 = Color32::from_rgb(0xF6, 0xF8, 0xFB);
const CARD: Color32 = Color32::WHITE;
const BORDER: Color32 = Color32::from_rgb(0xE2, 0xE8, 0xF0);
const TEXT: Color32 = Color32::from_rgb(0x1E, 0x29, 0x3B);
const MUTED: Color32 = Color32::from_rgb(0x64, 0x74, 0x8B);
const BLUE: Color32 = Color32::from_rgb(0x25, 0x63, 0xEB);
const BLUE_DARK: Color32 = Color32::from_rgb(0x1D, 0x4E, 0xD8);
const GREEN: Color32 = Color32::from_rgb(0x15, 0x80, 0x3D);
const RED: Color32 = Color32::from_rgb(0xB9, 0x1C, 0x1C);
const AMBER: Color32 = Color32::from_rgb(0xB4, 0x53, 0x09);

#[derive(Clone, Copy, PartialEq, Eq)]
enum NamingChoice {
    Replace,
    Suffix,
    Keep,
}

impl NamingChoice {
    fn to_naming(self) -> Naming {
        match self {
            NamingChoice::Replace => Naming::Replace,
            NamingChoice::Suffix => Naming::Suffix,
            NamingChoice::Keep => Naming::Keep,
        }
    }
    fn label(self) -> &'static str {
        match self {
            NamingChoice::Replace => "替换文件名中的旧 IP",
            NamingChoice::Suffix => "文件名追加 _new",
            NamingChoice::Keep => "保持原文件名（换目录）",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Scanning,
    Ready,
    Queued,
    Running,
    Done,
    Failed,
}

struct FileEntry {
    path: PathBuf,
    name: String,
    size: u64,
    packets: usize,
    kind: &'static str,
    status: Status,
    note: String,
    enabled: bool,
    ips: Vec<(Ip, usize)>,
    payload_hint: usize,
}

impl FileEntry {
    fn new(path: PathBuf) -> Self {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("(未知文件)")
            .to_string();
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        FileEntry {
            path,
            name,
            size,
            packets: 0,
            kind: "",
            status: Status::Scanning,
            note: "读取中…".to_string(),
            enabled: true,
            ips: Vec::new(),
            payload_hint: 0,
        }
    }

    fn status_text(&self) -> (String, Color32) {
        match self.status {
            Status::Scanning => ("读取中".into(), AMBER),
            Status::Ready => ("就绪".into(), MUTED),
            Status::Queued => ("排队中".into(), MUTED),
            Status::Running => ("改写中".into(), BLUE),
            Status::Done => ("已完成".into(), GREEN),
            Status::Failed => ("失败".into(), RED),
        }
    }
}

struct MapRow {
    old: String,
    new: String,
    count: usize,
}

struct LogLine {
    text: String,
    level: LogLevel,
}

#[derive(Clone, Copy)]
enum LogLevel {
    Info,
    Good,
    Warn,
    Error,
}

enum Msg {
    Scanned {
        idx: usize,
        result: Result<ScanInfo, String>,
    },
    FileProgress {
        idx: usize,
        done: usize,
        total: usize,
    },
    FileDone {
        idx: usize,
        result: Result<String, String>,
    },
    BatchDone {
        ok: usize,
        failed: usize,
        cancelled: bool,
    },
}

struct ScanInfo {
    packets: usize,
    kind: &'static str,
    ips: Vec<(Ip, usize)>,
    payload_hint: usize,
    note: String,
}

pub struct App {
    files: Vec<FileEntry>,
    rows: Vec<MapRow>,
    out_dir: String,
    naming: NamingChoice,
    replace_payload: bool,
    do_verify: bool,
    overwrite: bool,
    logs: Vec<LogLine>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    cancel: Arc<AtomicBool>,
    running: bool,
    progress: f32,
    progress_note: String,
    batch_total: usize,
    batch_done: usize,
    toast: Option<(String, bool)>,
    drag_active: bool,
    screenshot_path: Option<String>,
    demo_map: Option<String>,
    demo_map_applied: bool,
    autorun: bool,
    autorun_started: bool,
    frame_count: u32,
}

impl App {
    fn new(screenshot_path: Option<String>) -> Self {
        let (tx, rx) = channel();
        App {
            files: Vec::new(),
            rows: Vec::new(),
            out_dir: String::new(),
            naming: NamingChoice::Replace,
            replace_payload: false,
            do_verify: true,
            overwrite: false,
            logs: Vec::new(),
            tx,
            rx,
            cancel: Arc::new(AtomicBool::new(false)),
            running: false,
            progress: 0.0,
            progress_note: "等待任务".to_string(),
            batch_total: 0,
            batch_done: 0,
            toast: None,
            drag_active: false,
            screenshot_path,
            demo_map: std::env::var("PCAPRW_DEMO_MAP").ok(),
            demo_map_applied: false,
            autorun: std::env::var("PCAPRW_AUTORUN").is_ok(),
            autorun_started: false,
            frame_count: 0,
        }
    }

    /// Fills the "new address" column from PCAPRW_DEMO_MAP (screenshot helper).
    fn apply_demo_map(&mut self) {
        if self.demo_map_applied {
            return;
        }
        let Some(spec) = self.demo_map.clone() else { return };
        if self.files.iter().any(|f| f.status == Status::Scanning) || self.rows.is_empty() {
            return;
        }
        for pair in spec.split(';').filter(|p| !p.is_empty()) {
            if let Some((old, new)) = pair.split_once('=') {
                for row in self.rows.iter_mut() {
                    if row.old == old.trim() {
                        row.new = new.trim().to_string();
                    }
                }
            }
        }
        self.demo_map_applied = true;
    }

    /// Headless helper: start the batch automatically once scanning settles.
    fn maybe_autorun(&mut self) {
        if !self.autorun || self.autorun_started || self.running {
            return;
        }
        if self.files.is_empty()
            || self.files.iter().any(|f| f.status == Status::Scanning)
            || self.rows.is_empty()
        {
            return;
        }
        if !self.rows.iter().any(|r| !r.new.trim().is_empty()) {
            return;
        }
        self.autorun_started = true;
        if self.out_dir.trim().is_empty() {
            if let Ok(dir) = std::env::var("PCAPRW_OUT") {
                self.out_dir = dir;
            }
        }
        self.start_batch();
    }

    fn log(&mut self, level: LogLevel, text: impl Into<String>) {
        self.logs.push(LogLine {
            text: text.into(),
            level,
        });
        if self.logs.len() > 300 {
            let drop = self.logs.len() - 300;
            self.logs.drain(0..drop);
        }
    }

    fn add_paths(&mut self, paths: Vec<PathBuf>) {
        let mut added = 0usize;
        for path in paths {
            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if is_capture(&p) && !self.files.iter().any(|f| f.path == p) {
                            self.scan_one(p);
                            added += 1;
                        }
                    }
                }
                continue;
            }
            if !is_capture(&path) {
                self.toast = Some((format!("不支持的文件类型：{}", path.display()), false));
                continue;
            }
            if self.files.iter().any(|f| f.path == path) {
                continue;
            }
            self.scan_one(path);
            added += 1;
        }
        if added > 0 {
            self.log(LogLevel::Info, format!("已加入 {added} 个文件，正在读取…"));
        }
    }

    fn scan_one(&mut self, path: PathBuf) {
        let idx = self.files.len();
        self.files.push(FileEntry::new(path.clone()));
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = scan_file(&path);
            let _ = tx.send(Msg::Scanned { idx, result });
        });
    }

    /// Fill empty mapping rows from scanned endpoints, most active first.
    fn absorb_endpoints(&mut self) {
        use std::collections::HashMap;
        let mut counts: HashMap<Ip, usize> = HashMap::new();
        let mut payload_hint = 0usize;
        for f in &self.files {
            for (ip, c) in &f.ips {
                *counts.entry(*ip).or_insert(0) += *c;
            }
            payload_hint += f.payload_hint;
        }
        let mut list: Vec<(Ip, usize)> = counts.into_iter().collect();
        list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (ip, count) in list.into_iter().take(24) {
            if self.rows.iter().any(|r| r.old == ip.text()) {
                continue;
            }
            self.rows.push(MapRow {
                old: ip.text(),
                new: String::new(),
                count,
            });
        }
        if payload_hint > 0 && !self.replace_payload {
            self.log(
                LogLevel::Warn,
                format!(
                    "有 {payload_hint} 个包的载荷中出现端点 IP 文本（如 HTTP Host），如需一并替换请勾选“同时替换载荷中的 IP 文本”"
                ),
            );
        }
    }

    fn poll_messages(&mut self, ctx: &egui::Context) {
        let mut got = false;
        while let Ok(msg) = self.rx.try_recv() {
            got = true;
            match msg {
                Msg::Scanned { idx, result } => {
                    if let Some(f) = self.files.get_mut(idx) {
                        match result {
                            Ok(info) => {
                                f.packets = info.packets;
                                f.kind = info.kind;
                                f.status = Status::Ready;
                                f.note = info.note;
                                f.ips = info.ips;
                                f.payload_hint = info.payload_hint;
                            }
                            Err(e) => {
                                f.status = Status::Failed;
                                f.note = e.clone();
                            }
                        }
                        let name = f.name.clone();
                        let (status, note) = (f.status, f.note.clone());
                        if status == Status::Failed {
                            self.log(LogLevel::Error, format!("{name}：{note}"));
                        }
                    }
                    self.absorb_endpoints();
                }
                Msg::FileProgress { idx, done, total } => {
                    if let Some(f) = self.files.get_mut(idx) {
                        f.status = Status::Running;
                        let frac = if total == 0 {
                            0.0
                        } else {
                            done as f32 / total as f32
                        };
                        let overall = (self.batch_done as f32 + frac) / self.batch_total.max(1) as f32;
                        self.progress = overall.clamp(0.0, 1.0);
                        self.progress_note =
                            format!("{}：{done} / {total} 个包", f.name);
                    }
                }
                Msg::FileDone { idx, result } => {
                    let name = self
                        .files
                        .get(idx)
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| "文件".into());
                    match result {
                        Ok(summary) => {
                            let out_name = summary
                                .rsplit('→')
                                .next()
                                .map(|s| s.trim())
                                .map(|s| {
                                    std::path::Path::new(s)
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or(s)
                                        .to_string()
                                })
                                .unwrap_or_else(|| "已完成".into());
                            if let Some(f) = self.files.get_mut(idx) {
                                f.status = Status::Done;
                                f.note = out_name;
                            }
                            self.log(LogLevel::Good, format!("{name} 完成：{summary}"));
                        }
                        Err(e) => {
                            if let Some(f) = self.files.get_mut(idx) {
                                f.status = Status::Failed;
                                f.note = e.clone();
                            }
                            self.log(LogLevel::Error, format!("{name} 失败：{e}"));
                        }
                    }
                    self.batch_done += 1;
                }
                Msg::BatchDone {
                    ok,
                    failed,
                    cancelled,
                } => {
                    self.running = false;
                    self.progress = if cancelled { self.progress } else { 1.0 };
                    self.progress_note = if cancelled {
                        "已取消".to_string()
                    } else {
                        format!("完成：成功 {ok} 个，失败 {failed} 个")
                    };
                    if cancelled {
                        self.log(LogLevel::Warn, "任务已取消，输出可能不完整");
                    } else if failed == 0 {
                        self.log(LogLevel::Good, format!("全部完成，共 {ok} 个文件"));
                        self.toast = Some(("改写完成".into(), true));
                    } else {
                        self.log(
                            LogLevel::Warn,
                            format!("完成，但有 {failed} 个文件失败"),
                        );
                        self.toast = Some((format!("{failed} 个文件失败"), false));
                    }
                }
            }
        }
        if got {
            ctx.request_repaint();
        }
    }

    fn start_batch(&mut self) {
        let pairs: Vec<(String, String)> = self
            .rows
            .iter()
            .filter(|r| !r.old.trim().is_empty() && !r.new.trim().is_empty())
            .map(|r| (r.old.clone(), r.new.clone()))
            .collect();
        if pairs.is_empty() {
            self.toast = Some(("请先填写至少一行“新地址”".into(), false));
            self.log(LogLevel::Warn, "映射表为空，无法开始");
            return;
        }
        let mapping = match Mapping::from_text(&pairs) {
            Ok(m) => m,
            Err(e) => {
                self.toast = Some((e.clone(), false));
                self.log(LogLevel::Error, e);
                return;
            }
        };

        let jobs: Vec<(usize, PathBuf)> = self
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| f.enabled && f.status != Status::Failed && f.status != Status::Scanning)
            .map(|(i, f)| (i, f.path.clone()))
            .collect();
        if jobs.is_empty() {
            self.toast = Some(("没有可处理的文件".into(), false));
            return;
        }

        let out_dir = if self.out_dir.trim().is_empty() {
            None
        } else {
            let dir = PathBuf::from(self.out_dir.trim());
            if let Err(e) = std::fs::create_dir_all(&dir) {
                self.toast = Some((format!("无法创建输出目录：{e}"), false));
                return;
            }
            Some(dir)
        };

        for (idx, _) in &jobs {
            if let Some(f) = self.files.get_mut(*idx) {
                f.status = Status::Queued;
                f.note = "排队中".into();
            }
        }

        self.running = true;
        self.cancel = Arc::new(AtomicBool::new(false));
        self.progress = 0.0;
        self.progress_note = "准备中…".into();
        self.batch_total = jobs.len();
        self.batch_done = 0;

        let tx = self.tx.clone();
        let cancel = self.cancel.clone();
        let payload = self.replace_payload;
        let do_verify = self.do_verify;
        let overwrite = self.overwrite;
        let naming = self.naming.to_naming();
        let olds: Vec<String> = mapping.old_ips().iter().map(|ip| ip.text()).collect();

        self.log(
            LogLevel::Info,
            format!(
                "开始处理 {} 个文件，{} 条地址映射{}",
                jobs.len(),
                mapping.len(),
                if payload { "，含载荷替换" } else { "" }
            ),
        );

        thread::spawn(move || {
            let mut ok = 0usize;
            let mut failed = 0usize;
            let mut cancelled = false;

            for (idx, input) in jobs {
                if cancel.load(Ordering::Relaxed) {
                    cancelled = true;
                    break;
                }
                let result = process_one(
                    idx,
                    &input,
                    &mapping,
                    payload,
                    do_verify,
                    overwrite,
                    naming,
                    out_dir.as_deref(),
                    &olds,
                    &cancel,
                    &tx,
                );
                if result.is_ok() {
                    ok += 1;
                } else {
                    failed += 1;
                }
                let _ = tx.send(Msg::FileDone { idx, result });
            }

            let _ = tx.send(Msg::BatchDone {
                ok,
                failed,
                cancelled,
            });
        });
    }

    fn draw_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("PCAP IP 改写器")
                        .size(21.0)
                        .strong()
                        .color(TEXT),
                );
                ui.label(
                    RichText::new("改写抓包中的 IPv4 / IPv6 地址，自动重算校验和并保持 TCP 流完整")
                        .size(12.0)
                        .color(MUTED),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let btn = egui::Button::new(RichText::new("＋  添加文件").color(Color32::WHITE))
                    .fill(BLUE)
                    .corner_radius(8);
                if ui.add(btn).clicked() {
                    self.pick_files();
                }
                if ui
                    .add(
                        egui::Button::new(RichText::new("清空列表").color(MUTED))
                            .fill(Color32::TRANSPARENT)
                            .stroke(Stroke::new(1.0, BORDER))
                            .corner_radius(8),
                    )
                    .clicked()
                    && !self.running
                {
                    self.files.clear();
                    self.rows.clear();
                    self.logs.clear();
                    self.progress = 0.0;
                    self.progress_note = "等待任务".into();
                }
            });
        });
    }

    fn pick_files(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .add_filter("抓包文件", &["pcap", "pcapng", "cap"])
            .add_filter("所有文件", &["*"])
            .set_title("选择 pcap / pcapng 文件")
            .pick_files()
        {
            self.add_paths(paths);
        }
    }

    fn draw_files(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("捕获文件").size(14.0).strong().color(TEXT));
            ui.label(
                RichText::new(format!("{} 个", self.files.len()))
                    .size(12.0)
                    .color(MUTED),
            );
        });
        ui.add_space(6.0);

        let height = (ui.available_height() - 4.0).max(120.0);
        egui::Frame::new()
            .fill(Color32::from_rgb(0xFA, 0xFB, 0xFD))
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(10)
            .inner_margin(Margin::same(8))
            .show(ui, |ui| {
                ui.set_min_height(height);
                ui.set_max_height(height);
                if self.files.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(height * 0.3);
                        ui.label(
                            RichText::new("把 pcap / pcapng 文件拖到这里")
                                .size(13.5)
                                .color(MUTED),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("也可以点右上角“添加文件”")
                                .size(11.5)
                                .color(Color32::from_rgb(0x94, 0xA3, 0xB8)),
                        );
                    });
                    return;
                }
                egui::ScrollArea::vertical()
                    .id_salt("files_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for idx in 0..self.files.len() {
                            self.draw_file_row(ui, idx);
                            ui.add_space(6.0);
                        }
                    });
            });
    }

    fn draw_file_row(&mut self, ui: &mut egui::Ui, idx: usize) {
        let (name, status_text, status_color, meta, note, enabled, status) = {
            let f = &self.files[idx];
            let (st, sc) = f.status_text();
            let meta = if f.status == Status::Scanning {
                format_size(f.size)
            } else {
                format!("{} · {} 个包 · {}", f.kind, f.packets, format_size(f.size))
            };
            (
                f.name.clone(),
                st,
                sc,
                meta,
                f.note.clone(),
                f.enabled,
                f.status,
            )
        };

        egui::Frame::new()
            .fill(CARD)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(8)
            .inner_margin(Margin::symmetric(9, 7))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let mut checked = enabled;
                    if ui
                        .add_enabled(
                            !self.running && status != Status::Scanning,
                            egui::Checkbox::without_text(&mut checked),
                        )
                        .changed()
                    {
                        self.files[idx].enabled = checked;
                    }
                    let name_w = (ui.available_width() - 46.0).max(60.0);
                    ui.add_sized(
                        [name_w, 18.0],
                        egui::Label::new(RichText::new(&name).size(12.5).color(TEXT)).truncate(),
                    );
                    if ui
                        .add_enabled(
                            !self.running,
                            egui::Button::new(RichText::new("移除").size(11.0).color(MUTED))
                                .fill(Color32::TRANSPARENT)
                                .corner_radius(5),
                        )
                        .clicked()
                    {
                        self.files.remove(idx);
                    }
                });
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    ui.label(RichText::new(status_text).size(11.0).color(status_color));
                    ui.label(RichText::new(&meta).size(11.0).color(MUTED));
                });
                if status == Status::Failed || status == Status::Done {
                    let color = if status == Status::Failed { RED } else { GREEN };
                    ui.horizontal(|ui| {
                        ui.add_space(22.0);
                        ui.add(
                            egui::Label::new(RichText::new(&note).size(10.5).color(color))
                                .truncate(),
                        );
                    });
                }
            });
    }

    fn draw_mapping(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("地址映射").size(14.0).strong().color(TEXT));
            ui.label(
                RichText::new("填写右侧新地址，留空的行会被忽略")
                    .size(12.0)
                    .color(MUTED),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Button::new(RichText::new("＋ 空行").size(12.0).color(BLUE))
                            .fill(Color32::TRANSPARENT)
                            .corner_radius(6),
                    )
                    .clicked()
                {
                    self.rows.push(MapRow {
                        old: String::new(),
                        new: String::new(),
                        count: 0,
                    });
                }
            });
        });
        ui.add_space(4.0);

        if self.rows.is_empty() {
            ui.label(
                RichText::new("添加文件后，这里会自动列出捕获中的 IP 端点")
                    .size(12.0)
                    .color(MUTED),
            );
            return;
        }

        let mut delete: Option<usize> = None;
        let rows = &mut self.rows;
        let header_color = MUTED;
        egui::ScrollArea::vertical()
            .id_salt("map_scroll")
            .max_height(190.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("map_grid")
                    .num_columns(4)
                    .spacing([8.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("旧地址").size(11.5).color(header_color));
                        ui.label(RichText::new("新地址").size(11.5).color(header_color));
                        ui.label(RichText::new("包数").size(11.5).color(header_color));
                        ui.label("");
                        ui.end_row();

                        for (i, row) in rows.iter_mut().enumerate() {
                            ui.add_sized(
                                [166.0, 26.0],
                                egui::TextEdit::singleline(&mut row.old)
                                    .hint_text("旧地址")
                                    .font(FontId::monospace(12.5)),
                            );
                            let valid =
                                row.new.trim().is_empty() || parse_ip_any(&row.new).is_some();
                            let mut edit = egui::TextEdit::singleline(&mut row.new)
                                .hint_text("新地址")
                                .font(FontId::monospace(12.5));
                            if !valid {
                                edit = edit.text_color(RED);
                            }
                            ui.add_sized([184.0, 26.0], edit);
                            let count = row.count;
                            ui.allocate_ui(egui::vec2(46.0, 26.0), |ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if count > 0 {
                                            ui.label(
                                                RichText::new(count.to_string())
                                                    .size(11.5)
                                                    .color(MUTED),
                                            );
                                        }
                                    },
                                );
                            });
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("✕").size(12.0).color(MUTED),
                                    )
                                    .fill(Color32::TRANSPARENT),
                                )
                                .clicked()
                            {
                                delete = Some(i);
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(i) = delete {
            self.rows.remove(i);
        }
    }

    fn draw_settings(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("输出设置").size(14.0).strong().color(TEXT));
        ui.add_space(4.0);
        egui::Grid::new("settings_grid")
            .num_columns(2)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label(RichText::new("输出目录").size(12.5).color(MUTED));
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.out_dir)
                            .desired_width(360.0)
                            .hint_text("留空则输出到原文件所在目录"),
                    );
                    if ui
                        .add(
                            egui::Button::new(RichText::new("浏览…").size(12.0).color(TEXT))
                                .fill(Color32::from_rgb(0xF1, 0xF5, 0xF9))
                                .corner_radius(6),
                        )
                        .clicked()
                    {
                        if let Some(dir) = rfd::FileDialog::new()
                            .set_title("选择输出目录")
                            .pick_folder()
                        {
                            self.out_dir = dir.display().to_string();
                        }
                    }
                });
                ui.end_row();

                ui.label(RichText::new("文件命名").size(12.5).color(MUTED));
                egui::ComboBox::from_id_salt("naming")
                    .selected_text(self.naming.label())
                    .width(240.0)
                    .show_ui(ui, |ui| {
                        for choice in [
                            NamingChoice::Replace,
                            NamingChoice::Suffix,
                            NamingChoice::Keep,
                        ] {
                            ui.selectable_value(&mut self.naming, choice, choice.label());
                        }
                    });
                ui.end_row();
            });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.replace_payload, "同时替换载荷中的 IP 文本");
            ui.add_space(6.0);
            ui.label(
                RichText::new("会改动 HTTP Host/Referer 等文本并修正 TCP 序号")
                    .size(11.0)
                    .color(MUTED),
            );
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.do_verify, "完成后自动校验");
            ui.add_space(14.0);
            ui.checkbox(&mut self.overwrite, "覆盖同名文件");
        });
        ui.label(
            RichText::new("原始文件始终不会被修改，结果另存为新文件。")
                .size(11.0)
                .color(Color32::from_rgb(0x94, 0xA3, 0xB8)),
        );
    }

    fn draw_actions(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let can_start = !self.running && !self.files.is_empty();
            let btn = egui::Button::new(
                RichText::new(if self.running { "处理中…" } else { "开始改写" })
                    .size(14.0)
                    .color(Color32::WHITE),
            )
            .fill(if can_start { BLUE } else { Color32::from_rgb(0x9C, 0xAE, 0xC8) })
            .corner_radius(8)
            .min_size(egui::vec2(120.0, 34.0));
            if ui.add_enabled(can_start, btn).clicked() {
                self.start_batch();
            }

            if self.running {
                if ui
                    .add(
                        egui::Button::new(RichText::new("停止").size(13.0).color(RED))
                            .fill(Color32::WHITE)
                            .stroke(Stroke::new(1.0, Color32::from_rgb(0xF3, 0xC5, 0xC5)))
                            .corner_radius(8)
                            .min_size(egui::vec2(70.0, 34.0)),
                    )
                    .clicked()
                {
                    self.cancel.store(true, Ordering::Relaxed);
                    self.progress_note = "正在停止…".into();
                }
            }

            if self.running || self.progress > 0.0 {
                let bar = egui::ProgressBar::new(self.progress)
                    .desired_width(ui.available_width() - 12.0)
                    .animate(self.running);
                ui.add(bar);
            } else {
                ui.label(RichText::new(&self.progress_note).size(12.0).color(MUTED));
            }
        });
    }

    fn draw_logs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("日志").size(13.0).strong().color(TEXT));
            ui.label(
                RichText::new(&self.progress_note)
                    .size(11.5)
                    .color(if self.running { BLUE } else { MUTED }),
            );
        });
        ui.add_space(4.0);
        egui::ScrollArea::vertical()
            .id_salt("log_scroll")
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if self.logs.is_empty() {
                    ui.label(
                        RichText::new("等待操作…")
                            .size(12.0)
                            .color(Color32::from_rgb(0xA0, 0xAE, 0xC0)),
                    );
                }
                for line in &self.logs {
                    let color = match line.level {
                        LogLevel::Info => MUTED,
                        LogLevel::Good => GREEN,
                        LogLevel::Warn => AMBER,
                        LogLevel::Error => RED,
                    };
                    ui.add(
                        egui::Label::new(RichText::new(&line.text).size(12.0).color(color)).wrap(),
                    );
                }
            });
    }

    fn handle_drop(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        self.drag_active = !ctx.input(|i| i.raw.hovered_files.is_empty());
        if !dropped.is_empty() && !self.running {
            self.add_paths(dropped);
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_drop(&ctx);
        self.poll_messages(&ctx);
        self.apply_demo_map();
        self.maybe_autorun();
        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }

        egui::Panel::top("header")
            .resizable(false)
            .show_separator_line(false)
            .frame(
                egui::Frame::new()
                    .fill(CARD)
                    .inner_margin(Margin::symmetric(18, 12)),
            )
            .show(ui, |ui| {
                self.draw_header(ui);
            });

        egui::Panel::left("files_panel")
            .resizable(false)
            .default_size(372.0)
            .min_size(300.0)
            .max_size(520.0)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(BG).inner_margin(Margin {
                left: 18,
                right: 0,
                top: 4,
                bottom: 14,
            }))
            .show(ui, |ui| {
                self.draw_files(ui);
            });

        egui::CentralPanel::default_margins()
            .frame(egui::Frame::new().fill(BG).inner_margin(Margin {
                left: 14,
                right: 18,
                top: 4,
                bottom: 14,
            }))
            .show(ui, |ui| {
                egui::Frame::new()
                    .fill(CARD)
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(10)
                    .inner_margin(Margin::same(14))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        self.draw_mapping(ui);
                    });
                ui.add_space(10.0);
                egui::Frame::new()
                    .fill(CARD)
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(10)
                    .inner_margin(Margin::same(14))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        self.draw_settings(ui);
                    });
                ui.add_space(10.0);
                self.draw_actions(ui);
                ui.add_space(6.0);
                let log_height = ui.available_height().max(80.0);
                egui::Frame::new()
                    .fill(CARD)
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(10)
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.set_min_height(log_height - 24.0);
                        self.draw_logs(ui);
                    });
            });

        if self.drag_active {
            let rect = ctx.content_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::unique("drop_overlay"),
            ));
            painter.rect_filled(rect.shrink(6.0), CornerRadius::same(12), Color32::from_black_alpha(24));
            painter.rect_stroke(
                rect.shrink(6.0),
                CornerRadius::same(12),
                Stroke::new(2.0, BLUE),
                egui::StrokeKind::Inside,
            );
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "松开以导入抓包文件",
                FontId::new(18.0, egui::FontFamily::Proportional),
                BLUE,
            );
        }

        if let Some((text, good)) = self.toast.clone() {
            egui::Area::new(egui::Id::unique("toast"))
                .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -24.0))
                .show(&ctx, |ui| {
                    egui::Frame::new()
                        .fill(if good {
                            Color32::from_rgb(0xEC, 0xFD, 0xF5)
                        } else {
                            Color32::from_rgb(0xFE, 0xF2, 0xF2)
                        })
                        .stroke(Stroke::new(
                            1.0,
                            if good {
                                Color32::from_rgb(0xA7, 0xF3, 0xD0)
                            } else {
                                Color32::from_rgb(0xFE, 0xCA, 0xCA)
                            },
                        ))
                        .corner_radius(8)
                        .inner_margin(Margin::symmetric(14, 8))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(&text)
                                    .size(12.5)
                                    .color(if good { GREEN } else { RED }),
                            );
                        });
                });
            if ctx.input(|i| i.pointer.any_click()) {
                self.toast = None;
            }
        }

        // Optional offscreen capture for layout verification.
        if let Some(path) = self.screenshot_path.clone() {
            self.frame_count += 1;
            let ready = if self.autorun {
                self.autorun_started && !self.running && self.batch_done > 0
            } else {
                self.frame_count >= 90
            };
            if ready {
                let path_clone = path.clone();
                let cb = egui::ScreenshotCallback::new(move |image| {
                    let (w, h) = (image.width() as u32, image.height() as u32);
                    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
                    for px in image.pixels.iter() {
                        rgba.extend_from_slice(&[px.r(), px.g(), px.b(), px.a()]);
                    }
                    if let Some(img) = image::RgbaImage::from_raw(w, h, rgba) {
                        let _ = img.save(&path_clone);
                    }
                    std::process::exit(0);
                });
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(cb));
                self.screenshot_path = None;
                ctx.request_repaint();
            } else {
                ctx.request_repaint();
            }
        }
    }
}

fn is_capture(path: &std::path::Path) -> bool {
    matches!(
        path.extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("pcap") | Some("pcapng") | Some("cap")
    )
}

fn scan_file(path: &std::path::Path) -> Result<ScanInfo, String> {
    let cap = capture::load(path).map_err(|e| e.to_string())?;
    let analysis = analyze(&cap);
    let mut ips: Vec<(Ip, usize)> = analysis
        .ips
        .iter()
        .map(|i| (i.ip, i.packets))
        .collect();
    ips.truncate(40);
    let payload_hint: usize = analysis.ips.iter().map(|i| i.in_payload).sum();
    let proto_text: Vec<String> = analysis
        .protocols
        .iter()
        .take(4)
        .map(|(p, c)| format!("{}({})", proto_name(*p), c))
        .collect();
    let mut note = format!(
        "{} 个包 · {} 个端点 · {}",
        analysis.packets,
        analysis.ips.len(),
        proto_text.join(" ")
    );
    if analysis.truncated_packets > 0 {
        note.push_str(&format!(" · 截断 {}", analysis.truncated_packets));
    }
    if analysis.fragmented_packets > 0 {
        note.push_str(&format!(" · 分片 {}", analysis.fragmented_packets));
    }
    Ok(ScanInfo {
        packets: analysis.packets,
        kind: match cap.kind {
            capture::Kind::Pcap => "pcap",
            capture::Kind::Pcapng => "pcapng",
        },
        ips,
        payload_hint,
        note,
    })
}

#[allow(clippy::too_many_arguments)]
fn process_one(
    idx: usize,
    input: &std::path::Path,
    mapping: &Mapping,
    payload: bool,
    do_verify: bool,
    overwrite: bool,
    naming: Naming,
    out_dir: Option<&std::path::Path>,
    olds: &[String],
    cancel: &Arc<AtomicBool>,
    tx: &Sender<Msg>,
) -> Result<String, String> {
    let mut cap = capture::load(input).map_err(|e| e.to_string())?;
    let out_path = derive_output(input, mapping, naming, out_dir);

    if out_path.exists() && !overwrite && out_path != input {
        return Err(format!("目标已存在：{}（可勾选“覆盖同名文件”）", out_path.display()));
    }

    let rewriter = Rewriter::new(mapping.clone(), payload);
    let mut progress_cb = |done: usize, total: usize| {
        let _ = tx.send(Msg::FileProgress {
            idx,
            done,
            total,
        });
    };
    let stats = rewriter.process(&mut cap, Some(cancel), Some(&mut progress_cb));
    capture::save(&cap, &out_path).map_err(|e| e.to_string())?;

    let mut summary = format!(
        "{} 个包，改动 {} 个，L4 校验和 {} 个",
        stats.packets_total, stats.packets_modified, stats.l4_checksums
    );
    if stats.payload_hits > 0 {
        summary.push_str(&format!(
            "，载荷替换 {} 处（{} 字节）",
            stats.payload_hits, stats.bytes_delta
        ));
    }
    if stats.seq_fixed > 0 {
        summary.push_str(&format!("，序号修正 {} 个", stats.seq_fixed));
    }
    for w in &stats.warnings {
        summary.push_str(&format!("；{w}"));
    }

    if do_verify {
        let check = capture::load(&out_path).map_err(|e| e.to_string())?;
        let res = verify(&check, olds, payload);
        if res.ok() {
            summary.push_str("；校验通过");
        } else {
            return Err(format!(
                "写入成功但校验未通过：IP 错误 {}，L4 错误 {}，残留 {} 处",
                res.ip_bad,
                res.l4_bad,
                res.old_in_header + res.old_in_payload
            ));
        }
    }
    summary.push_str(&format!(" → {}", out_path.display()));
    Ok(summary)
}

fn setup_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Light);
    let mut style = (*ctx.style_of(egui::Theme::Light)).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = CARD;
    style.visuals.extreme_bg_color = Color32::from_rgb(0xF8, 0xFA, 0xFC);
    style.visuals.override_text_color = None;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.active.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.selection.bg_fill = Color32::from_rgb(0xDB, 0xEA, 0xFE);
    style.visuals.selection.stroke = Stroke::new(1.0, BLUE_DARK);
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.text_styles = [
        (
            egui::TextStyle::Heading,
            FontId::new(20.0, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Body,
            FontId::new(13.0, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Button,
            FontId::new(13.0, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Small,
            FontId::new(11.5, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Monospace,
            FontId::new(12.5, egui::FontFamily::Monospace),
        ),
    ]
    .into();
    ctx.set_style_of(egui::Theme::Light, style);
}

fn load_icon() -> Option<egui::IconData> {
    let bytes = include_bytes!("../assets/app.ico");
    let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Ico)
        .ok()?
        .to_rgba8();
    let (width, height) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

pub fn run() -> i32 {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1200.0, 840.0])
        .with_min_inner_size([1000.0, 700.0])
        .with_title("PCAP IP 改写器");
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let screenshot = std::env::var("PCAPRW_SCREENSHOT").ok();
    let demo_files = std::env::var("PCAPRW_DEMO").ok();
    let result = eframe::run_native(
        "PCAP IP 改写器",
        options,
        Box::new(move |cc| {
            setup_style(&cc.egui_ctx);
            let mut app = App::new(screenshot.clone());
            if let Some(list) = demo_files.clone() {
                let paths: Vec<PathBuf> = list
                    .split(';')
                    .filter(|s| !s.trim().is_empty())
                    .map(PathBuf::from)
                    .collect();
                app.add_paths(paths);
            }
            Ok(Box::new(app))
        }),
    );
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("界面启动失败：{e}");
            1
        }
    }
}
