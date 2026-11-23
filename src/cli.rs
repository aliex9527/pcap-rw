//! Command line interface: scan / rewrite / verify.

use std::path::{Path, PathBuf};

use pcap_rw::analyze::{analyze, proto_name};
use pcap_rw::capture::{self, format_size};
use pcap_rw::rewrite::{Mapping, Rewriter};
use pcap_rw::verify::verify;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Naming {
    Replace,
    Suffix,
    Keep,
}

/// Build the output path for one input file.
pub fn derive_output(
    input: &Path,
    mapping: &Mapping,
    naming: Naming,
    out_dir: Option<&Path>,
) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("pcap");

    let new_stem = match naming {
        Naming::Replace => {
            let mut text = stem.to_string();
            let mut changed = false;
            for (old, new) in mapping.pairs() {
                let old_s = old.text();
                if text.contains(&old_s) {
                    text = text.replace(&old_s, &new.text());
                    changed = true;
                }
            }
            if changed {
                text
            } else {
                format!("{stem}_new")
            }
        }
        Naming::Suffix => format!("{stem}_new"),
        Naming::Keep => {
            if out_dir.is_none() {
                format!("{stem}_new")
            } else {
                stem.to_string()
            }
        }
    };

    let file_name = format!("{new_stem}.{ext}");
    match out_dir {
        Some(dir) => dir.join(file_name),
        None => input.with_file_name(file_name),
    }
}

pub fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        usage();
        return 2;
    }
    match args[0].as_str() {
        "scan" => cmd_scan(&args[1..]),
        "rewrite" => cmd_rewrite(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "-h" | "--help" | "help" => {
            usage();
            0
        }
        other => {
            eprintln!("未知命令：{other}");
            usage();
            2
        }
    }
}

fn usage() {
    println!(
        "PCAP IP 改写器（Rust 版）

用法：
  pcap-rw scan <文件> [--pairs]           查看端点与流量分布
  pcap-rw rewrite <文件...> --map 旧=新 [-o 输出目录] [--payload] [--verify] [--overwrite]
                                          改写 IPv4 / IPv6 地址
  pcap-rw verify <文件> --old 旧IP [--payload]
                                          校验校验和与残留地址

选项：
  --map A=B        地址映射，可重复使用；如 --map 10.0.0.1=192.168.1.1
                   IPv6 写法相同：--map 2001:db8::1=2001:db8::9（只换同族地址）
  -o, --out DIR    输出目录（默认与原文件同目录）
  --payload        同时替换载荷中的 IP 文本（会修正 TCP seq/ack）
  --verify         写完立即校验
  --overwrite      允许覆盖同名文件
  --pairs          扫描时列出会话明细
  --old IP         校验时视为“旧地址”的 IP

不带任何参数启动将打开图形界面。"
    );
}

struct MapArgs {
    maps: Vec<(String, String)>,
    out_dir: Option<PathBuf>,
    payload: bool,
    do_verify: bool,
    overwrite: bool,
    files: Vec<PathBuf>,
    pairs: bool,
    olds: Vec<String>,
}

fn parse_args(args: &[String]) -> MapArgs {
    let mut out = MapArgs {
        maps: Vec::new(),
        out_dir: None,
        payload: false,
        do_verify: false,
        overwrite: false,
        files: Vec::new(),
        pairs: false,
        olds: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--map" | "-m" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Some((old, new)) = spec.split_once('=') {
                        out.maps
                            .push((old.trim().to_string(), new.trim().to_string()));
                    } else {
                        eprintln!("--map 需要 旧=新 形式，收到：{spec}");
                    }
                    i += 1;
                }
            }
            "-o" | "--out" => {
                if let Some(dir) = args.get(i + 1) {
                    out.out_dir = Some(PathBuf::from(dir));
                    i += 1;
                }
            }
            "--payload" => out.payload = true,
            "--verify" => out.do_verify = true,
            "--overwrite" => out.overwrite = true,
            "--pairs" => out.pairs = true,
            "--old" => {
                if let Some(ip) = args.get(i + 1) {
                    out.olds.push(ip.clone());
                    i += 1;
                }
            }
            other if !other.starts_with('-') => out.files.push(PathBuf::from(other)),
            other => eprintln!("忽略未知参数：{other}"),
        }
        i += 1;
    }
    out
}

fn cmd_scan(args: &[String]) -> i32 {
    let parsed = parse_args(args);
    if parsed.files.is_empty() {
        eprintln!("请提供至少一个 pcap 文件");
        return 2;
    }
    for path in &parsed.files {
        let cap = match capture::load(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("读取失败 {}：{e}", path.display());
                return 1;
            }
        };
        let a = analyze(&cap);
        println!("== {}", path.display());
        println!(
            "   格式：{}  包数：{}  IPv4：{}  IPv6：{}  VLAN：{}  分片：{}  截断：{}  大小：{}",
            match cap.kind {
                capture::Kind::Pcap => "pcap",
                capture::Kind::Pcapng => "pcapng",
            },
            a.packets,
            a.ipv4_packets,
            a.ipv6_packets,
            a.vlan_packets,
            a.fragmented_packets,
            a.truncated_packets,
            format_size(cap.file_size())
        );
        let proto_text: Vec<String> = a
            .protocols
            .iter()
            .map(|(p, c)| format!("{}({})", proto_name(*p), c))
            .collect();
        println!("   协议：{}", proto_text.join("  "));
        println!("   IP 端点：");
        let width = a
            .ips
            .iter()
            .take(20)
            .map(|i| i.ip_text().len())
            .max()
            .unwrap_or(16)
            .max(16);
        for info in a.ips.iter().take(20) {
            println!(
                "     {:<width$} {:>6} 包 {:>10} 端口 {}",
                info.ip_text(),
                info.packets,
                format_size(info.bytes),
                info.describe_ports(3),
                width = width
            );
        }
        if parsed.pairs {
            println!("   会话：");
            for p in a.pairs.iter().take(30) {
                println!(
                    "     {:<44} {:>6} 包 {:>10}",
                    p.label(),
                    p.packets,
                    format_size(p.bytes)
                );
            }
        }
    }
    0
}

fn cmd_rewrite(args: &[String]) -> i32 {
    let parsed = parse_args(args);
    if parsed.files.is_empty() {
        eprintln!("请提供至少一个 pcap 文件");
        return 2;
    }
    let mapping = match Mapping::from_text(&parsed.maps) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("映射表无效：{e}");
            return 2;
        }
    };
    if let Some(dir) = &parsed.out_dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("无法创建输出目录 {}：{e}", dir.display());
            return 1;
        }
    }

    let mut failures = 0;
    for input in &parsed.files {
        let mut cap = match capture::load(input) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("读取失败 {}：{e}", input.display());
                failures += 1;
                continue;
            }
        };
        let rewriter = Rewriter::new(mapping.clone(), parsed.payload);
        let stats = rewriter.process(&mut cap, None, None);
        let out_path = derive_output(input, &mapping, Naming::Replace, parsed.out_dir.as_deref());

        if out_path.exists() && !parsed.overwrite {
            eprintln!("目标已存在，跳过（加 --overwrite 覆盖）：{}", out_path.display());
            failures += 1;
            continue;
        }
        if let Err(e) = capture::save(&cap, &out_path) {
            eprintln!("写入失败 {}：{e}", out_path.display());
            failures += 1;
            continue;
        }

        println!("== {}", input.display());
        println!(
            "   包：{}  IPv4：{}  IPv6：{}  改动：{}（源 {} / 目的 {}）",
            stats.packets_total,
            stats.ipv4_packets,
            stats.ipv6_packets,
            stats.packets_modified,
            stats.src_hits,
            stats.dst_hits
        );
        println!(
            "   校验和：IPv4 头 {} 个 / L4 {} 个（跳过 {}）  载荷替换：{} 处  序号修正：{} 个",
            stats.ip_headers, stats.l4_checksums, stats.l4_skipped, stats.payload_hits,
            stats.seq_fixed
        );
        if stats.l4_recovered > 0 {
            println!(
                "   首片缺失：{} 个分片的上层协议头由校验和定位，校验和已重算",
                stats.l4_recovered
            );
        }
        for w in &stats.warnings {
            println!("   注意：{w}");
        }
        println!("   输出：{}", out_path.display());

        if parsed.do_verify {
            match capture::load(&out_path) {
                Ok(check) => {
                    let olds: Vec<String> = parsed
                        .olds
                        .clone()
                        .into_iter()
                        .chain(mapping.old_ips().iter().map(|ip| ip.text()))
                        .collect();
                    let res = verify(&check, &olds, parsed.payload);
                    println!("   校验：{}", res.summary());
                    for d in &res.details {
                        println!("     - {d}");
                    }
                    if !res.ok() {
                        failures += 1;
                    }
                }
                Err(e) => {
                    eprintln!("   校验时读取失败：{e}");
                    failures += 1;
                }
            }
        }
    }
    if failures > 0 {
        1
    } else {
        0
    }
}

fn cmd_verify(args: &[String]) -> i32 {
    let parsed = parse_args(args);
    if parsed.files.is_empty() {
        eprintln!("请提供至少一个 pcap 文件");
        return 2;
    }
    let mut olds = parsed.olds.clone();
    for (old, _) in &parsed.maps {
        olds.push(old.clone());
    }
    for path in &parsed.files {
        let cap = match capture::load(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("读取失败 {}：{e}", path.display());
                return 1;
            }
        };
        let res = verify(&cap, &olds, parsed.payload);
        println!("== {}", path.display());
        println!("   {}", res.summary());
        for d in &res.details {
            println!("   - {d}");
        }
    }
    0
}
