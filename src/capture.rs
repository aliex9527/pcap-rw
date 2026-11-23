//! Reading and writing classic pcap and pcapng files without external crates.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const PCAP_MAGIC_USEC_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
pub const PCAP_MAGIC_USEC_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
pub const PCAP_MAGIC_NSEC_LE: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
pub const PCAP_MAGIC_NSEC_BE: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
pub const PCAPNG_SHB: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

pub const BT_IDB: u32 = 1;
pub const BT_PB: u32 = 2;
pub const BT_SPB: u32 = 3;
pub const BT_EPB: u32 = 6;

#[derive(Debug)]
pub struct CapError(pub String);

impl std::fmt::Display for CapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CapError {}

impl From<std::io::Error> for CapError {
    fn from(e: std::io::Error) -> Self {
        CapError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CapError>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn r_u16(self, b: &[u8]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes([b[0], b[1]]),
            Endian::Big => u16::from_be_bytes([b[0], b[1]]),
        }
    }
    pub fn r_u32(self, b: &[u8]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Endian::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
    pub fn w_u16(self, v: u16) -> [u8; 2] {
        match self {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        }
    }
    pub fn w_u32(self, v: u32) -> [u8; 4] {
        match self {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        }
    }
}

pub const fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Pcap,
    Pcapng,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub data: Vec<u8>,
    pub linktype: u32,
    pub orig_len: usize,
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub endian: Endian,
    pub iface_id: u16,
    pub block_type: u32,
    pub options: Vec<u8>,
    pub ts_high: u32,
    pub ts_low: u32,
    pub drops: u16,
}

impl Packet {
    pub fn new(data: Vec<u8>, linktype: u32) -> Self {
        let orig = data.len();
        Packet {
            data,
            linktype,
            orig_len: orig,
            ts_sec: 0,
            ts_frac: 0,
            endian: Endian::Little,
            iface_id: 0,
            block_type: BT_EPB,
            options: Vec::new(),
            ts_high: 0,
            ts_low: 0,
            drops: 0,
        }
    }

    pub fn truncated(&self) -> bool {
        self.data.len() < self.orig_len
    }
}

#[derive(Debug, Clone)]
pub enum Item {
    Packet(Packet),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Capture {
    pub kind: Kind,
    pub linktype: u32,
    pub header: Vec<u8>,
    pub items: Vec<Item>,
    pub endian: Endian,
    pub nanosecond: bool,
    pub path: PathBuf,
}

impl Capture {
    pub fn packets(&self) -> impl Iterator<Item = &Packet> {
        self.items.iter().filter_map(|it| match it {
            Item::Packet(p) => Some(p),
            Item::Raw(_) => None,
        })
    }

    pub fn packets_mut(&mut self) -> impl Iterator<Item = &mut Packet> {
        self.items.iter_mut().filter_map(|it| match it {
            Item::Packet(p) => Some(p),
            Item::Raw(_) => None,
        })
    }

    pub fn packet_count(&self) -> usize {
        self.items
            .iter()
            .filter(|it| matches!(it, Item::Packet(_)))
            .count()
    }

    pub fn file_size(&self) -> u64 {
        fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }
}

pub fn load(path: impl AsRef<Path>) -> Result<Capture> {
    let path = path.as_ref();
    let data = fs::read(path)?;
    if data.len() < 4 {
        return Err(CapError("文件为空或长度不足 4 字节".into()));
    }
    if data[..4] == PCAPNG_SHB {
        load_pcapng(path, &data)
    } else {
        load_pcap(path, &data)
    }
}

fn load_pcap(path: &Path, data: &[u8]) -> Result<Capture> {
    let magic: [u8; 4] = data[..4].try_into().unwrap();
    let (endian, nanosecond) = match magic {
        PCAP_MAGIC_USEC_LE => (Endian::Little, false),
        PCAP_MAGIC_NSEC_LE => (Endian::Little, true),
        PCAP_MAGIC_USEC_BE => (Endian::Big, false),
        PCAP_MAGIC_NSEC_BE => (Endian::Big, true),
        _ => return Err(CapError("不是有效的 pcap 文件（magic 不匹配）".into())),
    };
    if data.len() < 24 {
        return Err(CapError("pcap 全局头不完整".into()));
    }
    let linktype = endian.r_u32(&data[20..24]);

    let mut items = Vec::new();
    let mut off = 24usize;
    let mut idx = 0usize;
    while off < data.len() {
        if off + 16 > data.len() {
            return Err(CapError(format!("第 {} 个包的记录头被截断", idx + 1)));
        }
        let ts_sec = endian.r_u32(&data[off..off + 4]);
        let ts_frac = endian.r_u32(&data[off + 4..off + 8]);
        let incl = endian.r_u32(&data[off + 8..off + 12]) as usize;
        let orig = endian.r_u32(&data[off + 12..off + 16]) as usize;
        off += 16;
        if incl > data.len() - off {
            return Err(CapError(format!(
                "第 {} 个包的数据被截断（需要 {incl} 字节）",
                idx + 1
            )));
        }
        let mut pkt = Packet::new(data[off..off + incl].to_vec(), linktype);
        pkt.orig_len = if orig == 0 { incl } else { orig };
        pkt.ts_sec = ts_sec;
        pkt.ts_frac = ts_frac;
        pkt.endian = endian;
        pkt.block_type = 0;
        items.push(Item::Packet(pkt));
        off += incl;
        idx += 1;
    }

    Ok(Capture {
        kind: Kind::Pcap,
        linktype,
        header: data[..24].to_vec(),
        items,
        endian,
        nanosecond,
        path: path.to_path_buf(),
    })
}

fn load_pcapng(path: &Path, data: &[u8]) -> Result<Capture> {
    let mut items: Vec<Item> = Vec::new();
    let mut interfaces: Vec<(u32, u32)> = Vec::new();
    let mut endian = Endian::Little;
    let mut off = 0usize;
    let mut block_no = 0usize;

    while off < data.len() {
        if off + 12 > data.len() {
            return Err(CapError(format!("pcapng 第 {} 个块头被截断", block_no + 1)));
        }
        let is_shb = data[off..off + 4] == PCAPNG_SHB;
        if is_shb {
            match &data[off + 8..off + 12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => endian = Endian::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => endian = Endian::Big,
                _ => return Err(CapError("pcapng SHB 字节序标记无效".into())),
            }
            interfaces.clear();
        }

        let btype = endian.r_u32(&data[off..off + 4]);
        let total = endian.r_u32(&data[off + 4..off + 8]) as usize;
        if total < 12 || total % 4 != 0 || off + total > data.len() {
            return Err(CapError(format!(
                "pcapng 第 {} 个块长度非法：{total}",
                block_no + 1
            )));
        }
        let trailer = endian.r_u32(&data[off + total - 4..off + total]) as usize;
        if trailer != total {
            return Err(CapError(format!(
                "pcapng 第 {} 个块首尾长度不一致",
                block_no + 1
            )));
        }
        let body = &data[off + 8..off + total - 4];
        let raw = data[off..off + total].to_vec();

        if is_shb {
            items.push(Item::Raw(raw));
        } else if btype == BT_IDB {
            if body.len() < 8 {
                return Err(CapError("IDB 块长度不足".into()));
            }
            let linktype = endian.r_u16(&body[0..2]) as u32;
            let snaplen = endian.r_u32(&body[4..8]);
            interfaces.push((linktype, snaplen));
            items.push(Item::Raw(raw));
        } else if btype == BT_EPB {
            if body.len() < 20 {
                return Err(CapError("EPB 块长度不足".into()));
            }
            let iface = endian.r_u32(&body[0..4]);
            let ts_high = endian.r_u32(&body[4..8]);
            let ts_low = endian.r_u32(&body[8..12]);
            let mut caplen = endian.r_u32(&body[12..16]) as usize;
            let origlen = endian.r_u32(&body[16..20]) as usize;
            if caplen > body.len() - 20 {
                caplen = body.len() - 20;
            }
            let pkt_bytes = body[20..20 + caplen].to_vec();
            let opt_start = 20 + caplen + pad4(caplen);
            let options = if opt_start <= body.len() {
                body[opt_start..].to_vec()
            } else {
                Vec::new()
            };
            let linktype = interfaces
                .get(iface as usize)
                .map(|(lt, _)| *lt)
                .unwrap_or(1);
            let mut pkt = Packet::new(pkt_bytes, linktype);
            pkt.orig_len = if origlen == 0 { caplen } else { origlen };
            pkt.endian = endian;
            pkt.iface_id = iface as u16;
            pkt.block_type = BT_EPB;
            pkt.options = options;
            pkt.ts_high = ts_high;
            pkt.ts_low = ts_low;
            items.push(Item::Packet(pkt));
        } else if btype == BT_PB {
            if body.len() < 20 {
                return Err(CapError("PB 块长度不足".into()));
            }
            let iface = endian.r_u16(&body[0..2]);
            let drops = endian.r_u16(&body[2..4]);
            let ts_high = endian.r_u32(&body[4..8]);
            let ts_low = endian.r_u32(&body[8..12]);
            let mut caplen = endian.r_u32(&body[12..16]) as usize;
            let origlen = endian.r_u32(&body[16..20]) as usize;
            if caplen > body.len() - 20 {
                caplen = body.len() - 20;
            }
            let pkt_bytes = body[20..20 + caplen].to_vec();
            let opt_start = 20 + caplen + pad4(caplen);
            let options = if opt_start <= body.len() {
                body[opt_start..].to_vec()
            } else {
                Vec::new()
            };
            let linktype = interfaces
                .get(iface as usize)
                .map(|(lt, _)| *lt)
                .unwrap_or(1);
            let mut pkt = Packet::new(pkt_bytes, linktype);
            pkt.orig_len = if origlen == 0 { caplen } else { origlen };
            pkt.endian = endian;
            pkt.iface_id = iface;
            pkt.block_type = BT_PB;
            pkt.options = options;
            pkt.ts_high = ts_high;
            pkt.ts_low = ts_low;
            pkt.drops = drops;
            items.push(Item::Packet(pkt));
        } else if btype == BT_SPB {
            if body.len() < 4 {
                return Err(CapError("SPB 块长度不足".into()));
            }
            let origlen = endian.r_u32(&body[0..4]) as usize;
            let avail = body.len() - 4;
            let caplen = if origlen == 0 {
                avail
            } else {
                origlen.min(avail)
            };
            let pkt_bytes = body[4..4 + caplen].to_vec();
            let linktype = interfaces.first().map(|(lt, _)| *lt).unwrap_or(1);
            let mut pkt = Packet::new(pkt_bytes, linktype);
            pkt.orig_len = if origlen == 0 { caplen } else { origlen };
            pkt.endian = endian;
            pkt.block_type = BT_SPB;
            items.push(Item::Packet(pkt));
        } else {
            items.push(Item::Raw(raw));
        }

        off += total;
        block_no += 1;
    }

    if items.is_empty() {
        return Err(CapError("pcapng 文件没有任何数据块".into()));
    }
    let linktype = interfaces.first().map(|(lt, _)| *lt).unwrap_or(1);
    Ok(Capture {
        kind: Kind::Pcapng,
        linktype,
        header: Vec::new(),
        items,
        endian,
        nanosecond: true,
        path: path.to_path_buf(),
    })
}

pub fn save(cap: &Capture, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let mut out: Vec<u8> = Vec::with_capacity(1 << 20);

    match cap.kind {
        Kind::Pcap => {
            out.extend_from_slice(&cap.header);
            let e = cap.endian;
            for pkt in cap.packets() {
                if pkt.data.len() > u32::MAX as usize {
                    return Err(CapError("包长度超出 pcap 上限".into()));
                }
                out.extend_from_slice(&e.w_u32(pkt.ts_sec));
                out.extend_from_slice(&e.w_u32(pkt.ts_frac));
                out.extend_from_slice(&e.w_u32(pkt.data.len() as u32));
                let orig = pkt.orig_len.max(pkt.data.len()) as u32;
                out.extend_from_slice(&e.w_u32(orig));
                out.extend_from_slice(&pkt.data);
            }
        }
        Kind::Pcapng => {
            for item in &cap.items {
                match item {
                    Item::Raw(raw) => out.extend_from_slice(raw),
                    Item::Packet(pkt) => serialize_packet(pkt, &mut out)?,
                }
            }
        }
    }

    atomic_write(path, &out)
}

fn serialize_packet(pkt: &Packet, out: &mut Vec<u8>) -> Result<()> {
    let e = pkt.endian;
    let data = &pkt.data;
    let padding = pad4(data.len());
    let orig_len = pkt.orig_len.max(data.len()) as u32;

    let mut body: Vec<u8> = Vec::with_capacity(24 + data.len() + padding + pkt.options.len());
    let btype = match pkt.block_type {
        BT_SPB => {
            body.extend_from_slice(&e.w_u32(orig_len));
            BT_SPB
        }
        BT_PB => {
            body.extend_from_slice(&e.w_u16(pkt.iface_id));
            body.extend_from_slice(&e.w_u16(pkt.drops));
            body.extend_from_slice(&e.w_u32(pkt.ts_high));
            body.extend_from_slice(&e.w_u32(pkt.ts_low));
            body.extend_from_slice(&e.w_u32(data.len() as u32));
            body.extend_from_slice(&e.w_u32(orig_len));
            BT_PB
        }
        _ => {
            body.extend_from_slice(&e.w_u32(pkt.iface_id as u32));
            body.extend_from_slice(&e.w_u32(pkt.ts_high));
            body.extend_from_slice(&e.w_u32(pkt.ts_low));
            body.extend_from_slice(&e.w_u32(data.len() as u32));
            body.extend_from_slice(&e.w_u32(orig_len));
            BT_EPB
        }
    };

    body.extend_from_slice(data);
    body.extend(std::iter::repeat_n(0u8, padding));
    body.extend_from_slice(&pkt.options);

    let total = 12 + body.len();
    if total % 4 != 0 {
        return Err(CapError("pcapng 块长度未对齐".into()));
    }
    out.extend_from_slice(&e.w_u32(btype));
    out.extend_from_slice(&e.w_u32(total as u32));
    out.extend_from_slice(&body);
    out.extend_from_slice(&e.w_u32(total as u32));
    Ok(())
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("out")
    ));
    {
        let mut fh = fs::File::create(&tmp)?;
        fh.write_all(data)?;
        fh.flush()?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        CapError(e.to_string())
    })?;
    Ok(())
}

pub fn format_size(num: u64) -> String {
    let units = ["B", "KB", "MB", "GB"];
    let mut value = num as f64;
    for unit in units {
        if value < 1024.0 || unit == "GB" {
            return if unit == "B" {
                format!("{num} B")
            } else {
                format!("{value:.1} {unit}")
            };
        }
        value /= 1024.0;
    }
    format!("{value:.1} GB")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad4_rounds_up() {
        assert_eq!(pad4(0), 0);
        assert_eq!(pad4(1), 3);
        assert_eq!(pad4(3), 1);
        assert_eq!(pad4(4), 0);
    }

    #[test]
    fn format_size_units() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.0 KB");
    }
}
