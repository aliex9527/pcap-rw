//! IPv4 / IPv6 address rewriting engine for pcap/pcapng captures.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::capture::{Capture, Packet};
use crate::checksum::{checksum, segment_checksum, tcp_udp_checksum};
use crate::link::{parse_ip_any, parse_ip_header, Ip, IpView};

#[derive(Debug, Clone, Default)]
pub struct RewriteStats {
    pub packets_total: usize,
    pub ipv4_packets: usize,
    pub ipv6_packets: usize,
    pub packets_modified: usize,
    pub src_hits: usize,
    pub dst_hits: usize,
    pub payload_hits: usize,
    pub ip_headers: usize,
    pub l4_checksums: usize,
    pub l4_skipped: usize,
    /// Fragmented datagrams whose offset-0 fragment is absent, where the
    /// transport header position was inferred and its checksum recomputed.
    pub l4_recovered: usize,
    pub seq_fixed: usize,
    pub bytes_delta: i64,
    pub warnings: Vec<String>,
    pub unsafe_payload_flows: usize,
    pub cancelled: bool,
}

impl RewriteStats {
    pub fn warn(&mut self, message: impl Into<String>) {
        let message = message.into();
        if !self.warnings.iter().any(|w| *w == message) {
            self.warnings.push(message);
        }
    }

    /// IPv4 + IPv6 packets that carried an address header.
    pub fn ip_packets(&self) -> usize {
        self.ipv4_packets + self.ipv6_packets
    }
}

/// An address substitution table parsed from user input.
#[derive(Debug, Clone, Default)]
pub struct Mapping {
    pairs: Vec<(Ip, Ip)>,
}

impl Mapping {
    pub fn new(pairs: Vec<(Ip, Ip)>) -> Self {
        let mut out: Vec<(Ip, Ip)> = Vec::new();
        for (old, new) in pairs {
            // Cross-family substitutions cannot be written back into a packet.
            if old == new || old.is_v4() != new.is_v4() {
                continue;
            }
            if let Some(slot) = out.iter_mut().find(|(o, _)| *o == old) {
                slot.1 = new;
            } else {
                out.push((old, new));
            }
        }
        Mapping { pairs: out }
    }

    /// Build from text pairs, ignoring rows where both sides are blank.
    pub fn from_text<S: AsRef<str>>(pairs: &[(S, S)]) -> std::result::Result<Self, String> {
        let mut out = Vec::new();
        for (old, new) in pairs {
            let old_t = old.as_ref().trim();
            let new_t = new.as_ref().trim();
            if old_t.is_empty() && new_t.is_empty() {
                continue;
            }
            let old_ip = parse_ip_any(old_t).ok_or_else(|| format!("旧地址不合法：{old_t}"))?;
            let new_ip = parse_ip_any(new_t).ok_or_else(|| format!("新地址不合法：{new_t}"))?;
            if old_ip.is_v4() != new_ip.is_v4() {
                return Err(format!(
                    "地址族不一致：{old_t} → {new_t}（IPv4 只能换成 IPv4，IPv6 只能换成 IPv6）"
                ));
            }
            out.push((old_ip, new_ip));
        }
        let mapping = Mapping::new(out);
        if mapping.is_empty() {
            return Err("没有有效的地址映射（旧地址与新地址相同也算无效）".into());
        }
        Ok(mapping)
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn pairs(&self) -> &[(Ip, Ip)] {
        &self.pairs
    }

    pub fn lookup(&self, ip: &Ip) -> Option<Ip> {
        self.pairs
            .iter()
            .find(|(old, _)| old == ip)
            .map(|(_, new)| *new)
    }

    pub fn old_ips(&self) -> Vec<Ip> {
        self.pairs.iter().map(|(old, _)| *old).collect()
    }

    /// Byte patterns for payload text replacement, longest first.
    fn text_patterns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut pats: Vec<(Vec<u8>, Vec<u8>)> = self
            .pairs
            .iter()
            .map(|(old, new)| (old.text().into_bytes(), new.text().into_bytes()))
            .collect();
        pats.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        pats
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlowKey {
    pub src: Ip,
    pub dst: Ip,
    pub sport: u16,
    pub dport: u16,
}

impl TcpFlowKey {
    pub fn reverse(&self) -> Self {
        TcpFlowKey {
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
        }
    }
}

/// (source, destination, fragment id, protocol discriminator)
type FragKey = (Ip, Ip, u32, u8);

/// Key used to group fragments of one datagram.
///
/// IPv4 identification is only 16 bits wide, so the upper-layer protocol has to
/// take part in the key. An IPv6 identification is 32 bits and unique per
/// (source, destination) pair, while its upper-layer protocol may hide behind
/// headers that only the first fragment carries — so family-6 entries use a zero
/// discriminator and never split a datagram because of it.
fn frag_key(view: &IpView) -> FragKey {
    match view {
        IpView::V4(v) => (Ip::V4(v.src), Ip::V4(v.dst), v.ident as u32, v.protocol),
        IpView::V6(v) => (Ip::V6(v.src), Ip::V6(v.dst), v.ident, 0),
    }
}

pub struct Rewriter {
    mapping: Mapping,
    replace_payload: bool,
    patterns: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Rewriter {
    pub fn new(mapping: Mapping, replace_payload: bool) -> Self {
        let patterns = mapping.text_patterns();
        Rewriter {
            mapping,
            replace_payload,
            patterns,
        }
    }

    pub fn process(
        &self,
        cap: &mut Capture,
        cancel: Option<&AtomicBool>,
        mut progress: Option<&mut dyn FnMut(usize, usize)>,
    ) -> RewriteStats {
        let total = cap.packet_count();
        let mut stats = RewriteStats {
            packets_total: total,
            ..Default::default()
        };

        let reassembly = reassemble_fragments(cap);
        let mut allow_payload = self.replace_payload;
        if allow_payload {
            if cap.packets().any(|p| p.truncated()) {
                allow_payload = false;
                stats.warn("存在被截断的包（caplen < origlen），已自动关闭载荷文本替换");
            }
            if reassembly.any {
                allow_payload = false;
                stats.warn("捕获中存在 IP 分片，已自动关闭载荷文本替换（地址改写不受影响）");
            }
        }

        let unsafe_flows = if allow_payload {
            find_unsafe_flows(cap)
        } else {
            HashSet::new()
        };
        if !unsafe_flows.is_empty() {
            stats.unsafe_payload_flows = unsafe_flows.len() / 2;
            let count = stats.unsafe_payload_flows;
            stats.warn(format!(
                "检测到 {count} 条 TCP 流存在重传/乱序，这些流只改 IP 头，不替换载荷文本"
            ));
        }

        let mut deltas: HashMap<TcpFlowKey, i64> = HashMap::new();
        let mut last_report = 0usize;
        let mut idx = 0usize;
        let is_cancelled = || cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false);

        for pkt in cap.packets_mut() {
            idx += 1;
            if is_cancelled() {
                stats.cancelled = true;
                stats.warn("用户已取消，输出可能不完整");
                break;
            }
            if let Some(cb) = progress.as_deref_mut() {
                if idx - last_report >= 200 || idx == total {
                    cb(idx, total);
                    last_report = idx;
                }
            }
            self.process_packet(
                pkt,
                &mut stats,
                &mut deltas,
                allow_payload,
                &unsafe_flows,
                &reassembly,
            );
        }
        stats
    }

    fn process_packet(
        &self,
        pkt: &mut Packet,
        stats: &mut RewriteStats,
        deltas: &mut HashMap<TcpFlowKey, i64>,
        allow_payload: bool,
        unsafe_flows: &HashSet<TcpFlowKey>,
        reassembly: &Reassembly,
    ) {
        let view = match parse_ip_header(&pkt.data, pkt.linktype) {
            Some(v) => v,
            None => return,
        };
        if view.version() == 4 {
            stats.ipv4_packets += 1;
        } else {
            stats.ipv6_packets += 1;
        }

        let off = view.offset();
        let hdr_len = view.header_len();
        let l4_off = view.l4_offset();
        let proto = view.l4_proto();
        let mut total_len = view.total_len();
        let (src, dst) = (view.src(), view.dst());
        let new_src = self.mapping.lookup(&src).unwrap_or(src);
        let new_dst = self.mapping.lookup(&dst).unwrap_or(dst);
        if new_src == src && new_dst == dst {
            return;
        }

        if total_len < hdr_len {
            stats.warn("发现 IP 总长度小于头长度，已跳过该包");
            return;
        }

        let mut captured_end = off + total_len;
        let ip_truncated = captured_end > pkt.data.len();
        let fragmented = view.fragmented();
        let frag_offset = view.frag_offset();

        let mut payload_delta: i64 = 0;
        let mut ports: Option<(u16, u16)> = None;
        let mut seq_orig = 0u32;
        let mut ack_orig = 0u32;
        let mut tcp_doff = 20usize;
        let is_tcp = proto == 6;
        // Later fragments carry fragment data where a transport header would be,
        // so ports and sequence numbers must not be read from them.
        let l4_ok = view.l4_present();

        if is_tcp && l4_ok && l4_off + 20 <= pkt.data.len() && l4_off + 20 <= captured_end {
            ports = Some((
                u16::from_be_bytes([pkt.data[l4_off], pkt.data[l4_off + 1]]),
                u16::from_be_bytes([pkt.data[l4_off + 2], pkt.data[l4_off + 3]]),
            ));
            seq_orig = u32::from_be_bytes([
                pkt.data[l4_off + 4],
                pkt.data[l4_off + 5],
                pkt.data[l4_off + 6],
                pkt.data[l4_off + 7],
            ]);
            ack_orig = u32::from_be_bytes([
                pkt.data[l4_off + 8],
                pkt.data[l4_off + 9],
                pkt.data[l4_off + 10],
                pkt.data[l4_off + 11],
            ]);
            tcp_doff = ((pkt.data[l4_off + 12] >> 4) as usize) * 4;
        } else if proto == 17
            && l4_ok
            && l4_off + 8 <= pkt.data.len()
            && l4_off + 8 <= captured_end
        {
            ports = Some((
                u16::from_be_bytes([pkt.data[l4_off], pkt.data[l4_off + 1]]),
                u16::from_be_bytes([pkt.data[l4_off + 2], pkt.data[l4_off + 3]]),
            ));
        }

        // 1) Shift TCP sequence numbers for earlier payload-length changes.
        if is_tcp && !ip_truncated {
            if let Some((sport, dport)) = ports {
                if !deltas.is_empty() {
                    let key = TcpFlowKey {
                        src,
                        dst,
                        sport,
                        dport,
                    };
                    let d_forward = deltas.get(&key).copied().unwrap_or(0);
                    let d_reverse = deltas.get(&key.reverse()).copied().unwrap_or(0);
                    let flags = pkt.data[l4_off + 13];
                    if d_forward != 0 {
                        let seq = (seq_orig as i64 + d_forward) as u32;
                        pkt.data[l4_off + 4..l4_off + 8].copy_from_slice(&seq.to_be_bytes());
                        stats.seq_fixed += 1;
                    }
                    if d_reverse != 0 && (flags & 0x10) != 0 {
                        let ack = (ack_orig as i64 + d_reverse) as u32;
                        pkt.data[l4_off + 8..l4_off + 12].copy_from_slice(&ack.to_be_bytes());
                        stats.seq_fixed += 1;
                    }
                }
            }
        }

        // 2) Optional payload text replacement (skip fragments, truncated, unsafe flows).
        if allow_payload && !ip_truncated && !fragmented {
            if let Some((sport, dport)) = ports {
                if proto == 6 || proto == 17 {
                    let key = TcpFlowKey {
                        src,
                        dst,
                        sport,
                        dport,
                    };
                    if !unsafe_flows.contains(&key) {
                        let payload_start = l4_off + if proto == 6 { tcp_doff } else { 8 };
                        if payload_start <= captured_end && captured_end <= pkt.data.len() {
                            let old_payload = &pkt.data[payload_start..captured_end];
                            if !old_payload.is_empty() {
                                if let Some((new_payload, hits)) = self.replace_text(old_payload) {
                                    let delta = new_payload.len() as i64 - old_payload.len() as i64;
                                    pkt.data.splice(payload_start..captured_end, new_payload);
                                    payload_delta = delta;
                                    stats.payload_hits += hits;
                                    stats.bytes_delta += delta;
                                    if is_tcp {
                                        *deltas.entry(key).or_insert(0) += delta;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3) Write the new addresses.
        match (&new_src, &new_dst) {
            (Ip::V4(s), Ip::V4(d)) => {
                pkt.data[off + 12..off + 16].copy_from_slice(s);
                pkt.data[off + 16..off + 20].copy_from_slice(d);
            }
            (Ip::V6(s), Ip::V6(d)) => {
                pkt.data[off + 8..off + 24].copy_from_slice(s);
                pkt.data[off + 24..off + 40].copy_from_slice(d);
            }
            // Mixed families never reach here: Mapping drops such pairs.
            _ => return,
        }
        stats.packets_modified += 1;
        if new_src != src {
            stats.src_hits += 1;
        }
        if new_dst != dst {
            stats.dst_hits += 1;
        }

        // 4) Fix lengths after a payload-length change.
        if payload_delta != 0 {
            total_len = (total_len as i64 + payload_delta) as usize;
            match view {
                IpView::V4(_) => pkt.data[off + 2..off + 4]
                    .copy_from_slice(&(total_len as u16).to_be_bytes()),
                IpView::V6(_) => {
                    let payload_len = total_len - 40;
                    pkt.data[off + 4..off + 6]
                        .copy_from_slice(&(payload_len as u16).to_be_bytes());
                }
            }
            captured_end = off + total_len;
            pkt.orig_len = (pkt.orig_len as i64 + payload_delta) as usize;
            if proto == 17 {
                let udp_len = (total_len - hdr_len) as u16;
                pkt.data[l4_off + 4..l4_off + 6].copy_from_slice(&udp_len.to_be_bytes());
            }
        }

        // 5) IPv4 header checksum (IPv6 has none).
        if matches!(view, IpView::V4(_)) {
            pkt.data[off + 10..off + 12].copy_from_slice(&[0, 0]);
            let ip_ck = checksum(&pkt.data[off..off + hdr_len]);
            pkt.data[off + 10..off + 12].copy_from_slice(&ip_ck.to_be_bytes());
            stats.ip_headers += 1;
        }

        // 6) Transport checksum.
        if ip_truncated || total_len > pkt.data.len() - off {
            stats.l4_skipped += 1;
            return;
        }

        if fragmented {
            let key = frag_key(&view);
            if frag_offset != 0 {
                // The offset-0 fragment is missing from this capture, so the
                // extension header chain went with it and the transport header
                // has to be located by inference before the checksum can be
                // recomputed.
                if recover_headless_checksum(pkt, &view, new_src, new_dst, stats, reassembly) {
                    return;
                }
                stats.l4_skipped += 1;
                return;
            }
            // Extension headers that sit behind the Fragment header belong to the
            // fragmentable part, so the transport header starts `shift` bytes into
            // the reassembled buffer instead of at its beginning.
            let shift = view.frag_l4_shift();
            let assembled = reassembly.complete.get(&key);
            let segment = match assembled.and_then(|buf| buf.get(shift..)) {
                Some(segment) => segment,
                None => {
                    stats.l4_skipped += 1;
                    if assembled.is_none() {
                        stats.warn("存在不完整的 IP 分片，首个分片的 TCP/UDP 校验和未重算");
                    }
                    return;
                }
            };
            // Checksum field offset inside the segment, plus its end offset.
            let field = match proto {
                6 => 16usize,
                17 => 6usize,
                _ => {
                    stats.l4_skipped += 1;
                    return;
                }
            };
            if segment.len() < field + 2 || l4_off + field + 2 > captured_end {
                stats.l4_skipped += 1;
                return;
            }
            if proto == 17 {
                let existing = u16::from_be_bytes([pkt.data[l4_off + 6], pkt.data[l4_off + 7]]);
                if existing != 0 {
                    let value = segment_checksum(
                        new_src.bytes(),
                        new_dst.bytes(),
                        proto,
                        segment,
                        field,
                    );
                    pkt.data[l4_off + 6..l4_off + 8].copy_from_slice(&value.to_be_bytes());
                }
            } else {
                let value =
                    segment_checksum(new_src.bytes(), new_dst.bytes(), proto, segment, field);
                pkt.data[l4_off + 16..l4_off + 18].copy_from_slice(&value.to_be_bytes());
            }
            stats.l4_checksums += 1;
            return;
        }

        let segment = pkt.data[l4_off..captured_end].to_vec();
        if proto == 6 && segment.len() >= 20 {
            let value = segment_checksum(new_src.bytes(), new_dst.bytes(), proto, &segment, 16);
            pkt.data[l4_off + 16..l4_off + 18].copy_from_slice(&value.to_be_bytes());
            stats.l4_checksums += 1;
        } else if proto == 17 && segment.len() >= 8 {
            if segment[6] != 0 || segment[7] != 0 {
                let value = segment_checksum(new_src.bytes(), new_dst.bytes(), proto, &segment, 6);
                pkt.data[l4_off + 6..l4_off + 8].copy_from_slice(&value.to_be_bytes());
            }
            stats.l4_checksums += 1;
        }
    }

    /// Single-pass literal substitution; returns `None` when nothing matched.
    fn replace_text(&self, payload: &[u8]) -> Option<(Vec<u8>, usize)> {
        if self.patterns.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(payload.len());
        let mut i = 0usize;
        let mut hits = 0usize;
        while i < payload.len() {
            let mut matched = false;
            for (pat, rep) in &self.patterns {
                if payload[i..].starts_with(pat) {
                    // Avoid partial matches inside a longer address literal.
                    let before_ok = i == 0 || !is_addr_char(payload[i - 1]);
                    let end = i + pat.len();
                    let after_ok = end >= payload.len() || !is_addr_char(payload[end]);
                    if before_ok && after_ok {
                        out.extend_from_slice(rep);
                        i = end;
                        hits += 1;
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                out.push(payload[i]);
                i += 1;
            }
        }
        if hits == 0 {
            None
        } else {
            Some((out, hits))
        }
    }
}

/// Characters that may continue an address literal (dotted quad or IPv6 hex form).
fn is_addr_char(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b'.' || b == b':'
}

/// Fragment reassembly state for one capture.
struct Reassembly {
    /// Datagrams whose first byte was captured, ready to be sliced at the
    /// transport header.
    complete: HashMap<FragKey, Vec<u8>>,
    /// Datagrams whose leading bytes never showed up because the offset-0
    /// fragment is absent from the capture: the offset of the first captured
    /// byte, plus every byte from there to the end of the datagram.
    headless: HashMap<FragKey, (usize, Vec<u8>)>,
    /// Whether the capture holds any fragment at all.
    any: bool,
}

fn reassemble_fragments(cap: &Capture) -> Reassembly {
    struct Entry {
        chunks: Vec<(usize, Vec<u8>)>,
        total: Option<usize>,
    }

    let mut parts: HashMap<FragKey, Entry> = HashMap::new();
    let mut any = false;

    for pkt in cap.packets() {
        let view = match parse_ip_header(&pkt.data, pkt.linktype) {
            Some(v) => v,
            None => continue,
        };
        if !view.fragmented() {
            continue;
        }
        any = true;
        if pkt.truncated() || view.offset() + view.total_len() > pkt.data.len() {
            continue;
        }
        let key = frag_key(&view);
        let end = view.offset() + view.total_len();
        // Reassembly offsets are relative to the fragmentable part, which starts
        // right after the Fragment header — not after the extension headers that
        // only the first fragment carries.
        let start = view.frag_data_offset();
        if start > end || end > pkt.data.len() {
            continue;
        }
        let entry = parts.entry(key).or_insert_with(|| Entry {
            chunks: Vec::new(),
            total: None,
        });
        let chunk = pkt.data[start..end].to_vec();
        let offset = view.frag_offset();
        if !view.more_fragments() {
            entry.total = Some(offset + chunk.len());
        }
        entry.chunks.push((offset, chunk));
    }

    let mut out = Reassembly {
        complete: HashMap::new(),
        headless: HashMap::new(),
        any,
    };
    for (key, mut entry) in parts {
        let total = match entry.total {
            Some(t) => t,
            None => continue,
        };
        entry.chunks.sort_by_key(|(off, _)| *off);
        // The earliest captured byte. Zero when the first fragment is there;
        // larger when it is missing, in which case everything before it (the
        // extension header chain and possibly part of the transport header) is
        // gone.
        let start = entry.chunks[0].0;
        if total < start {
            continue;
        }
        let mut buf: Vec<u8> = Vec::with_capacity(total - start);
        for (off, chunk) in &entry.chunks {
            // A hole makes every later offset uncertain.
            if *off != start + buf.len() {
                break;
            }
            buf.extend_from_slice(chunk);
        }
        if start + buf.len() < total {
            continue;
        }
        buf.truncate(total - start);
        if start == 0 {
            out.complete.insert(key, buf);
        } else {
            out.headless.insert(key, (start, buf));
        }
    }
    out
}

/// How far past the lost prefix the transport header may start. Extension
/// header chains that reach further are rare, and every candidate offset costs
/// one checksum pass over the rest of the datagram.
const HEADLESS_SCAN_LIMIT: usize = 256;

/// Recompute the transport checksum of a fragmented datagram whose offset-0
/// fragment never made it into the capture.
///
/// Everything the first fragment carried is gone, including the extension
/// headers that decided where the transport header starts. Because every byte
/// from the transport header onwards *is* present, a candidate position can be
/// tested: the original checksum was computed over the whole segment, so a
/// correct one sums to zero. Returns false when no position can be established,
/// leaving the caller to report the packet as skipped.
fn recover_headless_checksum(
    pkt: &mut Packet,
    view: &IpView,
    new_src: Ip,
    new_dst: Ip,
    stats: &mut RewriteStats,
    reassembly: &Reassembly,
) -> bool {
    let key = frag_key(view);
    let (start, buf) = match reassembly.headless.get(&key) {
        Some(entry) => entry,
        None => return false,
    };
    if *start != view.frag_offset() {
        // Another packet of this group starts earlier and already dealt with it.
        return false;
    }
    let located = match locate_lost_transport(view, buf) {
        Some(found) => found,
        None => {
            stats.warn("存在缺少首个分片的 IP 分片，扩展头长度无法确定，这些分组的 TCP/UDP 校验和未重算");
            return false;
        }
    };
    let (rel, proto) = located;
    let field = match proto {
        6 => 16usize,
        17 => 6usize,
        _ => return false,
    };
    // Everything up to the checksum field has to live in this fragment.
    let base = view.frag_data_offset() + rel + field;
    let end = (view.offset() + view.total_len()).min(pkt.data.len());
    if base + 2 > end {
        stats.warn("存在缺少首个分片的 IP 分片，推断出的上层协议头跨越了分片边界，TCP/UDP 校验和未重算");
        return false;
    }
    if proto == 17 {
        let existing = u16::from_be_bytes([pkt.data[base], pkt.data[base + 1]]);
        if existing == 0 {
            // No checksum to maintain for this datagram.
            stats.l4_checksums += 1;
            stats.l4_recovered += 1;
            return true;
        }
    }
    let value = segment_checksum(new_src.bytes(), new_dst.bytes(), proto, &buf[rel..], field);
    pkt.data[base..base + 2].copy_from_slice(&value.to_be_bytes());
    stats.l4_checksums += 1;
    stats.l4_recovered += 1;
    stats.warn("有 IP 分片缺少首个分片，已按扩展头长度推断出上层协议头位置并重算校验和");
    true
}

/// Guess where the transport header starts inside a datagram whose leading
/// bytes were never captured.
///
/// Only IPv6 can be recovered: only there do extension headers sit behind the
/// Fragment header, leaving a header chain of unknown length between the lost
/// prefix and the transport header. The chain starts at a known header number
/// but its length is unknown, so the transport header can only be at an 8-byte
/// multiple — that is what this walks.
fn locate_lost_transport(view: &IpView, buf: &[u8]) -> Option<(usize, u8)> {
    let v6 = match view {
        IpView::V6(v) => v,
        IpView::V4(_) => return None,
    };
    // A chain that starts with the transport header puts that header at offset
    // zero of the fragmentable part — i.e. inside the lost prefix.
    if !matches!(v6.next_header, 0 | 43 | 51 | 60) {
        return None;
    }
    let src = &v6.src;
    let dst = &v6.dst;
    let limit = buf.len().min(HEADLESS_SCAN_LIMIT);
    let mut weak: Option<(usize, u8)> = None;
    let mut weak_hits = 0usize;

    let mut rel = 0usize;
    while rel + 8 <= limit {
        let rest = &buf[rel..];
        // UDP carries its own length, which must describe exactly the bytes that
        // remain — already a strong hint on its own.
        let udp_len = u16::from_be_bytes([rest[4], rest[5]]) as usize;
        if udp_len == rest.len() {
            let sport = u16::from_be_bytes([rest[0], rest[1]]);
            let dport = u16::from_be_bytes([rest[2], rest[3]]);
            let sum = u16::from_be_bytes([rest[6], rest[7]]);
            if sum != 0 && tcp_udp_checksum(src, dst, 17, rest) == 0 {
                return Some((rel, 17));
            }
            // Zero is not a valid port, so this rules out runs of padding.
            if sport != 0 && dport != 0 {
                weak = Some((rel, 17));
                weak_hits += 1;
            }
        }
        // TCP has no length field, so only a valid checksum can pin it down.
        if rest.len() >= 20 {
            let doff = ((rest[12] >> 4) as usize) * 4;
            if (20..=60).contains(&doff)
                && doff <= rest.len()
                && tcp_udp_checksum(src, dst, 6, rest) == 0
            {
                return Some((rel, 6));
            }
        }
        rel += 8;
    }
    // Two structurally plausible positions mean no answer at all.
    if weak_hits == 1 {
        weak
    } else {
        None
    }
}

fn find_unsafe_flows(cap: &Capture) -> HashSet<TcpFlowKey> {
    let mut unsafe_flows: HashSet<TcpFlowKey> = HashSet::new();
    let mut max_end: HashMap<TcpFlowKey, u32> = HashMap::new();

    for pkt in cap.packets() {
        let view = match parse_ip_header(&pkt.data, pkt.linktype) {
            Some(v) => v,
            None => continue,
        };
        if view.l4_proto() != 6 || view.fragmented() {
            continue;
        }
        let l4 = view.l4_offset();
        let limit = pkt.data.len().min(view.offset() + view.total_len());
        if l4 + 20 > limit {
            continue;
        }
        let sport = u16::from_be_bytes([pkt.data[l4], pkt.data[l4 + 1]]);
        let dport = u16::from_be_bytes([pkt.data[l4 + 2], pkt.data[l4 + 3]]);
        let seq = u32::from_be_bytes([
            pkt.data[l4 + 4],
            pkt.data[l4 + 5],
            pkt.data[l4 + 6],
            pkt.data[l4 + 7],
        ]);
        let doff = ((pkt.data[l4 + 12] >> 4) as usize) * 4;
        let payload_len = view.total_len().saturating_sub(view.header_len() + doff);
        if payload_len == 0 {
            continue;
        }
        let key = TcpFlowKey {
            src: view.src(),
            dst: view.dst(),
            sport,
            dport,
        };
        let end = seq.wrapping_add(payload_len as u32);
        if let Some(prev) = max_end.get(&key) {
            if seq < *prev {
                unsafe_flows.insert(key);
                unsafe_flows.insert(key.reverse());
            }
        }
        let slot = max_end.entry(key).or_insert(0);
        if end > *slot {
            *slot = end;
        }
    }
    unsafe_flows
}
