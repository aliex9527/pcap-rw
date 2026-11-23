//! Quick inventory of IP endpoints and conversations in a capture.

use std::collections::HashMap;

use crate::capture::Capture;
use crate::link::{has_vlan, parse_ip_header, Ip};

#[derive(Debug, Clone, Default)]
pub struct IpInfo {
    pub ip: Ip,
    pub packets: usize,
    pub bytes: u64,
    pub ports: Vec<(u16, usize)>,
    pub protocols: Vec<(u8, usize)>,
    pub in_payload: usize,
    pub first_index: usize,
}

impl IpInfo {
    pub fn ip_text(&self) -> String {
        self.ip.text()
    }

    pub fn describe_ports(&self, limit: usize) -> String {
        if self.ports.is_empty() {
            return "—".to_string();
        }
        let parts: Vec<String> = self
            .ports
            .iter()
            .take(limit)
            .map(|(p, c)| format!("{p}({c})"))
            .collect();
        let mut text = parts.join("，");
        if self.ports.len() > limit {
            text.push_str(&format!(" 等 {} 个", self.ports.len()));
        }
        text
    }
}

#[derive(Debug, Clone, Default)]
pub struct PairInfo {
    pub src: Ip,
    pub dst: Ip,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub packets: usize,
    pub bytes: u64,
}

impl PairInfo {
    pub fn label(&self) -> String {
        format!(
            "{}:{} -> {}:{}",
            host_text(&self.src),
            self.sport,
            host_text(&self.dst),
            self.dport
        )
    }
}

/// IPv6 literals need brackets when combined with a port.
fn host_text(ip: &Ip) -> String {
    match ip {
        Ip::V4(b) => crate::link::ip_str(b),
        Ip::V6(b) => format!("[{}]", crate::link::ipv6_str(b)),
    }
}

#[derive(Debug, Clone, Default)]
pub struct Analysis {
    pub packets: usize,
    pub ipv4_packets: usize,
    pub ipv6_packets: usize,
    pub vlan_packets: usize,
    pub fragmented_packets: usize,
    pub truncated_packets: usize,
    pub ips: Vec<IpInfo>,
    pub pairs: Vec<PairInfo>,
    pub protocols: Vec<(u8, usize)>,
}

impl Analysis {
    pub fn ip_packets(&self) -> usize {
        self.ipv4_packets + self.ipv6_packets
    }
}

pub fn proto_name(num: u8) -> &'static str {
    match num {
        0 => "HOPOPT",
        1 => "ICMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        43 => "ROUTING",
        44 => "FRAG",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        59 => "NO-NXT",
        60 => "DSTOPTS",
        _ => "IP",
    }
}

fn bump(list: &mut Vec<(u8, usize)>, key: u8) {
    match list.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 += 1,
        None => list.push((key, 1)),
    }
}

pub fn analyze(cap: &Capture) -> Analysis {
    let mut result = Analysis {
        packets: cap.packet_count(),
        ..Default::default()
    };
    let mut ip_map: HashMap<Ip, IpInfo> = HashMap::new();
    let mut pair_map: HashMap<(Ip, Ip, u8, u16, u16), PairInfo> = HashMap::new();

    for (idx, pkt) in cap.packets().enumerate() {
        let idx = idx + 1;
        if pkt.truncated() {
            result.truncated_packets += 1;
        }
        if has_vlan(&pkt.data, pkt.linktype) {
            result.vlan_packets += 1;
        }

        let view = match parse_ip_header(&pkt.data, pkt.linktype) {
            Some(v) => v,
            None => continue,
        };
        if view.version() == 4 {
            result.ipv4_packets += 1;
        } else {
            result.ipv6_packets += 1;
        }
        if view.fragmented() {
            result.fragmented_packets += 1;
        }
        let proto = view.l4_proto();
        bump(&mut result.protocols, proto);

        let size = view
            .total_len()
            .min(pkt.data.len().saturating_sub(view.offset())) as u64;
        let (src, dst) = (view.src(), view.dst());

        for addr in [src, dst] {
            let info = ip_map.entry(addr).or_insert_with(|| IpInfo {
                ip: addr,
                first_index: idx,
                ..Default::default()
            });
            info.packets += 1;
            info.bytes += size;
            bump(&mut info.protocols, proto);
        }

        // Later fragments carry fragment data where the transport header would
        // be, so only packets that actually hold a header contribute ports.
        if (proto == 6 || proto == 17) && view.l4_present() {
            let l4 = view.l4_offset();
            if l4 + 4 <= pkt.data.len() && l4 + 4 <= view.offset() + view.total_len() {
                let sport = u16::from_be_bytes([pkt.data[l4], pkt.data[l4 + 1]]);
                let dport = u16::from_be_bytes([pkt.data[l4 + 2], pkt.data[l4 + 3]]);
                if sport != 0 {
                    if let Some(info) = ip_map.get_mut(&src) {
                        match info.ports.iter_mut().find(|(p, _)| *p == sport) {
                            Some(slot) => slot.1 += 1,
                            None => info.ports.push((sport, 1)),
                        }
                    }
                }
                if dport != 0 {
                    if let Some(info) = ip_map.get_mut(&dst) {
                        match info.ports.iter_mut().find(|(p, _)| *p == dport) {
                            Some(slot) => slot.1 += 1,
                            None => info.ports.push((dport, 1)),
                        }
                    }
                }
                let key = (src, dst, proto, sport, dport);
                let pair = pair_map.entry(key).or_insert_with(|| PairInfo {
                    src,
                    dst,
                    proto,
                    sport,
                    dport,
                    ..Default::default()
                });
                pair.packets += 1;
                pair.bytes += size;
            }
        }

        // Does the payload mention either endpoint as text (Host/Referer etc.)?
        if (proto == 6 || proto == 17) && view.l4_present() && !pkt.truncated() {
            let end = (view.offset() + view.total_len()).min(pkt.data.len());
            let start = view.l4_offset().min(end);
            let payload = &pkt.data[start..end];
            if !payload.is_empty() {
                if contains(payload, src.text().as_bytes()) {
                    if let Some(info) = ip_map.get_mut(&src) {
                        info.in_payload += 1;
                    }
                }
                if contains(payload, dst.text().as_bytes()) {
                    if let Some(info) = ip_map.get_mut(&dst) {
                        info.in_payload += 1;
                    }
                }
            }
        }
    }

    result.ips = ip_map.into_values().collect();
    result.ips.sort_by(|a, b| {
        b.packets
            .cmp(&a.packets)
            .then_with(|| a.ip.cmp(&b.ip))
    });
    for info in &mut result.ips {
        info.ports.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        info.protocols
            .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    }
    result.protocols.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    result.pairs = pair_map.into_values().collect();
    result.pairs.sort_by(|a, b| b.packets.cmp(&a.packets));
    result
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
