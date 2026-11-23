//! Post-write verification: checksums, leftover addresses, payload text.

use crate::capture::Capture;
use crate::checksum::{checksum, tcp_udp_checksum};
use crate::link::{parse_ip_any, parse_ip_header, Ip, IpView};

#[derive(Debug, Clone, Default)]
pub struct VerifyResult {
    pub packets: usize,
    pub ipv4_packets: usize,
    pub ipv6_packets: usize,
    pub ip_ok: usize,
    pub ip_bad: usize,
    pub l4_ok: usize,
    pub l4_bad: usize,
    pub l4_skipped: usize,
    pub old_in_header: usize,
    pub old_in_payload: usize,
    pub details: Vec<String>,
}

impl VerifyResult {
    pub fn ok(&self) -> bool {
        self.ip_bad == 0
            && self.l4_bad == 0
            && self.old_in_header == 0
            && self.old_in_payload == 0
    }

    pub fn summary(&self) -> String {
        if self.ok() {
            format!(
                "校验通过：{} 个包（IPv4 {} / IPv6 {}），IP 校验和 {} 通过，TCP/UDP 校验和 {} 通过",
                self.packets, self.ipv4_packets, self.ipv6_packets, self.ip_ok, self.l4_ok
            )
        } else {
            format!(
                "校验未通过：IP 错误 {}、L4 错误 {}、旧地址残留 {} 处",
                self.ip_bad,
                self.l4_bad,
                self.old_in_header + self.old_in_payload
            )
        }
    }
}

pub fn verify(cap: &Capture, old_ips: &[String], expect_no_payload_text: bool) -> VerifyResult {
    let olds: Vec<Ip> = old_ips.iter().filter_map(|s| parse_ip_any(s)).collect();
    let mut res = VerifyResult {
        packets: cap.packet_count(),
        ..Default::default()
    };

    for (idx, pkt) in cap.packets().enumerate() {
        let idx = idx + 1;
        let view = match parse_ip_header(&pkt.data, pkt.linktype) {
            Some(v) => v,
            None => continue,
        };
        let (src, dst) = (view.src(), view.dst());
        let src_text = src.text();
        let dst_text = dst.text();

        match view {
            IpView::V4(_) => {
                res.ipv4_packets += 1;
                let off = view.offset();
                if checksum(&pkt.data[off..off + view.header_len()]) == 0 {
                    res.ip_ok += 1;
                } else {
                    res.ip_bad += 1;
                    if res.details.len() < 8 {
                        res.details.push(format!(
                            "包 {idx}：IPv4 头校验和错误（{src_text} -> {dst_text}）"
                        ));
                    }
                }
            }
            IpView::V6(_) => {
                // IPv6 has no header checksum.
                res.ipv6_packets += 1;
            }
        }

        for old in &olds {
            if src == *old || dst == *old {
                res.old_in_header += 1;
                if res.details.len() < 8 {
                    res.details
                        .push(format!("包 {idx}：IP 头仍含旧地址 {old}"));
                }
            }
        }

        let proto = view.l4_proto();
        let fragmented = view.fragmented();
        let end = view.offset() + view.total_len();
        let l4 = view.l4_offset();
        if (proto == 6 || proto == 17) && !fragmented {
            if pkt.truncated() || end > pkt.data.len() || l4 > end {
                res.l4_skipped += 1;
            } else {
                let segment = &pkt.data[l4..end];
                let too_short = (proto == 6 && segment.len() < 20)
                    || (proto == 17 && segment.len() < 8);
                let udp_absent =
                    proto == 17 && segment.len() >= 8 && segment[6] == 0 && segment[7] == 0;
                if too_short || udp_absent {
                    res.l4_skipped += 1;
                } else if tcp_udp_checksum(src.bytes(), dst.bytes(), proto, segment) == 0 {
                    res.l4_ok += 1;
                } else {
                    res.l4_bad += 1;
                    if res.details.len() < 8 {
                        let name = if proto == 6 { "TCP" } else { "UDP" };
                        res.details.push(format!(
                            "包 {idx}：{name} 校验和错误（{src_text} -> {dst_text}）"
                        ));
                    }
                }
            }
        } else if fragmented {
            res.l4_skipped += 1;
        }

        if expect_no_payload_text
            && (proto == 6 || proto == 17)
            && !pkt.truncated()
            && end <= pkt.data.len()
        {
            let payload = &pkt.data[l4..end];
            for old in &olds {
                let needle = old.text();
                if contains(payload, needle.as_bytes()) {
                    res.old_in_payload += 1;
                    if res.details.len() < 8 {
                        res.details
                            .push(format!("包 {idx}：载荷仍含旧地址文本 {needle}"));
                    }
                }
            }
        }
    }
    res
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
