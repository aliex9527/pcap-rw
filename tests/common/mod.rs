//! Synthetic capture construction helpers for the integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use pcap_rw::capture::{save, Capture, Endian, Item, Kind, Packet};
use pcap_rw::checksum::tcp_udp_checksum;

pub fn ip(text: &str) -> [u8; 4] {
    let parts: Vec<u8> = text.split('.').map(|p| p.parse().unwrap()).collect();
    [parts[0], parts[1], parts[2], parts[3]]
}

pub fn ip6(text: &str) -> [u8; 16] {
    pcap_rw::link::parse_ipv6_text(text).expect("valid ipv6 literal")
}

/// Ethernet frame carrying an IPv4 payload.
pub fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Ethernet frame carrying an IPv6 payload.
pub fn ethernet6(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// IPv6 header (40 bytes) with no extension headers.
pub fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut hdr = vec![0u8; 40];
    hdr[0] = 0x60;
    hdr[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    hdr[6] = next;
    hdr[7] = 64;
    hdr[8..24].copy_from_slice(&src);
    hdr[24..40].copy_from_slice(&dst);
    hdr.extend_from_slice(payload);
    hdr
}

/// IPv6 packet with a fragment header in front of an upper-layer payload.
pub fn ipv6_frag(
    src: [u8; 16],
    dst: [u8; 16],
    ident: u32,
    offset_bytes: usize,
    more: bool,
    next: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut frag = vec![0u8; 8];
    frag[0] = next;
    let field: u16 = (((offset_bytes / 8) as u16) << 3) | u16::from(more);
    frag[2..4].copy_from_slice(&field.to_be_bytes());
    frag[4..8].copy_from_slice(&ident.to_be_bytes());

    let mut body = frag;
    body.extend_from_slice(payload);
    ipv6(src, dst, 44, &body)
}

pub fn ethernet_vlan(payload: &[u8], vlan: u16, inner_vlan: Option<u16>) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    match inner_vlan {
        Some(inner) => {
            frame.extend_from_slice(&0x88a8u16.to_be_bytes());
            frame.extend_from_slice(&vlan.to_be_bytes());
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&inner.to_be_bytes());
        }
        None => {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&vlan.to_be_bytes());
        }
    }
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    ident: u16,
    flags: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut hdr = vec![0u8; 20];
    hdr[0] = 0x45;
    hdr[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    hdr[4..6].copy_from_slice(&ident.to_be_bytes());
    hdr[6..8].copy_from_slice(&flags.to_be_bytes());
    hdr[8] = 64;
    hdr[9] = proto;
    hdr[12..16].copy_from_slice(&src);
    hdr[16..20].copy_from_slice(&dst);
    let ck = pcap_rw::checksum::checksum(&hdr);
    hdr[10..12].copy_from_slice(&ck.to_be_bytes());
    hdr.extend_from_slice(payload);
    hdr
}

pub fn tcp(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    tcp_seg(&src, &dst, sport, dport, seq, ack, flags, payload)
}

#[allow(clippy::too_many_arguments)]
pub fn tcp6(
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    tcp_seg(&src, &dst, sport, dport, seq, ack, flags, payload)
}

#[allow(clippy::too_many_arguments)]
fn tcp_seg(
    src: &[u8],
    dst: &[u8],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = vec![0u8; 20];
    seg[0..2].copy_from_slice(&sport.to_be_bytes());
    seg[2..4].copy_from_slice(&dport.to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = flags;
    seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
    seg.extend_from_slice(payload);
    let ck = tcp_udp_checksum(src, dst, 6, &seg);
    seg[16..18].copy_from_slice(&ck.to_be_bytes());
    seg
}

pub fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    udp_seg(&src, &dst, sport, dport, payload)
}

pub fn udp6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    udp_seg(&src, &dst, sport, dport, payload)
}

fn udp_seg(src: &[u8], dst: &[u8], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut seg = vec![0u8; 8];
    seg[0..2].copy_from_slice(&sport.to_be_bytes());
    seg[2..4].copy_from_slice(&dport.to_be_bytes());
    seg[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    seg.extend_from_slice(payload);
    let ck = tcp_udp_checksum(src, dst, 17, &seg);
    seg[6..8].copy_from_slice(&if ck == 0 { 0xFFFF } else { ck }.to_be_bytes());
    seg
}

/// Write a little-endian, microsecond-resolution pcap file.
pub fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    let mut cap = Capture {
        kind: Kind::Pcap,
        linktype: 1,
        header: Vec::new(),
        items: Vec::new(),
        endian: Endian::Little,
        nanosecond: false,
        path: path.to_path_buf(),
    };
    let mut header = Vec::new();
    header.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes());
    header.extend_from_slice(&4u16.to_le_bytes());
    header.extend_from_slice(&0i32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&65535u32.to_le_bytes());
    header.extend_from_slice(&1u32.to_le_bytes());
    cap.header = header;

    for (i, frame) in frames.iter().enumerate() {
        let mut pkt = Packet::new(frame.clone(), 1);
        pkt.ts_sec = 1_700_000_000 + i as u32;
        pkt.ts_frac = 0;
        pkt.endian = Endian::Little;
        pkt.block_type = 0;
        cap.items.push(Item::Packet(pkt));
    }
    save(&cap, path).expect("write pcap");
}

pub fn tmp_path(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push("pcaprw_tests");
    std::fs::create_dir_all(&dir).unwrap();
    dir.push(name);
    let _ = std::fs::remove_file(&dir);
    dir
}
