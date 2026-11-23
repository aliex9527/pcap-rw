mod common;

use common::{
    ethernet, ethernet6, ethernet_vlan, ip, ip6, ipv4, ipv6, ipv6_frag, tcp, tcp6, tmp_path, udp,
    udp6, write_pcap,
};
use pcap_rw::capture::{save, Endian, Item, Kind, Packet};
use pcap_rw::checksum::{checksum, tcp_udp_checksum};
use pcap_rw::link::{parse_ipv4, parse_ipv6, Ip};
use pcap_rw::rewrite::{Mapping, Rewriter};
use pcap_rw::verify::verify;

const A: &str = "10.1.2.3";
const B: &str = "192.168.50.7";
const C: &str = "36.112.209.154";
const D: &str = "112.80.32.175";

fn mapping() -> Mapping {
    Mapping::from_text(&[
        (A.to_string(), C.to_string()),
        (B.to_string(), D.to_string()),
    ])
    .unwrap()
}

fn rewrite_file(path: &std::path::Path, replace_payload: bool) -> pcap_rw::RewriteStats {
    let mut cap = pcap_rw::capture::load(path).unwrap();
    let rewriter = Rewriter::new(mapping(), replace_payload);
    let stats = rewriter.process(&mut cap, None, None);
    save(&cap, path).unwrap();
    stats
}

fn tcp_checksum_ok(pkt: &Packet) -> bool {
    let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
    let end = view.offset + view.total_len;
    let seg = &pkt.data[view.offset + view.ihl..end];
    tcp_udp_checksum(&view.src, &view.dst, 6, seg) == 0
}

#[test]
fn rewrites_tcp_and_fixes_checksums() {
    let path = tmp_path("tcp_in.pcap");
    let out = tmp_path("tcp_out.pcap");
    let body = b"hello";
    let frame = ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 1000, 1, 0x18, body)));
    write_pcap(&path, &[frame]);

    let stats = rewrite_file(&path, false);
    assert_eq!(stats.packets_modified, 1);
    assert_eq!(stats.src_hits, 1);
    assert_eq!(stats.dst_hits, 1);

    let cap = pcap_rw::capture::load(&path).unwrap();
    save(&cap, &out).unwrap();
    let check = pcap_rw::capture::load(&out).unwrap();
    let pkt = check.packets().next().unwrap();
    let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.src, ip(C));
    assert_eq!(view.dst, ip(D));
    assert!(checksum(&pkt.data[view.offset..view.offset + view.ihl]) == 0);
    assert!(tcp_checksum_ok(pkt));

    // Ports and sequence numbers must be untouched when the payload is not rewritten.
    let l4 = view.offset + view.ihl;
    assert_eq!(u16::from_be_bytes([pkt.data[l4], pkt.data[l4 + 1]]), 40000);
    assert_eq!(
        u32::from_be_bytes([
            pkt.data[l4 + 4],
            pkt.data[l4 + 5],
            pkt.data[l4 + 6],
            pkt.data[l4 + 7]
        ]),
        1000
    );

    let result = verify(&check, &[A.to_string(), B.to_string()], false);
    assert!(result.ok(), "{}", result.summary());
}

#[test]
fn handles_vlan_and_qinq() {
    for (label, frame) in [
        ("vlan", ethernet_vlan(&ipv4(ip(A), ip(B), 17, 5, 0, &udp(ip(A), ip(B), 1111, 2222, b"x")), 0x0522, None)),
        ("qinq", ethernet_vlan(&ipv4(ip(A), ip(B), 17, 6, 0, &udp(ip(A), ip(B), 1111, 2222, b"x")), 0x0522, Some(0x0a0b))),
    ] {
        let path = tmp_path(&format!("{label}.pcap"));
        write_pcap(&path, &[frame]);
        let stats = rewrite_file(&path, false);
        assert_eq!(stats.packets_modified, 1, "{label}");
        let cap = pcap_rw::capture::load(&path).unwrap();
        let pkt = cap.packets().next().unwrap();
        let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
        assert_eq!(view.src, ip(C), "{label}");
        assert_eq!(view.dst, ip(D), "{label}");
        assert!(checksum(&pkt.data[view.offset..view.offset + view.ihl]) == 0);
        let l4 = view.offset + view.ihl;
        assert!(tcp_udp_checksum(&view.src, &view.dst, 17, &pkt.data[l4..view.offset + view.total_len]) == 0);
        // The VLAN tags themselves must survive untouched (0x8100 for 802.1Q, 0x88a8 for QinQ).
        let expected_tag: [u8; 2] = if label == "qinq" { [0x88, 0xa8] } else { [0x81, 0x00] };
        assert_eq!(&pkt.data[12..14], &expected_tag, "{label}");
    }
}

#[test]
fn reassembles_fragmented_udp() {
    let path = tmp_path("frag.pcap");
    let payload: Vec<u8> = (0..40u8).collect();
    let datagram = udp(ip(A), ip(B), 1234, 5678, &payload);
    let first = ethernet(&ipv4(ip(A), ip(B), 17, 77, 0x2000, &datagram[..24]));
    let second = ethernet(&ipv4(ip(A), ip(B), 17, 77, 0x0003, &datagram[24..]));
    write_pcap(&path, &[first, second]);

    let stats = rewrite_file(&path, false);
    assert_eq!(stats.packets_modified, 2);

    let cap = pcap_rw::capture::load(&path).unwrap();
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    for pkt in cap.packets() {
        let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
        assert_eq!(view.src, ip(C));
        chunks.push(pkt.data[view.offset + view.ihl..view.offset + view.total_len].to_vec());
    }
    let mut merged = Vec::new();
    for c in chunks {
        merged.extend_from_slice(&c);
    }
    assert_eq!(merged.len(), datagram.len());
    assert_eq!(tcp_udp_checksum(&ip(C), &ip(D), 17, &merged), 0);
}

#[test]
fn payload_growth_shifts_following_seq() {
    let path = tmp_path("grow.pcap");
    let body = b"GET / HTTP/1.1\r\nHost: 192.168.50.7\r\n\r\n".to_vec();
    let frames = vec![
        ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 1000, 1, 0x18, &body))),
        ethernet(&ipv4(ip(A), ip(B), 6, 2, 0, &tcp(ip(A), ip(B), 40000, 80, 1000 + body.len() as u32, 1, 0x18, b"OK"))),
    ];
    write_pcap(&path, &frames);

    let stats = rewrite_file(&path, true);
    assert_eq!(stats.payload_hits, 1);
    assert_eq!(stats.bytes_delta, (D.len() - B.len()) as i64);
    assert!(stats.seq_fixed >= 1);

    let cap = pcap_rw::capture::load(&path).unwrap();
    let second = cap.packets().nth(1).unwrap();
    let view = parse_ipv4(&second.data, second.linktype).unwrap();
    let l4 = view.offset + view.ihl;
    let seq = u32::from_be_bytes([
        second.data[l4 + 4],
        second.data[l4 + 5],
        second.data[l4 + 6],
        second.data[l4 + 7],
    ]);
    assert_eq!(seq, 1000 + body.len() as u32 + (D.len() - B.len()) as u32);

    let first = cap.packets().next().unwrap();
    let view = parse_ipv4(&first.data, first.linktype).unwrap();
    let text = String::from_utf8_lossy(&first.data[view.offset + view.ihl + 20..view.offset + view.total_len]);
    assert!(text.contains(D), "payload should carry the new address: {text}");
    assert!(!text.contains(B));
}

#[test]
fn payload_shrink_produces_negative_delta() {
    let path = tmp_path("shrink.pcap");
    let body = b"Host: 192.168.50.7\r\n\r\n".to_vec();
    let frames = vec![
        ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 1000, 1, 0x18, &body))),
        ethernet(&ipv4(ip(A), ip(B), 6, 2, 0, &tcp(ip(A), ip(B), 40000, 80, 1000 + body.len() as u32, 1, 0x18, b"OK"))),
    ];
    write_pcap(&path, &frames);

    let mapping = Mapping::from_text(&[
        (A.to_string(), "8.8.8.8".to_string()),
        (B.to_string(), "1.1.1.1".to_string()),
    ])
    .unwrap();
    let mut cap = pcap_rw::capture::load(&path).unwrap();
    let stats = Rewriter::new(mapping, true).process(&mut cap, None, None);
    // Only the payload occurrence shrinks: 192.168.50.7 -> 1.1.1.1.
    assert_eq!(stats.bytes_delta, 7 - 12);

    let second = cap.packets().nth(1).unwrap();
    let view = parse_ipv4(&second.data, second.linktype).unwrap();
    let l4 = view.offset + view.ihl;
    let seq = u32::from_be_bytes([
        second.data[l4 + 4],
        second.data[l4 + 5],
        second.data[l4 + 6],
        second.data[l4 + 7],
    ]);
    assert_eq!(seq as i64, 1000 + body.len() as i64 + stats.bytes_delta);
}

#[test]
fn retransmitted_flows_skip_payload_rewrite() {
    let path = tmp_path("retrans.pcap");
    let body = b"GET / HTTP/1.1\r\nHost: 192.168.50.7\r\n\r\n".to_vec();
    let frames = vec![
        ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 100, 1, 0x18, &body))),
        ethernet(&ipv4(ip(A), ip(B), 6, 2, 0, &tcp(ip(A), ip(B), 40000, 80, 100, 1, 0x18, &body))),
        ethernet(&ipv4(ip(A), ip(B), 6, 3, 0, &tcp(ip(A), ip(B), 40000, 80, 100 + body.len() as u32, 1, 0x18, b"NEXT"))),
    ];
    write_pcap(&path, &frames);

    let stats = rewrite_file(&path, true);
    assert_eq!(stats.payload_hits, 0);
    assert!(
        stats.warnings.iter().any(|w| w.contains("重传")),
        "expected a retransmission warning, got {:?}",
        stats.warnings
    );
    assert_eq!(stats.packets_modified, 3);

    let cap = pcap_rw::capture::load(&path).unwrap();
    for pkt in cap.packets() {
        let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
        assert_eq!(view.src, ip(C));
        assert!(checksum(&pkt.data[view.offset..view.offset + view.ihl]) == 0);
    }
}

#[test]
fn does_not_partially_match_longer_addresses() {
    let path = tmp_path("prefix.pcap");
    // Payload mentions 10.1.2.33, which must not become 36.112.209.1543.
    let body = b"peer=10.1.2.33 and host=10.1.2.3\r\n".to_vec();
    let frame = ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 1000, 1, 0x18, &body)));
    write_pcap(&path, &[frame]);

    let stats = rewrite_file(&path, true);
    assert_eq!(stats.payload_hits, 1);
    let cap = pcap_rw::capture::load(&path).unwrap();
    let pkt = cap.packets().next().unwrap();
    let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
    let text = String::from_utf8_lossy(&pkt.data[view.offset + view.ihl + 20..view.offset + view.total_len]).to_string();
    assert!(text.contains("peer=10.1.2.33"), "{text}");
    assert!(text.contains(&format!("host={C}")), "{text}");
}

#[test]
fn big_endian_pcap_roundtrip() {
    let path = tmp_path("be.pcap");
    let frame = ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 1000, 1, 0x18, b"x")));
    let mut data = Vec::new();
    data.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes());
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&4u16.to_be_bytes());
    data.extend_from_slice(&0i32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&65535u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    data.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    data.extend_from_slice(&frame);
    std::fs::write(&path, &data).unwrap();

    let mut cap = pcap_rw::capture::load(&path).unwrap();
    assert_eq!(cap.endian, Endian::Big);
    let stats = Rewriter::new(mapping(), false).process(&mut cap, None, None);
    assert_eq!(stats.packets_modified, 1);
    let out = tmp_path("be_out.pcap");
    save(&cap, &out).unwrap();

    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(&bytes[..4], &[0xa1, 0xb2, 0xc3, 0xd4]);
    let check = pcap_rw::capture::load(&out).unwrap();
    let pkt = check.packets().next().unwrap();
    let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.src, ip(C));
    assert!(checksum(&pkt.data[view.offset..view.offset + view.ihl]) == 0);
}

#[test]
fn pcapng_epb_options_survive() {
    let path = tmp_path("ng.pcapng");
    let frame = ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 1000, 1, 0x18, b"x")));

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let total = 12 + body.len();
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out
    }

    let mut shb_body = Vec::new();
    shb_body.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    shb_body.extend_from_slice(&1u16.to_le_bytes());
    shb_body.extend_from_slice(&0u16.to_le_bytes());
    shb_body.extend_from_slice(&(-1i64).to_le_bytes());
    let mut file = block(0x0A0D0D0A, &shb_body);

    let mut idb_body = Vec::new();
    idb_body.extend_from_slice(&1u16.to_le_bytes());
    idb_body.extend_from_slice(&0u16.to_le_bytes());
    idb_body.extend_from_slice(&65535u32.to_le_bytes());
    file.extend_from_slice(&block(1, &idb_body));

    // EPB with padding and a comment option.
    let mut epb_body = Vec::new();
    epb_body.extend_from_slice(&0u32.to_le_bytes()); // interface
    epb_body.extend_from_slice(&0u32.to_le_bytes()); // ts high
    epb_body.extend_from_slice(&0u32.to_le_bytes()); // ts low
    epb_body.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    epb_body.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    epb_body.extend_from_slice(&frame);
    let pad = (4 - frame.len() % 4) % 4;
    epb_body.extend(std::iter::repeat_n(0u8, pad));
    epb_body.extend_from_slice(&1u16.to_le_bytes()); // opt_comment
    epb_body.extend_from_slice(&4u16.to_le_bytes());
    epb_body.extend_from_slice(b"test");
    epb_body.extend_from_slice(&0u16.to_le_bytes());
    epb_body.extend_from_slice(&0u16.to_le_bytes());
    file.extend_from_slice(&block(6, &epb_body));
    std::fs::write(&path, &file).unwrap();

    let mut cap = pcap_rw::capture::load(&path).unwrap();
    assert_eq!(cap.kind, Kind::Pcapng);
    let options_before = match &cap.items[2] {
        Item::Packet(p) => p.options.clone(),
        _ => panic!("third block should be a packet"),
    };
    assert!(!options_before.is_empty());

    let stats = Rewriter::new(mapping(), false).process(&mut cap, None, None);
    assert_eq!(stats.packets_modified, 1);
    let out = tmp_path("ng_out.pcapng");
    save(&cap, &out).unwrap();

    let check = pcap_rw::capture::load(&out).unwrap();
    let options_after = match &check.items[2] {
        Item::Packet(p) => p.options.clone(),
        _ => panic!("third block should be a packet"),
    };
    assert_eq!(options_before, options_after, "EPB options must be preserved");
    let pkt = check.packets().next().unwrap();
    let view = parse_ipv4(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.src, ip(C));
    assert!(checksum(&pkt.data[view.offset..view.offset + view.ihl]) == 0);
}

#[test]
fn truncated_capture_disables_payload_mode() {
    let path = tmp_path("trunc.pcap");
    let body = b"Host: 192.168.50.7\r\n\r\n".to_vec();
    let frame = ethernet(&ipv4(ip(A), ip(B), 6, 1, 0, &tcp(ip(A), ip(B), 40000, 80, 1000, 1, 0x18, &body)));
    write_pcap(&path, &[frame]);

    let mut cap = pcap_rw::capture::load(&path).unwrap();
    if let Some(pkt) = cap.packets_mut().next() {
        pkt.orig_len = pkt.data.len() + 40;
    }
    let stats = Rewriter::new(mapping(), true).process(&mut cap, None, None);
    assert_eq!(stats.payload_hits, 0);
    assert!(stats.warnings.iter().any(|w| w.contains("截断")));
    assert_eq!(stats.packets_modified, 1);
}

#[test]
fn mapping_rejects_invalid_and_ignores_identical() {
    assert!(Mapping::from_text(&[("1.2.3.4".to_string(), "1.2.3".to_string())]).is_err());
    assert!(Mapping::from_text(&[("1.2.3.4".to_string(), "1.2.3.4".to_string())]).is_err());
    let m = Mapping::from_text(&[("1.2.3.4".to_string(), "5.6.7.8".to_string())]).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(
        m.lookup(&Ip::V4(ip("1.2.3.4"))),
        Some(Ip::V4(ip("5.6.7.8")))
    );
    assert_eq!(m.lookup(&Ip::V4(ip("9.9.9.9"))), None);
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

const V6A: &str = "2001:db8::1";
const V6B: &str = "2001:db8::2";
const V6C: &str = "2001:db8:ffff::1";
const V6D: &str = "2001:db8:ffff::2";

fn mapping6() -> Mapping {
    Mapping::from_text(&[
        (V6A.to_string(), V6C.to_string()),
        (V6B.to_string(), V6D.to_string()),
    ])
    .unwrap()
}

fn rewrite_file_with(
    path: &std::path::Path,
    mapping: Mapping,
    replace_payload: bool,
) -> pcap_rw::RewriteStats {
    let mut cap = pcap_rw::capture::load(path).unwrap();
    let stats = Rewriter::new(mapping, replace_payload).process(&mut cap, None, None);
    save(&cap, path).unwrap();
    stats
}

#[test]
fn rewrites_ipv6_tcp_and_fixes_checksums() {
    let path = tmp_path("v6_tcp.pcap");
    let body = b"hello";
    let frame = ethernet6(&ipv6(
        ip6(V6A),
        ip6(V6B),
        6,
        &tcp6(ip6(V6A), ip6(V6B), 40000, 80, 1000, 1, 0x18, body),
    ));
    write_pcap(&path, &[frame]);

    let stats = rewrite_file_with(&path, mapping6(), false);
    assert_eq!(stats.ipv6_packets, 1);
    assert_eq!(stats.ipv4_packets, 0);
    assert_eq!(stats.packets_modified, 1);
    assert_eq!(stats.src_hits, 1);
    assert_eq!(stats.dst_hits, 1);
    assert_eq!(stats.l4_checksums, 1);

    let cap = pcap_rw::capture::load(&path).unwrap();
    let pkt = cap.packets().next().unwrap();
    let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.src, ip6(V6C));
    assert_eq!(view.dst, ip6(V6D));
    // Payload length field must be untouched when only addresses change.
    assert_eq!(view.payload_len, 20 + body.len());
    let seg = &pkt.data[view.l4_offset..view.offset + view.total_len()];
    assert_eq!(tcp_udp_checksum(&view.src, &view.dst, 6, seg), 0);
    assert_eq!(u16::from_be_bytes([seg[0], seg[1]]), 40000);

    let result = verify(&cap, &[V6A.to_string(), V6B.to_string()], false);
    assert!(result.ok(), "{}", result.summary());
    assert_eq!(result.ipv6_packets, 1);
}

#[test]
fn rewrites_ipv6_udp_behind_hop_by_hop() {
    let path = tmp_path("v6_ext.pcap");
    // Hop-by-hop header: next = UDP, length 0 (8 bytes total).
    let mut ext = vec![0u8; 8];
    ext[0] = 17;
    ext[1] = 0;
    let segment = udp6(ip6(V6A), ip6(V6B), 5353, 53, b"dns-query");
    let mut body = ext;
    body.extend_from_slice(&segment);
    let frame = ethernet6(&ipv6(ip6(V6A), ip6(V6B), 0, &body));
    write_pcap(&path, &[frame]);

    let stats = rewrite_file_with(&path, mapping6(), false);
    assert_eq!(stats.packets_modified, 1);
    assert_eq!(stats.l4_checksums, 1);

    let cap = pcap_rw::capture::load(&path).unwrap();
    let pkt = cap.packets().next().unwrap();
    let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.next_header, 17);
    assert_eq!(view.header_len, 48);
    assert_eq!(view.src, ip6(V6C));
    let seg = &pkt.data[view.l4_offset..view.offset + view.total_len()];
    assert_eq!(tcp_udp_checksum(&view.src, &view.dst, 17, seg), 0);
}

#[test]
fn rewrites_ipv6_fragment_first_piece() {
    let path = tmp_path("v6_frag.pcap");
    let seg = udp6(ip6(V6A), ip6(V6B), 5000, 6000, &[7u8; 16]);
    assert_eq!(seg.len(), 24);
    let first = ipv6_frag(ip6(V6A), ip6(V6B), 0x0A0B_0C0D, 0, true, 17, &seg[..16]);
    let second = ipv6_frag(ip6(V6A), ip6(V6B), 0x0A0B_0C0D, 16, false, 17, &seg[16..]);
    write_pcap(&path, &[ethernet6(&first), ethernet6(&second)]);

    let stats = rewrite_file_with(&path, mapping6(), false);
    assert_eq!(stats.packets_modified, 2);
    assert_eq!(stats.l4_checksums, 1, "only the first fragment carries L4");
    assert_eq!(stats.l4_skipped, 1);

    let cap = pcap_rw::capture::load(&path).unwrap();
    let pkt = cap.packets().next().unwrap();
    let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.src, ip6(V6C));
    assert_eq!(view.dst, ip6(V6D));
    let written = u16::from_be_bytes([pkt.data[view.l4_offset + 6], pkt.data[view.l4_offset + 7]]);

    let mut expected_seg = seg.clone();
    expected_seg[6..8].copy_from_slice(&[0, 0]);
    let expected = tcp_udp_checksum(&ip6(V6C), &ip6(V6D), 17, &expected_seg);
    assert_eq!(written, expected);
}

#[test]
fn rewrites_ipv6_fragments_carrying_destination_options() {
    let path = tmp_path("v6_frag_dstopts.pcap");
    const ID: u32 = 0x51A2_3B4C;

    // 16-byte Destination Options header inside the fragmentable part, i.e.
    // behind the fragment header.
    let mut dstopts = vec![0u8; 16];
    dstopts[0] = 17; // next header: UDP
    dstopts[1] = 1; // length: (1 + 1) * 8 = 16 bytes

    // The first two payload bytes are 60 / 0xff on purpose: the second fragment
    // then starts with what looks like a 2048-byte extension header, which must
    // not be parsed as one.
    let mut datagram = vec![0x11u8; 32];
    datagram[0] = 60;
    datagram[1] = 0xFF;
    let seg = udp6(ip6(V6A), ip6(V6B), 5000, 6000, &datagram);
    assert_eq!(seg.len(), 40);

    let mut body = dstopts.clone();
    body.extend_from_slice(&seg);
    assert_eq!(body.len(), 56);

    let frames = [
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 0, true, 60, &body[..24])),
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 24, true, 60, &body[24..48])),
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 48, false, 60, &body[48..])),
    ];
    write_pcap(&path, &frames);

    // Chosen so the pseudo-header delta is *not* one's-complement neutral
    // (0xffff), otherwise the checksum would stay identical by coincidence and
    // the assertion below would prove nothing.
    const NA: &str = "2001:db8:1234::9";
    const NB: &str = "2001:db9:5678::a";
    let mapping = Mapping::from_text(&[
        (V6A.to_string(), NA.to_string()),
        (V6B.to_string(), NB.to_string()),
    ])
    .unwrap();

    let stats = rewrite_file_with(&path, mapping, false);
    assert_eq!(stats.packets_modified, 3, "every fragment keeps its address rewrite");
    assert_eq!(stats.l4_checksums, 1, "only the first fragment holds the header");
    assert_eq!(stats.l4_skipped, 2);

    let cap = pcap_rw::capture::load(&path).unwrap();
    for pkt in cap.packets() {
        let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
        assert_eq!(view.src, ip6(NA));
        assert_eq!(view.dst, ip6(NB));
    }

    let pkt = cap.packets().next().unwrap();
    let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.l4_offset - view.frag_data_offset, 16);
    let written = u16::from_be_bytes([pkt.data[view.l4_offset + 6], pkt.data[view.l4_offset + 7]]);

    let original = u16::from_be_bytes([seg[6], seg[7]]);
    let mut expected_seg = seg.clone();
    expected_seg[6..8].copy_from_slice(&[0, 0]);
    let expected = tcp_udp_checksum(&ip6(NA), &ip6(NB), 17, &expected_seg);
    assert_ne!(expected, original, "mapping must change the checksum");
    assert_eq!(written, expected);
}

#[test]
fn recovers_checksum_when_first_fragment_is_missing() {
    let path = tmp_path("v6_frag_headless.pcap");
    const ID: u32 = 0x7E57_0001;

    // Destination options (16 bytes) behind the fragment header, then UDP.
    let mut dstopts = vec![0u8; 16];
    dstopts[0] = 17;
    dstopts[1] = 1;
    let seg = udp6(ip6(V6A), ip6(V6B), 5000, 6000, &[0x5Au8; 24]);
    assert_eq!(seg.len(), 32);
    let mut body = dstopts;
    body.extend_from_slice(&seg);
    assert_eq!(body.len(), 48);

    // The first fragment ends exactly where the UDP header begins, so dropping
    // it loses the destination options and nothing else.
    let frames = [
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 0, true, 60, &body[..16])),
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 16, true, 60, &body[16..40])),
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 40, false, 60, &body[40..])),
    ];
    write_pcap(&path, &frames[1..]);

    const NA: &str = "2001:db8:1234::9";
    const NB: &str = "2001:db9:5678::a";
    let mapping = Mapping::from_text(&[
        (V6A.to_string(), NA.to_string()),
        (V6B.to_string(), NB.to_string()),
    ])
    .unwrap();

    let stats = rewrite_file_with(&path, mapping, false);
    assert_eq!(stats.packets_modified, 2);
    assert_eq!(stats.l4_recovered, 1, "header position inferred from the checksum");
    assert_eq!(stats.l4_checksums, 1);

    let cap = pcap_rw::capture::load(&path).unwrap();
    let pkt = cap
        .packets()
        .find(|p| parse_ipv6(&p.data, p.linktype).unwrap().frag_offset == 16)
        .expect("fragment at offset 16");
    let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
    // The recovered header starts the fragment's data, so the checksum field is
    // six bytes in.
    let written =
        u16::from_be_bytes([pkt.data[view.frag_data_offset + 6], pkt.data[view.frag_data_offset + 7]]);

    let mut expected_seg = seg.clone();
    expected_seg[6..8].copy_from_slice(&[0, 0]);
    let expected = tcp_udp_checksum(&ip6(NA), &ip6(NB), 17, &expected_seg);
    assert_ne!(written, u16::from_be_bytes([seg[6], seg[7]]), "checksum must change");
    assert_eq!(written, expected);
}

#[test]
fn recovers_checksum_when_first_fragment_ends_inside_extension_header() {
    let path = tmp_path("v6_frag_headless_shift.pcap");
    const ID: u32 = 0x7E57_0002;

    let mut dstopts = vec![0u8; 16];
    dstopts[0] = 17;
    dstopts[1] = 1;
    let seg = udp6(ip6(V6A), ip6(V6B), 5000, 6000, &[0x33u8; 16]);
    assert_eq!(seg.len(), 24);
    let mut body = dstopts;
    body.extend_from_slice(&seg);
    assert_eq!(body.len(), 40);

    // The first fragment stops in the middle of the destination options, so the
    // surviving data starts eight bytes before the UDP header.
    let frames = [
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 0, true, 60, &body[..8])),
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 8, true, 60, &body[8..32])),
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 32, false, 60, &body[32..])),
    ];
    write_pcap(&path, &frames[1..]);

    const NA: &str = "2001:db8:1234::9";
    const NB: &str = "2001:db9:5678::a";
    let mapping = Mapping::from_text(&[
        (V6A.to_string(), NA.to_string()),
        (V6B.to_string(), NB.to_string()),
    ])
    .unwrap();

    let stats = rewrite_file_with(&path, mapping, false);
    assert_eq!(stats.packets_modified, 2);
    assert_eq!(stats.l4_recovered, 1);

    let cap = pcap_rw::capture::load(&path).unwrap();
    let pkt = cap
        .packets()
        .find(|p| parse_ipv6(&p.data, p.linktype).unwrap().frag_offset == 8)
        .expect("fragment at offset 8");
    let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
    let base = view.frag_data_offset + 8 + 6;
    let written = u16::from_be_bytes([pkt.data[base], pkt.data[base + 1]]);

    let mut expected_seg = seg.clone();
    expected_seg[6..8].copy_from_slice(&[0, 0]);
    let expected = tcp_udp_checksum(&ip6(NA), &ip6(NB), 17, &expected_seg);
    assert_eq!(written, expected);
}

#[test]
fn missing_first_fragment_without_extension_headers_is_reported() {
    let path = tmp_path("v6_frag_headless_lost.pcap");
    const ID: u32 = 0x7E57_0003;

    // No extension header: the transport header starts at offset zero of the
    // fragmentable part, so losing the first fragment loses the header itself.
    let seg = udp6(ip6(V6A), ip6(V6B), 5000, 6000, &[0xAAu8; 16]);
    assert_eq!(seg.len(), 24);
    let frames = [
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 0, true, 17, &seg[..8])),
        ethernet6(&ipv6_frag(ip6(V6A), ip6(V6B), ID, 8, false, 17, &seg[8..])),
    ];
    write_pcap(&path, &frames[1..]);

    let stats = rewrite_file_with(&path, mapping6(), false);
    assert_eq!(stats.l4_recovered, 0);
    assert_eq!(stats.l4_skipped, 1);
    assert!(
        stats.warnings.iter().any(|w| w.contains("缺少首个分片")),
        "should explain why the checksum was left alone: {:?}",
        stats.warnings
    );

    // The address rewrite must happen regardless.
    let cap = pcap_rw::capture::load(&path).unwrap();
    let pkt = cap.packets().next().unwrap();
    let view = parse_ipv6(&pkt.data, pkt.linktype).unwrap();
    assert_eq!(view.src, ip6(V6C));
    assert_eq!(view.dst, ip6(V6D));
}

#[test]
fn ipv6_payload_text_replacement_shifts_seq() {
    let path = tmp_path("v6_payload.pcap");
    let body = format!("GET / HTTP/1.1\r\nHost: {V6A}\r\n\r\n");
    let body = body.as_bytes();
    let frame1 = ethernet6(&ipv6(
        ip6(V6A),
        ip6(V6B),
        6,
        &tcp6(ip6(V6A), ip6(V6B), 40000, 80, 1000, 1, 0x18, body),
    ));
    let next_seq = 1000 + body.len() as u32;
    let frame2 = ethernet6(&ipv6(
        ip6(V6A),
        ip6(V6B),
        6,
        &tcp6(ip6(V6A), ip6(V6B), 40000, 80, next_seq, 1, 0x18, b"next"),
    ));
    write_pcap(&path, &[frame1, frame2]);

    let stats = rewrite_file_with(&path, mapping6(), true);
    assert_eq!(stats.payload_hits, 1);
    assert_eq!(stats.bytes_delta, 5, "2001:db8::1 -> 2001:db8:ffff::1");

    let cap = pcap_rw::capture::load(&path).unwrap();
    let first = cap.packets().next().unwrap();
    let view = parse_ipv6(&first.data, first.linktype).unwrap();
    assert_eq!(view.payload_len, 20 + body.len() + 5);
    let seg = &first.data[view.l4_offset..view.offset + view.total_len()];
    assert_eq!(tcp_udp_checksum(&view.src, &view.dst, 6, seg), 0);
    assert!(seg.windows(16).any(|w| w == V6C.as_bytes()));

    // The following segment keeps its place in the byte stream.
    let second = cap.packets().nth(1).unwrap();
    let view2 = parse_ipv6(&second.data, second.linktype).unwrap();
    let l4 = view2.l4_offset;
    let seq = u32::from_be_bytes([
        second.data[l4 + 4],
        second.data[l4 + 5],
        second.data[l4 + 6],
        second.data[l4 + 7],
    ]);
    assert_eq!(seq, next_seq + 5);
}

#[test]
fn mapping_rejects_cross_family() {
    let err = Mapping::from_text(&[("10.0.0.1".to_string(), "2001:db8::1".to_string())])
        .unwrap_err();
    assert!(err.contains("地址族"), "{err}");
    let err = Mapping::from_text(&[("2001:db8::1".to_string(), "10.0.0.1".to_string())])
        .unwrap_err();
    assert!(err.contains("地址族"), "{err}");
    // Same-family IPv6 pairs are accepted.
    let m = Mapping::from_text(&[(V6A.to_string(), V6C.to_string())]).unwrap();
    assert_eq!(m.len(), 1);
}

#[test]
fn mixed_v4_v6_capture_rewrites_both() {
    let path = tmp_path("mixed.pcap");
    let v4 = ethernet(&ipv4(
        ip(A),
        ip(B),
        17,
        0,
        0,
        &udp(ip(A), ip(B), 1111, 2222, b"v4"),
    ));
    let v6 = ethernet6(&ipv6(
        ip6(V6A),
        ip6(V6B),
        17,
        &udp6(ip6(V6A), ip6(V6B), 3333, 4444, b"v6"),
    ));
    write_pcap(&path, &[v4, v6]);

    let mapping = Mapping::from_text(&[
        (A.to_string(), C.to_string()),
        (B.to_string(), D.to_string()),
        (V6A.to_string(), V6C.to_string()),
        (V6B.to_string(), V6D.to_string()),
    ])
    .unwrap();
    let stats = rewrite_file_with(&path, mapping, false);
    assert_eq!(stats.ipv4_packets, 1);
    assert_eq!(stats.ipv6_packets, 1);
    assert_eq!(stats.packets_modified, 2);
    assert_eq!(stats.ip_headers, 1, "only the IPv4 header has a checksum");

    let cap = pcap_rw::capture::load(&path).unwrap();
    let mut pkts = cap.packets();
    let p4 = pkts.next().unwrap();
    let v4view = parse_ipv4(&p4.data, p4.linktype).unwrap();
    assert_eq!(v4view.src, ip(C));
    assert_eq!(checksum(&p4.data[v4view.offset..v4view.offset + v4view.ihl]), 0);

    let p6 = pkts.next().unwrap();
    let v6view = parse_ipv6(&p6.data, p6.linktype).unwrap();
    assert_eq!(v6view.src, ip6(V6C));
    let seg = &p6.data[v6view.l4_offset..v6view.offset + v6view.total_len()];
    assert_eq!(tcp_udp_checksum(&v6view.src, &v6view.dst, 17, seg), 0);
}
