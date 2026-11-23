//! Internet checksum helpers (RFC 1071).

/// Folded 16-bit one's complement sum of `data`.
pub fn ones_complement_sum(data: &[u8]) -> u32 {
    let mut total: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        total += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        total += (*last as u32) << 8;
    }
    while total >> 16 != 0 {
        total = (total & 0xFFFF) + (total >> 16);
    }
    total
}

/// RFC 1071 checksum. Returns 0 for an all-zero buffer of even length.
pub fn checksum(data: &[u8]) -> u16 {
    !(ones_complement_sum(data) as u16)
}

/// Checksum over the IP pseudo header plus the TCP/UDP segment.
///
/// The address slices decide the pseudo header layout: 4 bytes each selects the
/// IPv4 form (RFC 793), 16 bytes each selects the IPv6 form (RFC 8200 §8.1).
pub fn tcp_udp_checksum(src: &[u8], dst: &[u8], protocol: u8, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + segment.len());
    if src.len() == 16 {
        buf.extend_from_slice(src);
        buf.extend_from_slice(dst);
        buf.extend_from_slice(&(segment.len() as u32).to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, protocol]);
    } else {
        buf.extend_from_slice(src);
        buf.extend_from_slice(dst);
        buf.push(0);
        buf.push(protocol);
        buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    }
    buf.extend_from_slice(segment);
    checksum(&buf)
}

/// Same as [`tcp_udp_checksum`] but the 16-bit field at `field_off` is treated as zero.
pub fn segment_checksum(
    src: &[u8],
    dst: &[u8],
    protocol: u8,
    segment: &[u8],
    field_off: usize,
) -> u16 {
    let mut copy = segment.to_vec();
    if copy.len() >= field_off + 2 {
        copy[field_off] = 0;
        copy[field_off + 1] = 0;
    }
    tcp_udp_checksum(src, dst, protocol, &copy)
}

pub fn is_valid_ip_checksum(header: &[u8]) -> bool {
    checksum(header) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_zero_sum() {
        assert_eq!(ones_complement_sum(&[]), 0);
        assert_eq!(checksum(&[]), 0xFFFF);
    }

    #[test]
    fn odd_length_pads_with_zero() {
        assert_eq!(ones_complement_sum(&[0x12]), 0x1200);
        assert_eq!(ones_complement_sum(&[0x12, 0x34, 0x56]), 0x1234 + 0x5600);
    }

    #[test]
    fn ip_header_checksum_validates() {
        // A real IPv4 header with a correct checksum.
        let mut hdr = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let value = checksum(&hdr);
        hdr[10..12].copy_from_slice(&value.to_be_bytes());
        assert!(is_valid_ip_checksum(&hdr));
        hdr[12] ^= 0xFF;
        assert!(!is_valid_ip_checksum(&hdr));
    }

    #[test]
    fn ipv6_pseudo_header_round_trips() {
        let src = crate::link::parse_ipv6_text("2001:db8::1").unwrap();
        let dst = crate::link::parse_ipv6_text("2001:db8:ffff::2").unwrap();
        let mut seg = vec![0u8; 8];
        seg[0..2].copy_from_slice(&1234u16.to_be_bytes());
        seg[2..4].copy_from_slice(&53u16.to_be_bytes());
        seg[4..6].copy_from_slice(&8u16.to_be_bytes());

        let value = tcp_udp_checksum(&src, &dst, 17, &seg);
        seg[6..8].copy_from_slice(&value.to_be_bytes());

        let mut buf = Vec::new();
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&(seg.len() as u32).to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 17]);
        buf.extend_from_slice(&seg);
        assert_eq!(checksum(&buf), 0);
    }

    #[test]
    fn ipv4_and_ipv6_pseudo_headers_use_different_layouts() {
        // Same 32-bit address values, but only the 16-byte form is a valid IPv6
        // pseudo header; the checksum must still round-trip through its own layout.
        let src = crate::link::parse_ipv6_text("::a00:1").unwrap();
        let dst = crate::link::parse_ipv6_text("::a00:2").unwrap();
        let mut seg = vec![0u8; 20];
        seg[4..6].copy_from_slice(&20u16.to_be_bytes());
        let value = tcp_udp_checksum(&src, &dst, 6, &seg);
        seg[16..18].copy_from_slice(&value.to_be_bytes());

        let mut buf = Vec::new();
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&(seg.len() as u32).to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 6]);
        buf.extend_from_slice(&seg);
        assert_eq!(checksum(&buf), 0);
    }
}
