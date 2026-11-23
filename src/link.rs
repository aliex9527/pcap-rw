//! Locate and parse IPv4 / IPv6 headers inside common link-layer encapsulations.

pub const VLAN_TYPES: [u16; 5] = [0x8100, 0x88A8, 0x9100, 0x9200, 0x9300];
pub const ETYPE_IPV4: u16 = 0x0800;
pub const ETYPE_IPV6: u16 = 0x86DD;

pub const LT_NULL: u32 = 0;
pub const LT_ETHERNET: u32 = 1;
pub const LT_RAW_BSD: u32 = 12;
pub const LT_RAW: u32 = 101;
pub const LT_LINUX_SLL: u32 = 113;
pub const LT_IPV4: u32 = 228;
pub const LT_LINUX_SLL2: u32 = 276;

/// IPv6 extension header numbers.
const NH_HOPOPT: u8 = 0;
const NH_ROUTING: u8 = 43;
const NH_FRAGMENT: u8 = 44;
const NH_AH: u8 = 51;
const NH_NONE: u8 = 59;
const NH_DSTOPTS: u8 = 60;

pub fn is_raw(linktype: u32) -> bool {
    matches!(linktype, LT_RAW_BSD | LT_RAW | LT_IPV4 | 14 | 15)
}

/// An address in wire byte order, either IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Ip {
    pub fn is_v4(&self) -> bool {
        matches!(self, Ip::V4(_))
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Ip::V4(b) => b.as_slice(),
            Ip::V6(b) => b.as_slice(),
        }
    }

    pub fn text(&self) -> String {
        match self {
            Ip::V4(b) => ip_str(b),
            Ip::V6(b) => ipv6_str(b),
        }
    }

    pub fn family_name(&self) -> &'static str {
        if self.is_v4() { "IPv4" } else { "IPv6" }
    }
}

impl std::fmt::Display for Ip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

impl Default for Ip {
    fn default() -> Self {
        Ip::V4([0, 0, 0, 0])
    }
}

/// Byte offset of the network-layer header plus its IP version.
fn l3_offset(data: &[u8], linktype: u32) -> Option<(usize, u8)> {
    let n = data.len();
    match linktype {
        LT_ETHERNET => {
            if n < 14 {
                return None;
            }
            let mut etype = u16::from_be_bytes([data[12], data[13]]);
            let mut pos = 14usize;
            while VLAN_TYPES.contains(&etype) {
                if n < pos + 4 {
                    return None;
                }
                etype = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                pos += 4;
            }
            match etype {
                ETYPE_IPV4 => (n >= pos + 20).then_some((pos, 4)),
                ETYPE_IPV6 => (n >= pos + 40).then_some((pos, 6)),
                _ => None,
            }
        }
        t if is_raw(t) => {
            if n < 20 {
                return None;
            }
            match data[0] >> 4 {
                4 => Some((0, 4)),
                6 if n >= 40 => Some((0, 6)),
                _ => None,
            }
        }
        LT_LINUX_SLL => {
            if n < 16 {
                return None;
            }
            match u16::from_be_bytes([data[14], data[15]]) {
                ETYPE_IPV4 => (n >= 36).then_some((16, 4)),
                ETYPE_IPV6 => (n >= 56).then_some((16, 6)),
                _ => None,
            }
        }
        LT_LINUX_SLL2 => {
            if n < 20 {
                return None;
            }
            match u16::from_be_bytes([data[0], data[1]]) {
                ETYPE_IPV4 => (n >= 40).then_some((20, 4)),
                ETYPE_IPV6 => (n >= 60).then_some((20, 6)),
                _ => None,
            }
        }
        LT_NULL => {
            if n < 24 {
                return None;
            }
            match data[4] >> 4 {
                4 => Some((4, 4)),
                6 => Some((4, 6)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Byte offset of the IPv4 header, or `None` when the frame is not IPv4.
pub fn ipv4_offset(data: &[u8], linktype: u32) -> Option<usize> {
    match l3_offset(data, linktype)? {
        (off, 4) => Some(off),
        _ => None,
    }
}

/// Ethernet frame carrying at least one VLAN tag (802.1Q / QinQ).
pub fn has_vlan(data: &[u8], linktype: u32) -> bool {
    if linktype != LT_ETHERNET || data.len() < 14 {
        return false;
    }
    VLAN_TYPES.contains(&u16::from_be_bytes([data[12], data[13]]))
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4View {
    pub offset: usize,
    pub ihl: usize,
    pub total_len: usize,
    pub protocol: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub frag: u16,
    pub ident: u16,
}

impl Ipv4View {
    /// Header end offset inside the frame.
    pub fn l4_offset(&self) -> usize {
        self.offset + self.ihl
    }

    /// True when this datagram is a fragment (MF set or nonzero offset).
    pub fn fragmented(&self) -> bool {
        (self.frag & 0x3FFF) != 0
    }

    pub fn frag_offset(&self) -> usize {
        ((self.frag & 0x1FFF) as usize) * 8
    }

    pub fn more_fragments(&self) -> bool {
        (self.frag & 0x2000) != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6View {
    pub offset: usize,
    /// Value of the 16-bit payload length field (extension headers included).
    pub payload_len: usize,
    /// Upper-layer protocol once the extension header chain has been walked.
    pub next_header: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    /// Offset of the upper-layer header (after the extension header chain).
    pub l4_offset: usize,
    pub header_len: usize,
    /// Start of the fragmentable data: the byte after the Fragment header.
    /// For fragments whose offset is nonzero this equals `l4_offset`, because
    /// no upper-layer header is present; for packets without a Fragment header
    /// it is simply `l4_offset`.
    pub frag_data_offset: usize,
    pub frag_offset: usize,
    pub more_fragments: bool,
    pub has_fragment_header: bool,
    pub ident: u32,
}

impl Ipv6View {
    pub fn total_len(&self) -> usize {
        40 + self.payload_len
    }

    /// Atomic fragments (offset 0, MF clear) are not treated as fragmentation.
    pub fn fragmented(&self) -> bool {
        self.has_fragment_header && (self.frag_offset != 0 || self.more_fragments)
    }
}

/// Version-agnostic view of a network-layer header.
#[derive(Debug, Clone, Copy)]
pub enum IpView {
    V4(Ipv4View),
    V6(Ipv6View),
}

impl IpView {
    pub fn version(&self) -> u8 {
        match self {
            IpView::V4(_) => 4,
            IpView::V6(_) => 6,
        }
    }

    pub fn offset(&self) -> usize {
        match self {
            IpView::V4(v) => v.offset,
            IpView::V6(v) => v.offset,
        }
    }

    pub fn total_len(&self) -> usize {
        match self {
            IpView::V4(v) => v.total_len,
            IpView::V6(v) => v.total_len(),
        }
    }

    pub fn l4_offset(&self) -> usize {
        match self {
            IpView::V4(v) => v.l4_offset(),
            IpView::V6(v) => v.l4_offset,
        }
    }

    pub fn header_len(&self) -> usize {
        self.l4_offset() - self.offset()
    }

    pub fn l4_proto(&self) -> u8 {
        match self {
            IpView::V4(v) => v.protocol,
            IpView::V6(v) => v.next_header,
        }
    }

    pub fn src(&self) -> Ip {
        match self {
            IpView::V4(v) => Ip::V4(v.src),
            IpView::V6(v) => Ip::V6(v.src),
        }
    }

    pub fn dst(&self) -> Ip {
        match self {
            IpView::V4(v) => Ip::V4(v.dst),
            IpView::V6(v) => Ip::V6(v.dst),
        }
    }

    pub fn fragmented(&self) -> bool {
        match self {
            IpView::V4(v) => v.fragmented(),
            IpView::V6(v) => v.fragmented(),
        }
    }

    pub fn frag_offset(&self) -> usize {
        match self {
            IpView::V4(v) => v.frag_offset(),
            IpView::V6(v) => v.frag_offset,
        }
    }

    pub fn more_fragments(&self) -> bool {
        match self {
            IpView::V4(v) => v.more_fragments(),
            IpView::V6(v) => v.more_fragments,
        }
    }

    pub fn frag_ident(&self) -> u32 {
        match self {
            IpView::V4(v) => v.ident as u32,
            IpView::V6(v) => v.ident,
        }
    }

    /// First byte of the fragmentable payload, i.e. the reassembly origin.
    pub fn frag_data_offset(&self) -> usize {
        match self {
            IpView::V4(v) => v.l4_offset(),
            IpView::V6(v) => v.frag_data_offset,
        }
    }

    /// Distance from the reassembly origin to the transport header. Almost
    /// always zero; nonzero when the first fragment carries extension headers
    /// after its Fragment header (e.g. destination options for the final
    /// destination), which belong to the fragmentable part.
    pub fn frag_l4_shift(&self) -> usize {
        self.l4_offset().saturating_sub(self.frag_data_offset())
    }

    /// Whether the upper-layer header is physically present in this packet.
    /// Later fragments of a fragmented datagram carry only fragment data.
    pub fn l4_present(&self) -> bool {
        match self {
            IpView::V4(v) => !v.fragmented() || v.frag_offset() == 0,
            IpView::V6(v) => !(v.has_fragment_header && v.frag_offset != 0),
        }
    }
}

pub fn parse_ipv4(data: &[u8], linktype: u32) -> Option<Ipv4View> {
    let (off, version) = l3_offset(data, linktype)?;
    if version != 4 {
        return None;
    }
    parse_ipv4_at(data, off)
}

fn parse_ipv4_at(data: &[u8], off: usize) -> Option<Ipv4View> {
    if data.len() < off + 20 {
        return None;
    }
    if (data[off] >> 4) != 4 {
        return None;
    }
    let ihl = ((data[off] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < off + ihl {
        return None;
    }
    Some(Ipv4View {
        offset: off,
        ihl,
        total_len: u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize,
        protocol: data[off + 9],
        src: [data[off + 12], data[off + 13], data[off + 14], data[off + 15]],
        dst: [data[off + 16], data[off + 17], data[off + 18], data[off + 19]],
        frag: u16::from_be_bytes([data[off + 6], data[off + 7]]),
        ident: u16::from_be_bytes([data[off + 4], data[off + 5]]),
    })
}

pub fn parse_ipv6(data: &[u8], linktype: u32) -> Option<Ipv6View> {
    let (off, version) = l3_offset(data, linktype)?;
    if version != 6 {
        return None;
    }
    parse_ipv6_at(data, off)
}

fn parse_ipv6_at(data: &[u8], off: usize) -> Option<Ipv6View> {
    if data.len() < off + 40 || (data[off] >> 4) != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[off + 4], data[off + 5]]) as usize;
    let mut next = data[off + 6];
    let src: [u8; 16] = data[off + 8..off + 24].try_into().ok()?;
    let dst: [u8; 16] = data[off + 24..off + 40].try_into().ok()?;

    let mut pos = off + 40;
    let mut frag_offset = 0usize;
    let mut more_fragments = false;
    let mut has_fragment_header = false;
    let mut ident = 0u32;
    let mut frag_data_offset = 0usize;

    // Bound the walk so a malformed chain cannot loop forever.
    for _ in 0..16 {
        let step = match next {
            NH_HOPOPT | NH_ROUTING | NH_DSTOPTS => {
                if pos + 2 > data.len() {
                    return None;
                }
                (data[pos + 1] as usize + 1) * 8
            }
            NH_AH => {
                if pos + 2 > data.len() {
                    return None;
                }
                (data[pos + 1] as usize + 2) * 4
            }
            NH_FRAGMENT => 8,
            _ => break,
        };
        if pos + step > data.len() {
            return None;
        }
        let following = data[pos];
        if next == NH_FRAGMENT {
            let field = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            frag_offset = ((field >> 3) as usize) * 8;
            more_fragments = (field & 1) != 0;
            has_fragment_header = true;
            ident = u32::from_be_bytes([
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            frag_data_offset = pos + 8;
            // In a non-first fragment the octets after the Fragment header are
            // fragment data, not headers. Walking further would read the
            // payload as if it were an extension header, so stop here. The
            // header chain of the original datagram is only present in the
            // first fragment.
            if frag_offset != 0 {
                return Some(Ipv6View {
                    offset: off,
                    payload_len,
                    next_header: following,
                    src,
                    dst,
                    l4_offset: frag_data_offset,
                    header_len: frag_data_offset - off,
                    frag_data_offset,
                    frag_offset,
                    more_fragments,
                    has_fragment_header,
                    ident,
                });
            }
        }
        next = following;
        pos += step;
    }

    if next == NH_NONE {
        // No upper-layer header at all.
        return Some(Ipv6View {
            offset: off,
            payload_len,
            next_header: NH_NONE,
            src,
            dst,
            l4_offset: pos,
            header_len: pos - off,
            frag_data_offset: if has_fragment_header {
                frag_data_offset
            } else {
                pos
            },
            frag_offset,
            more_fragments,
            has_fragment_header,
            ident,
        });
    }

    Some(Ipv6View {
        offset: off,
        payload_len,
        next_header: next,
        src,
        dst,
        l4_offset: pos,
        header_len: pos - off,
        frag_data_offset: if has_fragment_header {
            frag_data_offset
        } else {
            pos
        },
        frag_offset,
        more_fragments,
        has_fragment_header,
        ident,
    })
}

/// Parse either an IPv4 or an IPv6 header, whichever the frame carries.
pub fn parse_ip_header(data: &[u8], linktype: u32) -> Option<IpView> {
    match l3_offset(data, linktype)? {
        (off, 4) => parse_ipv4_at(data, off).map(IpView::V4),
        (off, 6) => parse_ipv6_at(data, off).map(IpView::V6),
        _ => None,
    }
}

pub fn ip_str(raw: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3])
}

/// RFC 5952 text form: lowercase hex, no leading zeros, longest zero run squeezed.
pub fn ipv6_str(raw: &[u8; 16]) -> String {
    let mut groups = [0u16; 8];
    for (i, g) in groups.iter_mut().enumerate() {
        *g = u16::from_be_bytes([raw[i * 2], raw[i * 2 + 1]]);
    }

    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut i = 0usize;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            if i - start > best_len {
                best_start = start;
                best_len = i - start;
            }
        } else {
            i += 1;
        }
    }
    if best_len < 2 {
        best_start = 0;
        best_len = 0;
    }

    let mut out = String::with_capacity(39);
    let mut idx = 0usize;
    while idx < 8 {
        if best_len > 0 && idx == best_start {
            out.push_str("::");
            idx += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[idx]));
        idx += 1;
    }
    if out.is_empty() {
        out.push_str("::");
    }
    out
}

/// Strict dotted-quad parser: 4 parts, no leading zeros, 0-255 each.
pub fn parse_ip(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        let value: u32 = part.parse().ok()?;
        if value > 255 {
            return None;
        }
        out[i] = value as u8;
    }
    Some(out)
}

fn parse_ipv6_groups(text: &str, out: &mut Vec<u16>) -> Option<()> {
    if text.is_empty() {
        return Some(());
    }
    let parts: Vec<&str> = text.split(':').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return None;
        }
        if part.contains('.') {
            // Embedded dotted quad, only valid as the final component.
            if i != parts.len() - 1 {
                return None;
            }
            let v4 = parse_ip(part)?;
            out.push(u16::from_be_bytes([v4[0], v4[1]]));
            out.push(u16::from_be_bytes([v4[2], v4[3]]));
            continue;
        }
        if part.len() > 4 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u16::from_str_radix(part, 16).ok()?);
    }
    Some(())
}

fn groups_to_bytes(groups: &[u16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, g) in groups.iter().take(8).enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&g.to_be_bytes());
    }
    out
}

/// Parse IPv6 text, accepting `::` compression and a trailing dotted quad.
pub fn parse_ipv6_text(text: &str) -> Option<[u8; 16]> {
    let text = text.trim();
    if text.is_empty() || text.contains('%') {
        return None;
    }
    match text.find("::") {
        Some(pos) => {
            if text[pos + 2..].contains("::") {
                return None;
            }
            let mut head = Vec::new();
            let mut tail = Vec::new();
            parse_ipv6_groups(&text[..pos], &mut head)?;
            parse_ipv6_groups(&text[pos + 2..], &mut tail)?;
            if head.len() + tail.len() > 7 {
                return None;
            }
            let mut groups = head;
            groups.resize(8 - tail.len(), 0);
            groups.extend_from_slice(&tail);
            Some(groups_to_bytes(&groups))
        }
        None => {
            let mut groups = Vec::new();
            parse_ipv6_groups(text, &mut groups)?;
            if groups.len() != 8 {
                return None;
            }
            Some(groups_to_bytes(&groups))
        }
    }
}

/// Parse either address family from text.
pub fn parse_ip_any(text: &str) -> Option<Ip> {
    let text = text.trim();
    if text.contains(':') {
        parse_ipv6_text(text).map(Ip::V6)
    } else {
        parse_ip(text).map(Ip::V4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_ethernet() {
        let mut frame = vec![0u8; 14 + 20];
        frame[12] = 0x08;
        frame[13] = 0x00;
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&20u16.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let v = parse_ipv4(&frame, LT_ETHERNET).unwrap();
        assert_eq!(v.offset, 14);
        assert_eq!(v.ihl, 20);
        assert_eq!(ip_str(&v.src), "10.0.0.1");
        assert_eq!(ip_str(&v.dst), "10.0.0.2");
    }

    #[test]
    fn parses_double_tagged_vlan() {
        let mut frame = vec![0u8; 14 + 8 + 20];
        frame[12] = 0x88;
        frame[13] = 0xa8;
        frame[16] = 0x81;
        frame[17] = 0x00;
        frame[20] = 0x08;
        frame[21] = 0x00;
        frame[14 + 8] = 0x45;
        let v = parse_ipv4(&frame, LT_ETHERNET).unwrap();
        assert_eq!(v.offset, 22);
        assert!(has_vlan(&frame, LT_ETHERNET));
    }

    #[test]
    fn strict_ip_parsing() {
        assert_eq!(parse_ip("1.2.3.4"), Some([1, 2, 3, 4]));
        assert_eq!(parse_ip(" 255.255.255.255 "), Some([255, 255, 255, 255]));
        assert_eq!(parse_ip("1.2.3"), None);
        assert_eq!(parse_ip("1.2.3.256"), None);
        assert_eq!(parse_ip("1.2.3.04"), None);
        assert_eq!(parse_ip("a.b.c.d"), None);
    }

    #[test]
    fn ipv6_text_round_trip() {
        let cases = [
            ("::", "::"),
            ("::1", "::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("fe80::a:b:c:d", "fe80::a:b:c:d"),
            ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ];
        for (input, expected) in cases {
            let raw = parse_ipv6_text(input).unwrap_or_else(|| panic!("cannot parse {input}"));
            assert_eq!(ipv6_str(&raw), expected, "input {input}");
        }
        // Embedded IPv4 form.
        let mapped = parse_ipv6_text("::ffff:192.168.1.1").unwrap();
        assert_eq!(&mapped[10..12], &[0xff, 0xff]);
        assert_eq!(&mapped[12..16], &[192, 168, 1, 1]);
        assert!(parse_ipv6_text("1::2::3").is_none());
        assert!(parse_ipv6_text("1:2:3").is_none());
        assert!(parse_ipv6_text("gggg::1").is_none());
    }

    #[test]
    fn parses_ipv6_ethernet_frame() {
        let mut frame = vec![0u8; 14 + 40 + 8];
        frame[12] = 0x86;
        frame[13] = 0xdd;
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&8u16.to_be_bytes());
        ip[6] = 17;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&parse_ipv6_text("2001:db8::1").unwrap());
        ip[24..40].copy_from_slice(&parse_ipv6_text("2001:db8::2").unwrap());
        ip[40..42].copy_from_slice(&1234u16.to_be_bytes());
        ip[42..44].copy_from_slice(&53u16.to_be_bytes());

        let view = parse_ip_header(&frame, LT_ETHERNET).unwrap();
        assert_eq!(view.version(), 6);
        assert_eq!(view.offset(), 14);
        assert_eq!(view.header_len(), 40);
        assert_eq!(view.l4_offset(), 54);
        assert_eq!(view.l4_proto(), 17);
        assert_eq!(view.total_len(), 48);
        assert_eq!(view.src().text(), "2001:db8::1");
        assert!(!view.fragmented());
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        // Hop-by-hop (8 bytes) then destination options (16 bytes), then TCP.
        let mut frame = vec![0u8; 14 + 40 + 8 + 16 + 20];
        frame[12] = 0x86;
        frame[13] = 0xdd;
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(44u16).to_be_bytes());
        ip[6] = NH_HOPOPT;
        ip[8..24].copy_from_slice(&parse_ipv6_text("2001:db8::a").unwrap());
        ip[24..40].copy_from_slice(&parse_ipv6_text("2001:db8::b").unwrap());
        // hop-by-hop: next = destination options, len = 0 (8 bytes)
        ip[40] = NH_DSTOPTS;
        ip[41] = 0;
        // destination options: next = TCP, len = 1 (16 bytes)
        ip[48] = 6;
        ip[49] = 1;

        let view = parse_ipv6(&frame, LT_ETHERNET).unwrap();
        assert_eq!(view.next_header, 6);
        assert_eq!(view.l4_offset, 14 + 40 + 8 + 16);
        assert_eq!(view.header_len, 64);
    }

    #[test]
    fn reads_ipv6_fragment_header() {
        let mut frame = vec![0u8; 14 + 40 + 8 + 8];
        frame[12] = 0x86;
        frame[13] = 0xdd;
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&16u16.to_be_bytes());
        ip[6] = NH_FRAGMENT;
        // fragment header: next = UDP, offset = 100 (x8), M = 1, ident = 0x11223344
        ip[40] = 17;
        let field: u16 = (100 << 3) | 1;
        ip[42..44].copy_from_slice(&field.to_be_bytes());
        ip[44..48].copy_from_slice(&0x11223344u32.to_be_bytes());

        let view = parse_ipv6(&frame, LT_ETHERNET).unwrap();
        assert_eq!(view.next_header, 17);
        assert!(view.fragmented());
        assert_eq!(view.frag_offset, 800);
        assert_eq!(view.frag_data_offset, 14 + 40 + 8);
        assert!(view.more_fragments);
        assert_eq!(view.ident, 0x11223344);
    }

    #[test]
    fn sees_destination_options_behind_fragment_header() {
        // IPv6 -> Fragment -> Destination Options -> UDP, as a first fragment.
        let mut frame = vec![0u8; 14 + 40 + 8 + 16 + 8];
        frame[12] = 0x86;
        frame[13] = 0xdd;
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&32u16.to_be_bytes());
        ip[6] = NH_FRAGMENT;
        ip[8..24].copy_from_slice(&parse_ipv6_text("2001:db8::a").unwrap());
        ip[24..40].copy_from_slice(&parse_ipv6_text("2001:db8::b").unwrap());
        // Fragment header: next = destination options, offset 0, M = 1.
        ip[40] = NH_DSTOPTS;
        ip[42..44].copy_from_slice(&1u16.to_be_bytes());
        ip[44..48].copy_from_slice(&0xAABB_CCDDu32.to_be_bytes());
        // Destination options: next = UDP, length 1 (16 bytes).
        ip[48] = 17;
        ip[49] = 1;

        let view = parse_ipv6(&frame, LT_ETHERNET).unwrap();
        assert_eq!(view.next_header, 17);
        assert_eq!(view.frag_data_offset, 14 + 40 + 8);
        assert_eq!(view.l4_offset, 14 + 40 + 8 + 16);
        assert_eq!(view.frag_offset, 0);
        assert!(view.more_fragments);

        let any = parse_ip_header(&frame, LT_ETHERNET).unwrap();
        assert_eq!(any.frag_l4_shift(), 16);
        assert!(any.l4_present());
    }

    #[test]
    fn later_fragment_does_not_parse_fragment_data_as_headers() {
        // A later fragment whose data happens to look like a destination options
        // header claiming 2048 bytes. Walking it would make the whole packet
        // unparseable, so the address would never be rewritten.
        let mut frame = vec![0u8; 14 + 40 + 8 + 24];
        frame[12] = 0x86;
        frame[13] = 0xdd;
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&32u16.to_be_bytes());
        ip[6] = NH_FRAGMENT;
        ip[40] = NH_DSTOPTS;
        let field: u16 = 3 << 3; // offset 24 bytes, M = 0
        ip[42..44].copy_from_slice(&field.to_be_bytes());
        ip[48] = NH_DSTOPTS;
        ip[49] = 0xFF;

        let view = parse_ipv6(&frame, LT_ETHERNET).unwrap();
        assert_eq!(view.frag_offset, 24);
        assert_eq!(view.l4_offset, view.frag_data_offset);
        let any = parse_ip_header(&frame, LT_ETHERNET).unwrap();
        assert_eq!(any.frag_l4_shift(), 0);
        assert!(!any.l4_present());
    }

    #[test]
    fn parse_ip_any_keeps_family() {
        assert!(parse_ip_any("10.0.0.1").unwrap().is_v4());
        assert!(!parse_ip_any("2001:db8::1").unwrap().is_v4());
        assert_eq!(parse_ip_any("2001:db8::1").unwrap().text(), "2001:db8::1");
    }
}
