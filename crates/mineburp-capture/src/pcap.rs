//! Classic pcap and pcapng, read and write.
//!
//! The reader serves two very different inputs — dumpcap's live stream and an
//! operator-supplied capture file — so it treats both the same way: as
//! untrusted. Every length is checked against a ceiling before anything is
//! allocated, and a malformed block ends the read with an error instead of a
//! panic or a gigabyte allocation.

use std::io::{self, Read, Write};

/// The largest single record or block the reader will allocate for.
pub const MAX_RECORD: usize = 32 * 1024 * 1024;

/// More interfaces than this in one pcapng section is not a real capture.
const MAX_INTERFACES: usize = 1_024;

/// One captured frame, with its timestamp normalised to microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRecord {
    pub linktype: u32,
    pub timestamp_micros: i64,
    pub data: Vec<u8>,
    /// The record's pcapng comment (`opt_comment`), if it has one. `MineBurp`'s
    /// own exports describe each packet there, which is how an import of one
    /// recovers the states and framing the export wrote.
    pub comment: Option<String>,
    /// The record came from an interface `MineBurp`'s own pcapng export
    /// declared ([`EXPORT_INTERFACE`]): its streams hold decrypted,
    /// uncompressed frames, one packet per commented record.
    pub mineburp_export: bool,
}

/// The interface name `MineBurp`'s pcapng export writes its streams on.
pub const EXPORT_INTERFACE: &str = "mineburp-decrypted";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        let bytes: [u8; 2] = bytes[..2].try_into().expect("two bytes");
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let bytes: [u8; 4] = bytes[..4].try_into().expect("four bytes");
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    fn u64(self, bytes: &[u8]) -> u64 {
        let bytes: [u8; 8] = bytes[..8].try_into().expect("eight bytes");
        match self {
            Self::Little => u64::from_le_bytes(bytes),
            Self::Big => u64::from_be_bytes(bytes),
        }
    }
}

/// How a pcapng interface's timestamps are scaled.
#[derive(Debug, Clone, Copy)]
struct Interface {
    linktype: u32,
    /// Units per second are `10^n` (`decimal`) or `2^n`.
    resolution: u8,
    decimal: bool,
    offset_seconds: i64,
    /// Named [`EXPORT_INTERFACE`].
    mineburp_export: bool,
}

impl Interface {
    fn micros(&self, units: u64) -> i64 {
        let units = i128::from(units);
        let micros = if self.decimal {
            let exponent = u32::from(self.resolution.min(18));
            units * 1_000_000 / 10_i128.pow(exponent)
        } else {
            let shift = u32::from(self.resolution.min(63));
            (units * 1_000_000) >> shift
        };
        let total = micros + i128::from(self.offset_seconds) * 1_000_000;
        i64::try_from(total).unwrap_or(i64::MAX)
    }
}

#[derive(Debug)]
enum Format {
    Pcap {
        endian: Endian,
        nanoseconds: bool,
        linktype: u32,
    },
    Pcapng {
        endian: Endian,
        interfaces: Vec<Interface>,
    },
}

/// Reads frames from a classic pcap or pcapng stream, detected from its magic.
#[derive(Debug)]
pub struct CaptureReader<R> {
    input: R,
    format: Format,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

const PCAPNG_SECTION: u32 = 0x0a0d_0d0a;
const PCAPNG_BYTE_ORDER: u32 = 0x1a2b_3c4d;

impl<R: Read> CaptureReader<R> {
    /// Reads the file header and decides which format follows.
    pub fn new(mut input: R) -> io::Result<Self> {
        let mut magic = [0_u8; 4];
        input.read_exact(&mut magic)?;
        let format = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => pcap_header(&mut input, Endian::Little, false)?,
            [0x4d, 0x3c, 0xb2, 0xa1] => pcap_header(&mut input, Endian::Little, true)?,
            [0xa1, 0xb2, 0xc3, 0xd4] => pcap_header(&mut input, Endian::Big, false)?,
            [0xa1, 0xb2, 0x3c, 0x4d] => pcap_header(&mut input, Endian::Big, true)?,
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                let endian = read_section_header(&mut input)?;
                Format::Pcapng {
                    endian,
                    interfaces: Vec::new(),
                }
            }
            _ => return Err(invalid("not a pcap or pcapng capture")),
        };
        Ok(Self { input, format })
    }

    /// The next captured frame, or `None` at a clean end of stream.
    pub fn next_record(&mut self) -> io::Result<Option<CaptureRecord>> {
        match &mut self.format {
            Format::Pcap {
                endian,
                nanoseconds,
                linktype,
            } => read_pcap_record(&mut self.input, *endian, *nanoseconds, *linktype),
            Format::Pcapng { .. } => self.next_pcapng_record(),
        }
    }

    fn next_pcapng_record(&mut self) -> io::Result<Option<CaptureRecord>> {
        loop {
            let mut head = [0_u8; 8];
            if !read_exact_or_eof(&mut self.input, &mut head)? {
                return Ok(None);
            }
            let Format::Pcapng { endian, interfaces } = &mut self.format else {
                unreachable!("pcapng reader");
            };
            // A new section may switch byte order; its length can only be read
            // after its byte-order magic, which follows the length.
            if u32::from_le_bytes(head[..4].try_into().expect("four bytes")) == PCAPNG_SECTION {
                let mut rest = [0_u8; 4];
                self.input.read_exact(&mut rest)?;
                let (next_endian, length) = section_order(&head[4..8], &rest)?;
                // Type, length and byte-order magic are consumed; the rest of
                // the body and the trailer remain.
                skip(&mut self.input, checked_body_length(length, 28)? + 16)?;
                *endian = next_endian;
                interfaces.clear();
                continue;
            }
            let block_type = endian.u32(&head[..4]);
            let length = endian.u32(&head[4..8]);
            let body_length = checked_body_length(length, 12)?;
            let mut body = vec![0_u8; body_length];
            self.input.read_exact(&mut body)?;
            let mut trailer = [0_u8; 4];
            self.input.read_exact(&mut trailer)?;
            if endian.u32(&trailer) != length {
                return Err(invalid("pcapng block length trailer does not match"));
            }
            match block_type {
                // Interface description.
                1 => {
                    if interfaces.len() >= MAX_INTERFACES {
                        return Err(invalid("pcapng section declares too many interfaces"));
                    }
                    interfaces.push(parse_interface(*endian, &body)?);
                }
                // Enhanced packet: a 32-bit interface id.
                6 => {
                    let index = body.get(0..4).map(|bytes| endian.u32(bytes) as usize);
                    return timed_packet(*endian, interfaces, &body, index).map(Some);
                }
                // Simple packet: no timestamp, always interface 0.
                3 => {
                    if body.len() < 4 {
                        return Err(invalid("pcapng simple packet block is truncated"));
                    }
                    let original = endian.u32(&body[0..4]) as usize;
                    let available = body.len() - 4;
                    let data = &body[4..4 + original.min(available)];
                    let interface = *interfaces
                        .first()
                        .ok_or_else(|| invalid("pcapng packet precedes any interface"))?;
                    return Ok(Some(CaptureRecord {
                        linktype: interface.linktype,
                        timestamp_micros: 0,
                        data: data.to_vec(),
                        comment: None,
                        mineburp_export: interface.mineburp_export,
                    }));
                }
                // Obsolete packet block, still written by old tools: a 16-bit
                // interface id, otherwise laid out like an enhanced packet.
                2 => {
                    let index = body.get(0..2).map(|bytes| endian.u16(bytes) as usize);
                    return timed_packet(*endian, interfaces, &body, index).map(Some);
                }
                // Name resolution, statistics, custom, decryption secrets…
                _ => {}
            }
        }
    }
}

/// Reads an enhanced or obsolete packet block: interface, 64-bit
/// timestamp, captured length, data, then options.
fn timed_packet(
    endian: Endian,
    interfaces: &[Interface],
    body: &[u8],
    index: Option<usize>,
) -> io::Result<CaptureRecord> {
    if body.len() < 20 {
        return Err(invalid("pcapng packet block is truncated"));
    }
    let index = index.ok_or_else(|| invalid("pcapng packet block is truncated"))?;
    let units = (u64::from(endian.u32(&body[4..8])) << 32) | u64::from(endian.u32(&body[8..12]));
    let captured = endian.u32(&body[12..16]) as usize;
    let data = body
        .get(20..20_usize.saturating_add(captured))
        .ok_or_else(|| invalid("pcapng packet data overruns its block"))?;
    let interface = interfaces
        .get(index)
        .ok_or_else(|| invalid("pcapng packet names an unknown interface"))?;
    let options = body
        .get(20 + captured.div_ceil(4) * 4..)
        .unwrap_or_default();
    Ok(CaptureRecord {
        linktype: interface.linktype,
        timestamp_micros: interface.micros(units),
        data: data.to_vec(),
        comment: packet_comment(endian, options),
        mineburp_export: interface.mineburp_export,
    })
}

fn pcap_header(input: &mut impl Read, endian: Endian, nanoseconds: bool) -> io::Result<Format> {
    let mut rest = [0_u8; 20];
    input.read_exact(&mut rest)?;
    // The link type's low 16 bits; the upper bits carry an FCS flag.
    let linktype = endian.u32(&rest[16..20]) & 0x0fff_ffff;
    Ok(Format::Pcap {
        endian,
        nanoseconds,
        linktype,
    })
}

fn read_pcap_record(
    input: &mut impl Read,
    endian: Endian,
    nanoseconds: bool,
    linktype: u32,
) -> io::Result<Option<CaptureRecord>> {
    let mut header = [0_u8; 16];
    if !read_exact_or_eof(input, &mut header)? {
        return Ok(None);
    }
    let seconds = i64::from(endian.u32(&header[0..4]));
    let fraction = i64::from(endian.u32(&header[4..8]));
    let captured = endian.u32(&header[8..12]) as usize;
    if captured > MAX_RECORD {
        return Err(invalid("capture record exceeds the size limit"));
    }
    let mut data = vec![0_u8; captured];
    input.read_exact(&mut data)?;
    let fraction = if nanoseconds {
        fraction / 1_000
    } else {
        fraction
    };
    Ok(Some(CaptureRecord {
        linktype,
        timestamp_micros: seconds.saturating_mul(1_000_000).saturating_add(fraction),
        data,
        comment: None,
        mineburp_export: false,
    }))
}

/// Reads the section header that follows an already-consumed block type.
fn read_section_header(input: &mut impl Read) -> io::Result<Endian> {
    let mut head = [0_u8; 8];
    input.read_exact(&mut head)?;
    let (endian, length) = section_order(&head[..4], &head[4..8])?;
    // Type, length and byte-order magic are consumed; the rest of the body
    // (at least version and section length) and the trailer remain.
    skip(input, checked_body_length(length, 28)? + 16)?;
    Ok(endian)
}

fn section_order(length: &[u8], magic: &[u8]) -> io::Result<(Endian, u32)> {
    let endian = if u32::from_le_bytes(magic[..4].try_into().expect("four bytes"))
        == PCAPNG_BYTE_ORDER
    {
        Endian::Little
    } else if u32::from_be_bytes(magic[..4].try_into().expect("four bytes")) == PCAPNG_BYTE_ORDER {
        Endian::Big
    } else {
        return Err(invalid("pcapng section has no byte-order magic"));
    };
    Ok((endian, endian.u32(length)))
}

/// The body length of a block of total length `length` with `overhead` bytes
/// of framing, after checking it is sane.
fn checked_body_length(length: u32, overhead: usize) -> io::Result<usize> {
    let length = length as usize;
    if length < overhead || !length.is_multiple_of(4) || length > MAX_RECORD {
        return Err(invalid("pcapng block has an invalid length"));
    }
    Ok(length - overhead)
}

fn parse_interface(endian: Endian, body: &[u8]) -> io::Result<Interface> {
    if body.len() < 8 {
        return Err(invalid("pcapng interface block is truncated"));
    }
    let mut interface = Interface {
        linktype: u32::from(endian.u16(&body[0..2])),
        resolution: 6,
        decimal: true,
        offset_seconds: 0,
        mineburp_export: false,
    };
    let mut options = &body[8..];
    while options.len() >= 4 {
        let code = endian.u16(&options[0..2]);
        let length = usize::from(endian.u16(&options[2..4]));
        let padded = length.div_ceil(4) * 4;
        let Some(value) = options.get(4..4 + length) else {
            break;
        };
        match code {
            0 => break,
            2 => interface.mineburp_export = value == EXPORT_INTERFACE.as_bytes(),
            9 if length >= 1 => {
                interface.decimal = value[0] & 0x80 == 0;
                interface.resolution = value[0] & 0x7f;
            }
            14 if length >= 8 => {
                interface.offset_seconds = i64::try_from(endian.u64(value)).unwrap_or(0);
            }
            _ => {}
        }
        options = options.get(4 + padded..).unwrap_or_default();
    }
    Ok(interface)
}

/// The first `opt_comment` among a packet block's options, if it is UTF-8.
fn packet_comment(endian: Endian, mut options: &[u8]) -> Option<String> {
    while options.len() >= 4 {
        let code = endian.u16(&options[0..2]);
        let length = usize::from(endian.u16(&options[2..4]));
        let value = options.get(4..4 + length)?;
        match code {
            0 => return None,
            1 => return std::str::from_utf8(value).ok().map(str::to_owned),
            _ => {}
        }
        options = options
            .get(4 + length.div_ceil(4) * 4..)
            .unwrap_or_default();
    }
    None
}

fn skip(input: &mut impl Read, count: usize) -> io::Result<()> {
    let copied = io::copy(&mut input.take(count as u64), &mut io::sink())?;
    if copied == count as u64 {
        Ok(())
    } else {
        Err(io::ErrorKind::UnexpectedEof.into())
    }
}

/// `read_exact`, except that a stream ending cleanly *before the first byte*
/// is reported as `false` rather than as an error.
fn read_exact_or_eof(input: &mut impl Read, buffer: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// Writes a little-endian pcapng stream with microsecond timestamps.
#[derive(Debug)]
pub struct PcapngWriter<W: Write> {
    output: W,
    interfaces: u32,
}

impl<W: Write> PcapngWriter<W> {
    /// Starts a section; `application` is recorded as `shb_userappl`.
    pub fn new(mut output: W, application: &str) -> io::Result<Self> {
        let mut body = Vec::new();
        body.extend_from_slice(&PCAPNG_BYTE_ORDER.to_le_bytes());
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        // Section length unknown.
        body.extend_from_slice(&u64::MAX.to_le_bytes());
        push_option(&mut body, 4, application.as_bytes());
        push_option(&mut body, 0, &[]);
        write_block(&mut output, PCAPNG_SECTION, &body)?;
        Ok(Self {
            output,
            interfaces: 0,
        })
    }

    /// Declares an interface and returns its id for [`write_packet`](Self::write_packet).
    pub fn add_interface(&mut self, linktype: u16, name: &str) -> io::Result<u32> {
        let mut body = Vec::new();
        body.extend_from_slice(&linktype.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        push_option(&mut body, 2, name.as_bytes());
        // if_tsresol: 10^-6.
        push_option(&mut body, 9, &[6]);
        push_option(&mut body, 0, &[]);
        write_block(&mut self.output, 1, &body)?;
        let id = self.interfaces;
        self.interfaces += 1;
        Ok(id)
    }

    /// Writes one frame as an enhanced packet block, with an optional comment.
    pub fn write_packet(
        &mut self,
        interface: u32,
        timestamp_micros: i64,
        data: &[u8],
        comment: Option<&str>,
    ) -> io::Result<()> {
        let length = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet is too large"))?;
        let units = u64::try_from(timestamp_micros).unwrap_or(0);
        let mut body = Vec::with_capacity(data.len() + 64);
        body.extend_from_slice(&interface.to_le_bytes());
        body.extend_from_slice(&u32::try_from(units >> 32).unwrap_or(0).to_le_bytes());
        body.extend_from_slice(
            &u32::try_from(units & 0xffff_ffff)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        body.extend_from_slice(&length.to_le_bytes());
        body.extend_from_slice(&length.to_le_bytes());
        body.extend_from_slice(data);
        pad(&mut body);
        if let Some(comment) = comment {
            push_option(&mut body, 1, comment.as_bytes());
            push_option(&mut body, 0, &[]);
        }
        write_block(&mut self.output, 6, &body)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }

    pub fn into_inner(self) -> W {
        self.output
    }
}

fn push_option(body: &mut Vec<u8>, code: u16, value: &[u8]) {
    // Option values are at most 65535 bytes; longer comments are cut.
    let value = &value[..value.len().min(usize::from(u16::MAX) - 3)];
    body.extend_from_slice(&code.to_le_bytes());
    body.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_le_bytes());
    body.extend_from_slice(value);
    pad(body);
}

fn pad(body: &mut Vec<u8>) {
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
}

fn write_block(output: &mut impl Write, block_type: u32, body: &[u8]) -> io::Result<()> {
    let length = u32::try_from(body.len() + 12)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block is too large"))?;
    output.write_all(&block_type.to_le_bytes())?;
    output.write_all(&length.to_le_bytes())?;
    output.write_all(body)?;
    output.write_all(&length.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcapng_round_trips_packets_timestamps_and_link_types() {
        let mut writer = PcapngWriter::new(Vec::new(), "test").expect("writer");
        let raw = writer.add_interface(101, "raw").expect("interface");
        let ether = writer.add_interface(1, "eth").expect("interface");
        writer
            .write_packet(raw, 1_700_000_000_123_456, b"abcde", Some("note"))
            .expect("packet");
        writer.write_packet(ether, 42, b"xy", None).expect("packet");
        let bytes = writer.into_inner();

        let mut reader = CaptureReader::new(bytes.as_slice()).expect("reader");
        let first = reader.next_record().expect("read").expect("record");
        assert_eq!(first.linktype, 101);
        assert_eq!(first.timestamp_micros, 1_700_000_000_123_456);
        assert_eq!(first.data, b"abcde");
        assert_eq!(first.comment.as_deref(), Some("note"));
        let second = reader.next_record().expect("read").expect("record");
        assert_eq!(second.linktype, 1);
        assert_eq!(second.data, b"xy");
        assert_eq!(second.comment, None);
        assert!(reader.next_record().expect("read").is_none());
    }

    #[test]
    fn reads_classic_pcap_in_both_resolutions() {
        for (magic, fraction, expected) in [
            ([0xd4, 0xc3, 0xb2, 0xa1], 250_u32, 3_000_250_i64),
            ([0x4d, 0x3c, 0xb2, 0xa1], 250_000, 3_000_250),
        ] {
            let mut file = magic.to_vec();
            file.extend_from_slice(&[2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            file.extend_from_slice(&65_535_u32.to_le_bytes());
            file.extend_from_slice(&113_u32.to_le_bytes());
            file.extend_from_slice(&3_u32.to_le_bytes());
            file.extend_from_slice(&fraction.to_le_bytes());
            file.extend_from_slice(&2_u32.to_le_bytes());
            file.extend_from_slice(&2_u32.to_le_bytes());
            file.extend_from_slice(b"hi");
            let mut reader = CaptureReader::new(file.as_slice()).expect("reader");
            let record = reader.next_record().expect("read").expect("record");
            assert_eq!(record.linktype, 113);
            assert_eq!(record.timestamp_micros, expected);
            assert_eq!(record.data, b"hi");
        }
    }

    #[test]
    fn honours_interface_timestamp_resolution() {
        let interface = Interface {
            linktype: 1,
            resolution: 9,
            decimal: true,
            offset_seconds: 0,
            mineburp_export: false,
        };
        assert_eq!(interface.micros(1_500_000_000), 1_500_000);
        let binary = Interface {
            resolution: 10,
            decimal: false,
            ..interface
        };
        assert_eq!(binary.micros(1_024), 1_000_000);
    }

    #[test]
    fn rejects_hostile_lengths_without_allocating() {
        let mut writer = PcapngWriter::new(Vec::new(), "t").expect("writer");
        writer.add_interface(1, "eth").expect("interface");
        let mut bytes = writer.into_inner();
        // An enhanced packet claiming to be 4 GiB.
        bytes.extend_from_slice(&6_u32.to_le_bytes());
        bytes.extend_from_slice(&0xffff_fff0_u32.to_le_bytes());
        let mut reader = CaptureReader::new(bytes.as_slice()).expect("reader");
        assert!(reader.next_record().is_err());

        // A classic record claiming 1 GiB.
        let mut file = vec![0xd4, 0xc3, 0xb2, 0xa1];
        file.extend_from_slice(&[0; 16]);
        file.extend_from_slice(&1_u32.to_le_bytes());
        file.extend_from_slice(&[0; 8]);
        file.extend_from_slice(&(1_u32 << 30).to_le_bytes());
        file.extend_from_slice(&[0; 4]);
        let mut reader = CaptureReader::new(file.as_slice()).expect("reader");
        assert!(reader.next_record().is_err());
    }

    #[test]
    fn never_panics_on_truncated_or_corrupt_input() {
        let mut writer = PcapngWriter::new(Vec::new(), "fuzz").expect("writer");
        let interface = writer.add_interface(1, "eth").expect("interface");
        for index in 0..4_u8 {
            writer
                .write_packet(interface, i64::from(index), &[index; 37], Some("c"))
                .expect("packet");
        }
        let bytes = writer.into_inner();
        for cut in 0..bytes.len() {
            if let Ok(mut reader) = CaptureReader::new(&bytes[..cut]) {
                while let Ok(Some(_)) = reader.next_record() {}
            }
        }
        for flip in 0..bytes.len() {
            let mut corrupt = bytes.clone();
            corrupt[flip] ^= 0xa5;
            if let Ok(mut reader) = CaptureReader::new(corrupt.as_slice()) {
                for _ in 0..16 {
                    if !matches!(reader.next_record(), Ok(Some(_))) {
                        break;
                    }
                }
            }
        }
    }
}
