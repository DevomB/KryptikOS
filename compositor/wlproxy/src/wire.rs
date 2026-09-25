//! The Wayland wire format, parsed defensively.
//!
//! This module reads bytes that arrive from inside a zone. A zone is assumed
//! compromised - that is the entire premise of the system - so every length in
//! here is attacker-controlled and is treated that way. There is no `unwrap`
//! on input-derived data anywhere in this file, and no arithmetic on a length
//! that has not been bounds-checked first.
//!
//! # The format
//!
//! A message is an 8-byte header followed by arguments, all 32-bit aligned,
//! all in HOST byte order (Wayland is a local-only protocol and does not
//! convert):
//!
//! ```text
//!   word 0:  object id                        u32
//!   word 1:  (size << 16) | opcode            u16 size, u16 opcode
//!   then:    arguments, each padded to 4 bytes
//! ```
//!
//! `size` counts the header, so the minimum legal message is 8 bytes and a
//! message claiming less than that is malformed rather than empty.
//!
//! Argument encodings:
//!
//! | type | encoding |
//! |---|---|
//! | `int`, `uint` | one 32-bit word |
//! | `fixed` | one word, signed 24.8 fixed point |
//! | `object`, `new_id` | one word; 0 means null |
//! | `string` | u32 length INCLUDING the trailing NUL, then bytes, padded to 4. Length 0 is a null string |
//! | `array` | u32 byte count, then bytes, padded to 4 |
//! | `fd` | **nothing in the byte stream** - sent out of band via SCM_RIGHTS |
//!
//! # The trap in that table
//!
//! `fd` occupies no bytes. A proxy that frames messages correctly but does not
//! know how many descriptors each message consumes will desynchronise the
//! descriptor queue from the byte stream, and then hand a client a descriptor
//! belonging to a different message. That is not a crash, it is a
//! confidentiality failure, and it is invisible until it matters. Which
//! messages carry descriptors is therefore not a detail of this module but the
//! reason `protocol.rs` exists.

use std::fmt;

pub const HEADER_LEN: usize = 8;

/// Upper bound on a single message.
///
/// libwayland's connection buffer is 4096 bytes, so no conforming client emits
/// more than that in one message even though the size field could express
/// 65535. Enforcing the real limit rather than the expressible one means a
/// hostile client cannot make the proxy buffer 64KiB per connection by writing
/// a large size field it never intends to fill.
pub const MAX_MESSAGE_LEN: usize = 4096;

/// Object ids at or above this are the server's to allocate; below it are the
/// client's. A client that creates an id in the server's range is either
/// broken or probing, and either way is refused.
pub const SERVER_ID_BASE: u32 = 0xFF00_0000;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WireError {
    /// Fewer bytes than a header.
    Truncated,
    /// `size` field is below the header length, or not 32-bit aligned, or
    /// beyond `MAX_MESSAGE_LEN`.
    BadSize(u16),
    /// An argument ran past the end of the message body.
    ArgOverrun,
    /// A string whose declared length does not end in NUL.
    UnterminatedString,
    /// A string containing bytes that are not valid UTF-8.
    ///
    /// Wayland interface names are ASCII, so this only ever fires on hostile
    /// or corrupt input. It is a distinct error from `UnterminatedString`
    /// because the two say different things about the peer.
    NotUtf8,
    /// An interior NUL inside a string body.
    ///
    /// Refused because `"wl_shm\0_evil"` and `"wl_shm"` compare differently
    /// depending on whether the comparison is length-aware, and a policy
    /// decision that depends on that is a policy decision waiting to be
    /// bypassed.
    InteriorNul,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "message shorter than a header"),
            WireError::BadSize(n) => write!(
                f,
                "illegal message size {n} (must be >= {HEADER_LEN}, 4-byte aligned, \
                 and <= {MAX_MESSAGE_LEN})"
            ),
            WireError::ArgOverrun => write!(f, "argument runs past the end of the message"),
            WireError::UnterminatedString => write!(f, "string is not NUL-terminated"),
            WireError::NotUtf8 => write!(f, "string is not valid UTF-8"),
            WireError::InteriorNul => write!(f, "string contains an interior NUL"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Header {
    pub object: u32,
    pub opcode: u16,
    /// Total message length in bytes, including this header.
    pub size: u16,
}

impl Header {
    /// Parse a header from the first 8 bytes of `buf`.
    ///
    /// Validates `size` here rather than at use, so that no caller can obtain
    /// a `Header` carrying a length it then trusts.
    pub fn parse(buf: &[u8]) -> Result<Header, WireError> {
        if buf.len() < HEADER_LEN {
            return Err(WireError::Truncated);
        }
        let object = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let word1 = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let opcode = (word1 & 0xFFFF) as u16;
        let size = (word1 >> 16) as u16;

        if (size as usize) < HEADER_LEN
            || size % 4 != 0
            || (size as usize) > MAX_MESSAGE_LEN
        {
            return Err(WireError::BadSize(size));
        }
        Ok(Header {
            object,
            opcode,
            size,
        })
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(&self.object.to_ne_bytes());
        let word1 = ((self.size as u32) << 16) | self.opcode as u32;
        out[4..].copy_from_slice(&word1.to_ne_bytes());
        out
    }
}

/// Sequential reader over a message body.
///
/// Every method returns `Result`; none of them panic on malformed input. The
/// reader never advances past `body.len()`.
pub struct ArgReader<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> ArgReader<'a> {
    pub fn new(body: &'a [u8]) -> ArgReader<'a> {
        ArgReader { body, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.body.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        // Checked addition: `n` derives from attacker-controlled lengths and
        // `pos + n` could otherwise wrap on a 32-bit target.
        let end = self.pos.checked_add(n).ok_or(WireError::ArgOverrun)?;
        if end > self.body.len() {
            return Err(WireError::ArgOverrun);
        }
        let s = &self.body[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let w = self.take(4)?;
        Ok(u32::from_ne_bytes([w[0], w[1], w[2], w[3]]))
    }

    /// Read a string. `None` is the protocol's null string (declared length 0).
    pub fn string(&mut self) -> Result<Option<&'a str>, WireError> {
        let declared = self.u32()? as usize;
        if declared == 0 {
            return Ok(None);
        }
        let padded = pad4(declared).ok_or(WireError::ArgOverrun)?;
        let raw = self.take(padded)?;
        let body = &raw[..declared];
        // The declared length includes the NUL, so the last byte must be one.
        match body.last() {
            Some(0) => {}
            _ => return Err(WireError::UnterminatedString),
        }
        let text = &body[..declared - 1];
        if text.contains(&0) {
            return Err(WireError::InteriorNul);
        }
        std::str::from_utf8(text).map(Some).map_err(|_| WireError::NotUtf8)
    }

    pub fn array(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        let padded = pad4(len).ok_or(WireError::ArgOverrun)?;
        let raw = self.take(padded)?;
        Ok(&raw[..len])
    }
}

/// Round `n` up to a multiple of 4, or `None` on overflow.
pub fn pad4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|x| x & !3)
}

/// Builder for a message the proxy emits itself.
///
/// The proxy synthesises `wl_display.error` to reject a client, and could
/// rewrite registry events. Both need encoding, and hand-assembling byte
/// arrays at each call site is how padding bugs happen.
pub struct MessageWriter {
    object: u32,
    opcode: u16,
    body: Vec<u8>,
}

impl MessageWriter {
    pub fn new(object: u32, opcode: u16) -> MessageWriter {
        MessageWriter {
            object,
            opcode,
            body: Vec::new(),
        }
    }

    pub fn u32(mut self, v: u32) -> Self {
        self.body.extend_from_slice(&v.to_ne_bytes());
        self
    }

    #[cfg(test)]
    pub fn i32(self, v: i32) -> Self {
        self.u32(v as u32)
    }

    /// Append a string, with its NUL and its padding.
    pub fn string(mut self, s: &str) -> Self {
        let declared = s.len() + 1;
        self.body.extend_from_slice(&(declared as u32).to_ne_bytes());
        self.body.extend_from_slice(s.as_bytes());
        self.body.push(0);
        while self.body.len() % 4 != 0 {
            self.body.push(0);
        }
        self
    }

    /// Finish the message.
    ///
    /// Returns `None` if the result would exceed `MAX_MESSAGE_LEN` - which can
    /// only happen for an over-long error string, and is better reported than
    /// truncated into a malformed message.
    pub fn finish(self) -> Option<Vec<u8>> {
        let size = HEADER_LEN + self.body.len();
        if size > MAX_MESSAGE_LEN || size > u16::MAX as usize {
            return None;
        }
        let header = Header {
            object: self.object,
            opcode: self.opcode,
            size: size as u16,
        };
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&self.body);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(object: u32, opcode: u16, size: u16) -> [u8; 8] {
        Header {
            object,
            opcode,
            size,
        }
        .encode()
    }

    #[test]
    fn header_roundtrip() {
        let h = Header {
            object: 1,
            opcode: 1,
            size: 12,
        };
        assert_eq!(Header::parse(&h.encode()).unwrap(), h);
    }

    #[test]
    fn header_needs_eight_bytes() {
        assert_eq!(Header::parse(&[0u8; 7]), Err(WireError::Truncated));
        assert_eq!(Header::parse(&[]), Err(WireError::Truncated));
    }

    #[test]
    fn a_size_below_the_header_is_refused() {
        // The message that claims to be shorter than its own header. A proxy
        // that subtracts without checking gets an underflow here, and on a
        // release build with overflow-checks off that becomes a huge length.
        for bad in [0u16, 1, 4, 7] {
            assert_eq!(
                Header::parse(&hdr(1, 0, bad)),
                Err(WireError::BadSize(bad)),
                "size {bad} should be refused"
            );
        }
    }

    #[test]
    fn an_unaligned_size_is_refused() {
        for bad in [9u16, 10, 11, 13] {
            assert_eq!(Header::parse(&hdr(1, 0, bad)), Err(WireError::BadSize(bad)));
        }
    }

    #[test]
    fn an_oversized_message_is_refused() {
        let too_big = (MAX_MESSAGE_LEN + 4) as u16;
        assert_eq!(
            Header::parse(&hdr(1, 0, too_big)),
            Err(WireError::BadSize(too_big))
        );
        // The boundary itself is legal.
        assert!(Header::parse(&hdr(1, 0, MAX_MESSAGE_LEN as u16)).is_ok());
    }

    #[test]
    fn pad4_rounds_up() {
        assert_eq!(pad4(0), Some(0));
        assert_eq!(pad4(1), Some(4));
        assert_eq!(pad4(4), Some(4));
        assert_eq!(pad4(5), Some(8));
        assert_eq!(pad4(usize::MAX), None);
    }

    #[test]
    fn reads_words() {
        let body = [1u32, 0xFFFF_FFFF]
            .iter()
            .flat_map(|v| v.to_ne_bytes())
            .collect::<Vec<u8>>();
        let mut r = ArgReader::new(&body);
        assert_eq!(r.u32().unwrap(), 1);
        assert_eq!(r.u32().unwrap(), 0xFFFF_FFFF);
        assert!(r.is_empty());
        assert_eq!(r.u32(), Err(WireError::ArgOverrun));
    }

    #[test]
    fn reads_a_string_with_its_padding() {
        // "wl_shm" is 6 bytes + NUL = 7 declared, padded to 8.
        let mut body = 7u32.to_ne_bytes().to_vec();
        body.extend_from_slice(b"wl_shm\0\0");
        let mut r = ArgReader::new(&body);
        assert_eq!(r.string().unwrap(), Some("wl_shm"));
        assert!(r.is_empty());
    }

    #[test]
    fn a_null_string_is_none_not_empty() {
        let body = 0u32.to_ne_bytes().to_vec();
        let mut r = ArgReader::new(&body);
        assert_eq!(r.string().unwrap(), None);
    }

    #[test]
    fn an_unterminated_string_is_refused() {
        // Declares 4 bytes but the fourth is not a NUL.
        let mut body = 4u32.to_ne_bytes().to_vec();
        body.extend_from_slice(b"abcd");
        let mut r = ArgReader::new(&body);
        assert_eq!(r.string(), Err(WireError::UnterminatedString));
    }

    #[test]
    fn an_interior_nul_is_refused() {
        // "wl\0shm" - compares equal to "wl" under a NUL-terminated read and
        // unequal under a length-aware one. Refusing removes the ambiguity
        // before any policy code can depend on which one it got.
        let mut body = 7u32.to_ne_bytes().to_vec();
        body.extend_from_slice(b"wl\0shm\0\0");
        let mut r = ArgReader::new(&body);
        assert_eq!(r.string(), Err(WireError::InteriorNul));
    }

    #[test]
    fn non_utf8_is_refused() {
        let mut body = 4u32.to_ne_bytes().to_vec();
        body.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0x00]);
        let mut r = ArgReader::new(&body);
        assert_eq!(r.string(), Err(WireError::NotUtf8));
    }

    #[test]
    fn a_string_longer_than_the_body_is_refused_not_panicked() {
        // The classic: declared length far beyond what was actually sent.
        let body = 0xFFFF_FF00u32.to_ne_bytes().to_vec();
        let mut r = ArgReader::new(&body);
        assert_eq!(r.string(), Err(WireError::ArgOverrun));
    }

    #[test]
    fn an_array_longer_than_the_body_is_refused() {
        let body = 0xFFFF_FF00u32.to_ne_bytes().to_vec();
        let mut r = ArgReader::new(&body);
        assert_eq!(r.array(), Err(WireError::ArgOverrun));
    }

    #[test]
    fn reads_an_array_with_padding() {
        let mut body = 5u32.to_ne_bytes().to_vec();
        body.extend_from_slice(&[1, 2, 3, 4, 5, 0, 0, 0]);
        let mut r = ArgReader::new(&body);
        assert_eq!(r.array().unwrap(), &[1, 2, 3, 4, 5]);
        assert!(r.is_empty());
    }

    #[test]
    fn writer_produces_something_the_reader_accepts() {
        // wl_display.error(object_id, code, message)
        let msg = MessageWriter::new(1, 0)
            .u32(7)
            .u32(3)
            .string("no")
            .finish()
            .unwrap();
        let h = Header::parse(&msg).unwrap();
        assert_eq!(h.object, 1);
        assert_eq!(h.opcode, 0);
        assert_eq!(h.size as usize, msg.len());

        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
        assert_eq!(r.u32().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 3);
        assert_eq!(r.string().unwrap(), Some("no"));
        assert!(r.is_empty());
    }

    #[test]
    fn writer_output_is_always_aligned() {
        for s in ["", "a", "ab", "abc", "abcd", "abcde"] {
            let msg = MessageWriter::new(1, 0).string(s).finish().unwrap();
            assert_eq!(msg.len() % 4, 0, "string {s:?} produced {} bytes", msg.len());
            let mut r = ArgReader::new(&msg[HEADER_LEN..]);
            assert_eq!(r.string().unwrap(), Some(s).filter(|x: &&str| !x.is_empty()).or(Some("")));
        }
    }

    #[test]
    fn writer_refuses_to_emit_an_oversized_message() {
        let huge = "x".repeat(MAX_MESSAGE_LEN);
        assert!(MessageWriter::new(1, 0).string(&huge).finish().is_none());
    }

    #[test]
    fn server_id_base_splits_the_ranges_as_documented() {
        assert_eq!(SERVER_ID_BASE, 0xFF00_0000);
        assert!(1 < SERVER_ID_BASE);
        assert!(0xFEFF_FFFF < SERVER_ID_BASE);
    }
}
