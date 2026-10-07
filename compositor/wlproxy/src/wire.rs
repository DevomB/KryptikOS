//! The Wayland wire format, parsed defensively: every length comes from a zone,
//! so none is used unchecked, and no input can make this panic.
//!
//! A message is a header (object id; `size << 16 | opcode`, `size` counting the
//! header) and arguments padded to 4 bytes, all in host byte order. A string's
//! length includes its NUL, and 0 means null. An fd takes no bytes: it travels
//! by SCM_RIGHTS, so only the tables (protocol.rs) say how many a message
//! carries, and a miscount hands a client another message's descriptor.

use std::fmt;

pub const HEADER_LEN: usize = 8;

/// Largest message. libwayland never sends more than its 4096-byte buffer; the
/// 16-bit size field could claim 64 KiB for the proxy to buffer.
pub const MAX_MESSAGE_LEN: usize = 4096;

/// Ids from here up are the server's; a client creating one is refused.
pub const SERVER_ID_BASE: u32 = 0xFF00_0000;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WireError {
    /// Fewer bytes than a header.
    Truncated,
    /// `size` below the header length, unaligned, or over `MAX_MESSAGE_LEN`.
    BadSize(u16),
    /// An argument ran past the end of the message body.
    ArgOverrun,
    /// A second new_id in one message: the object map takes one per message.
    SecondNewId,
    /// A string whose declared length does not end in NUL.
    UnterminatedString,
    /// A null string where the signature does not allow one.
    NullString,
    /// A string that is not valid UTF-8, which every Wayland string must be.
    NotUtf8,
    /// A NUL inside a string: `"wl_shm\0_evil"` equals `"wl_shm"` only to a
    /// C-string comparison, and policy must not depend on which kind runs.
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
            WireError::SecondNewId => write!(f, "message creates a second object"),
            WireError::UnterminatedString => write!(f, "string is not NUL-terminated"),
            WireError::NullString => write!(f, "null string where the signature requires one"),
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
    /// Parse a header from the first 8 bytes of `buf`. `size` is validated
    /// here, so no `Header` can carry a bad length.
    pub fn parse(buf: &[u8]) -> Result<Header, WireError> {
        if buf.len() < HEADER_LEN {
            return Err(WireError::Truncated);
        }
        let object = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let word1 = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let opcode = (word1 & 0xFFFF) as u16;
        let size = (word1 >> 16) as u16;

        if (size as usize) < HEADER_LEN
            || !size.is_multiple_of(4)
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

/// Sequential reader over a message body; it never panics or passes the end.
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
        // `n` comes from the client, and `pos + n` could wrap on a 32-bit target.
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

/// Builder for the messages the proxy writes itself: errors and rewrites.
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
        while !self.body.len().is_multiple_of(4) {
            self.body.push(0);
        }
        self
    }

    /// Finish the message; None if it would exceed `MAX_MESSAGE_LEN`.
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
mod tests;
