//! Message signatures from the generated tables (protocol_tables.rs): how many
//! descriptors ride with each message and which object it creates, so the
//! object map stays in step with both peers.

use crate::wire::{ArgReader, WireError};

#[derive(Debug, Clone, Copy)]
pub struct Message {
    pub name: &'static str,
    /// Space-separated argument letters; see gen-wl-protocol.py.
    pub sig: &'static str,
    pub since: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Interface {
    pub name: &'static str,
    /// Read by a test that holds policy::ALLOWED to what the tables parse.
    #[cfg_attr(not(test), allow(dead_code))]
    pub version: u32,
    pub requests: &'static [Message],
    pub events: &'static [Message],
}

/// The interface of that name; None is a refusal in every caller. Indexed on
/// first use, since this runs for every new object and every advertised global.
pub fn find(name: &str) -> Option<&'static Interface> {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static BY_NAME: OnceLock<HashMap<&'static str, &'static Interface>> = OnceLock::new();
    BY_NAME
        .get_or_init(|| crate::protocol_tables::INTERFACES.iter().map(|i| (i.name, i)).collect())
        .get(name)
        .copied()
}

/// One argument of a message, as the wire carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arg {
    Int,
    Uint,
    Fixed,
    String { nullable: bool },
    Object { nullable: bool },
    /// A new object. `iface` is None for wl_registry.bind, whose new_id follows
    /// the interface name and version the client chose.
    NewId { iface: Option<&'static str> },
    Array,
    Fd,
}

impl Message {
    pub fn args(&self) -> impl Iterator<Item = Arg> + '_ {
        self.sig.split_whitespace().map(|tok| {
            let (nullable, tok) = match tok.strip_prefix('?') {
                Some(rest) => (true, rest),
                None => (false, tok),
            };
            match tok {
                "i" => Arg::Int,
                "u" => Arg::Uint,
                "f" => Arg::Fixed,
                "s" => Arg::String { nullable },
                "o" => Arg::Object { nullable },
                "a" => Arg::Array,
                "h" => Arg::Fd,
                t if t.starts_with("n:") => Arg::NewId {
                    iface: match &t[2..] {
                        "*" => None,
                        name => Some(name),
                    },
                },
                other => panic!("generated table carries an unknown signature token {other:?}"),
            }
        })
    }

    pub fn fd_count(&self) -> usize {
        self.args().filter(|a| *a == Arg::Fd).count()
    }
}

/// The object a message creates and the strings it carries (for rewriting),
/// borrowed from the body: decoding allocates only for a message with strings.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Decoded<'a> {
    /// (new object id, interface name). No message creates two (the tables are
    /// tested for it), and a body that tries is refused.
    pub new_object: Option<(u32, &'a str)>,
    /// (byte offset of the string's length word within the body, value)
    pub strings: Vec<(usize, &'a str)>,
    /// The version requested by wl_registry.bind, when this is one.
    pub bind_version: Option<u32>,
}

impl<'a> Decoded<'a> {
    fn created(&mut self, id: u32, name: &'a str) -> Result<(), WireError> {
        if self.new_object.is_some() {
            return Err(WireError::ArgOverrun);
        }
        self.new_object = Some((id, name));
        Ok(())
    }
}

/// Validate a body against its signature and collect what the proxy needs. It
/// must parse exactly to its end: a trailing byte is as suspect as a missing one.
pub fn decode<'a>(msg: &Message, body: &'a [u8]) -> Result<Decoded<'a>, WireError> {
    let mut r = ArgReader::new(body);
    let mut d = Decoded::default();
    for arg in msg.args() {
        match arg {
            Arg::Int | Arg::Uint | Arg::Fixed | Arg::Object { .. } => {
                r.u32()?;
            }
            Arg::String { nullable } => {
                let at = body.len() - r.remaining();
                match r.string()? {
                    Some(s) => d.strings.push((at, s)),
                    None if nullable => {}
                    None => return Err(WireError::UnterminatedString),
                }
            }
            Arg::Array => {
                r.array()?;
            }
            Arg::NewId { iface: Some(name) } => {
                let id = r.u32()?;
                d.created(id, name)?;
            }
            Arg::NewId { iface: None } => {
                // wl_registry.bind: string interface, uint version, new_id
                let name = r.string()?.ok_or(WireError::UnterminatedString)?;
                let version = r.u32()?;
                let id = r.u32()?;
                d.bind_version = Some(version);
                d.created(id, name)?;
            }
            Arg::Fd => {}
        }
    }
    if !r.is_empty() {
        return Err(WireError::ArgOverrun);
    }
    Ok(d)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::wire::MessageWriter;

    #[test]
    fn every_generated_signature_parses() {
        for i in crate::protocol_tables::INTERFACES {
            for m in i.requests.iter().chain(i.events.iter()) {
                let _ = m.args().count();
            }
        }
    }

    #[test]
    fn find_matches_table_exactly() {
        for i in crate::protocol_tables::INTERFACES {
            let found = find(i.name).expect("every generated interface is findable");
            assert!(std::ptr::eq(found, i), "{} resolved to a different entry", i.name);
        }
        assert!(find("").is_none());
        assert!(find("wl_compositor_").is_none());
    }

    /// At most one new object per message, and no more descriptors than one sendmsg carries.
    #[test]
    fn tables_fit_one_send() {
        for i in crate::protocol_tables::INTERFACES {
            for m in i.requests.iter().chain(i.events.iter()) {
                let created = m.args().filter(|a| matches!(a, Arg::NewId { .. })).count();
                assert!(created <= 1, "{}.{} creates {created} objects", i.name, m.name);
                assert!(m.fd_count() <= crate::session::BATCH_FDS, "{}.{}", i.name, m.name);
            }
        }
    }

    #[test]
    fn descriptor_counts_from_tables() {
        let shm = find("wl_shm").unwrap();
        let create_pool = shm.requests.iter().find(|m| m.name == "create_pool").unwrap();
        assert_eq!(create_pool.fd_count(), 1);
        let kb = find("wl_keyboard").unwrap();
        let keymap = kb.events.iter().find(|m| m.name == "keymap").unwrap();
        assert_eq!(keymap.fd_count(), 1);
        let comp = find("wl_compositor").unwrap();
        assert!(comp.requests.iter().all(|m| m.fd_count() == 0));
    }

    #[test]
    fn bind_uses_client_named_interface() {
        let reg = find("wl_registry").unwrap();
        let bind = &reg.requests[0];
        let msg = MessageWriter::new(2, 0).u32(4).string("wl_compositor").u32(5).u32(3).finish().unwrap();
        let d = decode(bind, &msg[8..]).unwrap();
        assert_eq!(d.new_object, Some((3, "wl_compositor")));
        assert_eq!(d.bind_version, Some(5));
    }

    #[test]
    fn trailing_byte_is_refused() {
        let comp = find("wl_compositor").unwrap();
        let create_surface = &comp.requests[0]; // n:wl_surface
        let mut msg = MessageWriter::new(3, 0).u32(9).finish().unwrap();
        msg.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(decode(create_surface, &msg[8..]), Err(WireError::ArgOverrun));
        let ok = MessageWriter::new(3, 0).u32(9).finish().unwrap();
        assert_eq!(decode(create_surface, &ok[8..]).unwrap().new_object, Some((9, "wl_surface")));
    }

    #[test]
    fn strings_are_located_for_rewriting() {
        let top = find("xdg_toplevel").unwrap();
        let set_title = top.requests.iter().find(|m| m.name == "set_title").unwrap();
        let msg = MessageWriter::new(7, 2).string("hello").finish().unwrap();
        let d = decode(set_title, &msg[8..]).unwrap();
        assert_eq!(d.strings, vec![(0, "hello")]);
    }

    // --- the decoder, attacked ---------------------------------------------
    /* `Header::parse` and `decode` see every byte a client sends. A well-formed
     * body for each message in the tables is damaged by a fixed-seed generator,
     * so a failure repeats on every machine. The decoder must never panic or
     * read past the body, and returns Ok only for an exact parse. */

    /// xorshift64*: small, seeded, the same sequence everywhere.
    pub(crate) struct Rng(pub u64);
    impl Rng {
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    /// The values a length or an id is most likely to be mishandled at.
    const EDGES: [u32; 10] = [0, 1, 3, 4, 5, 0x7f, 0xfff, 0x1000, 0x7fff_ffff, 0xffff_ffff];

    fn well_formed(m: &Message, rng: &mut Rng) -> Vec<u8> {
        let mut b = Vec::new();
        let word = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_ne_bytes());
        let bytes = |b: &mut Vec<u8>, data: &[u8]| {
            b.extend_from_slice(data);
            while b.len() % 4 != 0 {
                b.push(0);
            }
        };
        for arg in m.args() {
            match arg {
                Arg::Int | Arg::Uint | Arg::Fixed | Arg::Object { .. } => word(&mut b, rng.next() as u32),
                Arg::String { .. } => {
                    let text = ["", "x", "wl_seat", "a title, with spaces", "zażółć"][rng.below(5)];
                    word(&mut b, text.len() as u32 + 1);
                    bytes(&mut b, &[text.as_bytes(), &[0]].concat());
                }
                Arg::Array => {
                    let len = rng.below(9);
                    word(&mut b, len as u32);
                    bytes(&mut b, &vec![0xAB; len]);
                }
                Arg::NewId { iface: None } => {
                    word(&mut b, 14);
                    bytes(&mut b, b"wl_compositor\0");
                    word(&mut b, 4);
                    word(&mut b, 7);
                }
                Arg::NewId { iface: Some(_) } => word(&mut b, 7),
                Arg::Fd => {}
            }
        }
        b
    }

    fn damage(body: &mut Vec<u8>, rng: &mut Rng) {
        match rng.below(6) {
            0 if !body.is_empty() => { let at = rng.below(body.len()); body[at] ^= 1 << rng.below(8); }
            1 if !body.is_empty() => body.truncate(rng.below(body.len())),
            2 => { let n = 1 + rng.below(8); for _ in 0..n { body.push(rng.next() as u8); } }
            3 if body.len() >= 4 => {
                // A whole word replaced by an edge value: where the lengths live.
                let at = rng.below(body.len() / 4) * 4;
                body[at..at + 4].copy_from_slice(&EDGES[rng.below(EDGES.len())].to_ne_bytes());
            }
            4 if !body.is_empty() => { let at = rng.below(body.len()); body[at] = [0x00, 0xff, 0x80, 0xc0][rng.below(4)]; }
            _ if body.len() >= 8 => { let at = rng.below(body.len() / 4) * 4; body.drain(at..at + 4); }
            _ => body.push(0),
        }
    }

    #[test]
    fn decoder_survives_any_body() {
        let mut rng = Rng(0x4B52_5950_5449_4B31);
        let (mut tried, mut accepted) = (0u32, 0u32);
        for i in crate::protocol_tables::INTERFACES {
            for m in i.requests.iter().chain(i.events.iter()) {
                let seed = well_formed(m, &mut rng);
                assert!(decode(m, &seed).is_ok(), "{}.{}: the well-formed body was refused", i.name, m.name);
                for _ in 0..300 {
                    let mut body = seed.clone();
                    for _ in 0..1 + rng.below(3) {
                        damage(&mut body, &mut rng);
                    }
                    tried += 1;
                    // Not panicking is the first property.
                    if let Ok(d) = decode(m, &body) {
                        accepted += 1;
                        assert_eq!(body.len() % 4, 0, "{}.{}: accepted a body that is not word-aligned", i.name, m.name);
                        for (at, s) in &d.strings {
                            assert!(at + 4 + s.len() < body.len() + 1, "{}.{}: a string lies past the body", i.name, m.name);
                            assert!(!s.contains('\0'), "{}.{}: a string with a NUL in it", i.name, m.name);
                        }
                    }
                }
            }
        }
        // The generator must actually reach both sides of the decoder.
        assert!(tried > 10_000 && accepted > tried / 50 && accepted < tried, "tried {tried}, accepted {accepted}");
    }

    #[test]
    fn header_parse_survives_any_bytes() {
        use crate::wire::{Header, HEADER_LEN, MAX_MESSAGE_LEN};
        let mut rng = Rng(0x5749_5245_4844_5231);
        for n in 0..200_000u32 {
            let mut buf = rng.next().to_ne_bytes().to_vec();
            if n % 3 == 0 {
                // The size field is where the edges are: steer a third of the runs there.
                let size = [0u16, 4, 7, 8, 9, 12, 4092, 4096, 4097, 4100, 0xfffc, 0xffff][rng.below(12)];
                let word1 = (u32::from(size) << 16) | (rng.next() as u32 & 0xffff);
                buf[4..].copy_from_slice(&word1.to_ne_bytes());
            }
            buf.truncate(rng.below(HEADER_LEN + 1).max(if n % 5 == 0 { 0 } else { HEADER_LEN }));
            if let Ok(h) = Header::parse(&buf) {
                assert!(buf.len() >= HEADER_LEN);
                assert!((h.size as usize) >= HEADER_LEN && (h.size as usize) <= MAX_MESSAGE_LEN && h.size % 4 == 0, "{h:?}");
                assert_eq!(Header::parse(&h.encode()), Ok(h), "a header does not survive its own encoding");
            }
        }
    }
}
