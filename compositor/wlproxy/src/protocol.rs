//! Protocol knowledge: which messages exist, what they carry, and in
//! particular which ones carry descriptors and which create objects.
//!
//! The tables are generated from upstream's XML (protocol_tables.rs); this
//! module gives them a shape and answers the two questions the proxy asks
//! on every message: how many descriptors ride with it, and which new
//! objects it creates (and of which interface), so the object map stays in
//! step with both peers.

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
    pub version: u32,
    pub requests: &'static [Message],
    pub events: &'static [Message],
}

pub fn find(name: &str) -> Option<&'static Interface> {
    crate::protocol_tables::INTERFACES.iter().find(|i| i.name == name)
}

/// One argument of a message, as the wire carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arg {
    Int,
    Uint,
    Fixed,
    String { nullable: bool },
    Object { nullable: bool },
    /// A new object created by this message. `iface` is `None` for
    /// wl_registry.bind, whose new_id is preceded on the wire by the
    /// interface name and version the client chose.
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

/// What a decoded message tells the proxy: the objects it creates, and the
/// strings it carries (for rewriting), in argument order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// (new object id, interface name). For wl_registry.bind the interface
    /// comes from the request itself.
    pub new_objects: Vec<(u32, String)>,
    /// (byte offset of the string's length word within the body, value)
    pub strings: Vec<(usize, String)>,
    /// The version requested by wl_registry.bind, when this is one.
    pub bind_version: Option<u32>,
}

/// Walk a message body against its signature, validating every argument
/// and collecting what the proxy needs. Refuses anything that does not
/// parse exactly to the signature's end: a trailing byte is as suspect as a
/// missing one.
pub fn decode(msg: &Message, body: &[u8]) -> Result<Decoded, WireError> {
    let mut r = ArgReader::new(body);
    let mut d = Decoded::default();
    let mut pending_bind: Option<(String, u32)> = None;
    for arg in msg.args() {
        match arg {
            Arg::Int | Arg::Uint | Arg::Fixed | Arg::Object { .. } => {
                r.u32()?;
            }
            Arg::String { nullable } => {
                let at = body.len() - r.remaining();
                match r.string()? {
                    Some(s) => d.strings.push((at, s.to_string())),
                    None if nullable => {}
                    None => return Err(WireError::UnterminatedString),
                }
            }
            Arg::Array => {
                r.array()?;
            }
            Arg::NewId { iface: Some(name) } => {
                let id = r.u32()?;
                d.new_objects.push((id, name.to_string()));
            }
            Arg::NewId { iface: None } => {
                // wl_registry.bind: string interface, uint version, new_id
                let name = match r.string()? {
                    Some(s) => s.to_string(),
                    None => return Err(WireError::UnterminatedString),
                };
                let version = r.u32()?;
                let id = r.u32()?;
                pending_bind = Some((name.clone(), version));
                d.new_objects.push((id, name));
            }
            Arg::Fd => {}
        }
    }
    if !r.is_empty() {
        return Err(WireError::ArgOverrun);
    }
    if let Some((_, v)) = pending_bind {
        d.bind_version = Some(v);
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
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
    fn descriptor_counts_come_from_the_tables() {
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
    fn bind_is_decoded_with_the_interface_the_client_named() {
        let reg = find("wl_registry").unwrap();
        let bind = &reg.requests[0];
        let msg = MessageWriter::new(2, 0).u32(4).string("wl_compositor").u32(5).u32(3).finish().unwrap();
        let d = decode(bind, &msg[8..]).unwrap();
        assert_eq!(d.new_objects, vec![(3, "wl_compositor".to_string())]);
        assert_eq!(d.bind_version, Some(5));
    }

    #[test]
    fn a_trailing_byte_is_refused() {
        let comp = find("wl_compositor").unwrap();
        let create_surface = &comp.requests[0]; // n:wl_surface
        let mut msg = MessageWriter::new(3, 0).u32(9).finish().unwrap();
        msg.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(decode(create_surface, &msg[8..]), Err(WireError::ArgOverrun));
        let ok = MessageWriter::new(3, 0).u32(9).finish().unwrap();
        assert_eq!(decode(create_surface, &ok[8..]).unwrap().new_objects, vec![(9, "wl_surface".into())]);
    }

    #[test]
    fn strings_are_located_for_rewriting() {
        let top = find("xdg_toplevel").unwrap();
        let set_title = top.requests.iter().find(|m| m.name == "set_title").unwrap();
        let msg = MessageWriter::new(7, 2).string("hello").finish().unwrap();
        let d = decode(set_title, &msg[8..]).unwrap();
        assert_eq!(d.strings, vec![(0, "hello".to_string())]);
    }
}
