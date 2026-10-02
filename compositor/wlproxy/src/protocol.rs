//! Message signatures (protocol_tables.rs): the descriptors each carries and the object it creates.

use crate::wire::{ArgReader, WireError};

#[derive(Debug, Clone, Copy)]
pub struct Message {
    pub name: &'static str,
    /// The arguments in wire order, as gen-wl-protocol.py wrote them.
    pub args: &'static [Arg],
    /// How many of them are descriptors.
    pub fds: u8,
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

/// The interface of that name, indexed on first use: this runs for every new object and global.
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
    /// A new object; `iface` is None for wl_registry.bind, where the client names it on the wire.
    NewId { iface: Option<&'static str> },
    Array,
    Fd,
}

impl Message {
    pub fn fd_count(&self) -> usize {
        self.fds as usize
    }
}

/// The object a message creates and its strings, borrowed: only a message with strings allocates.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Decoded<'a> {
    /// (id, interface). No message in the tables creates two; a body that tries is refused.
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

/// Check a body against its signature to its exact end: a trailing byte is as bad as a missing one.
pub fn decode<'a>(msg: &Message, body: &'a [u8]) -> Result<Decoded<'a>, WireError> {
    let mut r = ArgReader::new(body);
    let mut d = Decoded::default();
    for &arg in msg.args {
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
pub(crate) mod tests;
