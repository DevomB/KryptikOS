//! kryptik-wlproxy's wire parser under libFuzzer: message framing, every
//! signature in the generated tables, and the writer the rewrites use. These
//! three files name nothing else in the proxy, so they compile here as they are.

#![no_main]
#![allow(dead_code)]

#[path = "../src/protocol.rs"]
mod protocol;
#[path = "../src/protocol_tables.rs"]
mod protocol_tables;
#[path = "../src/wire.rs"]
mod wire;

use libfuzzer_sys::fuzz_target;
use protocol::{decode, Arg, Message};
use wire::{ArgReader, Header, MessageWriter, HEADER_LEN};

/// Every request and event in the tables.
fn messages() -> &'static [&'static Message] {
    static ALL: std::sync::OnceLock<Vec<&'static Message>> = std::sync::OnceLock::new();
    ALL.get_or_init(|| protocol_tables::INTERFACES.iter().flat_map(|i| i.requests.iter().chain(i.events)).collect())
}

fuzz_target!(|data: &[u8]| {
    let all = messages();
    let mut rest = data;
    // A stream of messages, each read against the signature its object id picks.
    while let Ok(h) = Header::parse(rest) {
        assert_eq!(Header::parse(&h.encode()), Ok(h));
        let size = h.size as usize;
        let Some(body) = rest.get(HEADER_LEN..size) else { break };
        let m = all[h.object as usize % all.len()];
        if let Ok(d) = decode(m, body) {
            assert_eq!(d.new_object.is_some(), m.args.iter().any(|a| matches!(a, Arg::NewId { .. })));
            assert_eq!(d.bind_version.is_some(), m.args.contains(&Arg::NewId { iface: None }));
            for (at, s) in &d.strings {
                // The offset a rewrite trusts, and what the proxy would write in its place.
                assert_eq!(&body[at + 4..at + 4 + s.len()], s.as_bytes());
                assert_eq!(body[at + 4 + s.len()], 0);
                if let Some(out) = MessageWriter::new(h.object, h.opcode).string(s).finish() {
                    assert_eq!(Header::parse(&out).map(|w| w.size as usize), Ok(out.len()));
                    assert_eq!(ArgReader::new(&out[HEADER_LEN..]).string(), Ok(Some(*s)));
                }
            }
        }
        rest = &rest[size..];
    }
});
