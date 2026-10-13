//! The broker's request parser under libFuzzer: any header line a zone can
//! send, and whatever it accepts held to the bounds its refusals enforce.

use libfuzzer_sys::fuzz_target;

use crate::broker::{check_transfer_name, parse_request, Request, CLIPBOARD_MAX, MIME_TYPES};
use crate::update::{POINTER_MAX, PUT_MAX};

fuzz_target!(|data: &[u8]| {
    // The header as serve_connection takes it: up to the first newline, decoded lossily.
    let Some(nl) = data.iter().position(|b| *b == b'\n') else { return };
    let header = String::from_utf8_lossy(&data[..nl]);
    match parse_request(&header) {
        Err(_) | Ok(Request::Version | Request::ClipboardGet | Request::UpdatePoll) => {}
        Ok(Request::ClipboardSet { mime, len }) => assert!(MIME_TYPES.contains(&mime.as_str()) && len <= CLIPBOARD_MAX),
        Ok(Request::Transfer { dest, name }) => {
            assert!((1..=12).contains(&dest.len()));
            assert!(dest.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
            assert!(check_transfer_name(&name).is_ok());
        }
        Ok(Request::TimeOffset(c)) => assert!(c.offset.is_finite() && c.offset.abs() <= 1e10 && (1..=16).contains(&c.sources)),
        Ok(Request::UpdateLatest { plen, slen }) => assert!((1..=POINTER_MAX).contains(&plen) && (1..=POINTER_MAX).contains(&slen)),
        Ok(Request::UpdatePut { name, len, .. }) => assert!(check_transfer_name(&name).is_ok() && (1..=PUT_MAX).contains(&len)),
        Ok(Request::NotAZoneVerb(v)) => assert_eq!(v, "clipboard-move"),
        Ok(Request::Unknown(v)) => assert!(!v.is_empty() && !v.contains(char::is_whitespace)),
    }
});
