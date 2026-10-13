use super::*;

#[test]
fn a_refused_passphrase_is_heard_in_wpa_supplicants_words() {
    // WPA2: the 4-way handshake failed.
    assert_eq!(
        heard("<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Home \\\"net\\\"\" auth_failures=1 duration=10 reason=WRONG_KEY"),
        Some(Heard::WrongKey { ssid: b"Home \"net\"".to_vec() })
    );
    // SAE: the access point refused the station's confirm, which names only the access point.
    assert_eq!(
        heard("<3>SME: Trying to authenticate with 02:00:00:00:01:00 (SSID='Caf\\xc3\\xa9' freq=2412 MHz)"),
        Some(Heard::Trying { bssid: "02:00:00:00:01:00".into(), ssid: "Café".as_bytes().to_vec() })
    );
    assert_eq!(
        heard("<3>CTRL-EVENT-AUTH-REJECT 02:00:00:00:01:00 auth_type=3 auth_transaction=2 status_code=15"),
        Some(Heard::SaeRefused { bssid: "02:00:00:00:01:00".into() })
    );
    assert_eq!(heard("<3>CTRL-EVENT-CONNECTED - Connection to 02:00:00:00:01:00 completed [id=0 id_str=]"), Some(Heard::Joined));
    assert_eq!(heard("<3>CTRL-EVENT-TERMINATING "), Some(Heard::Ending));
    for other in [
        // A join that failed for another reason says nothing of the passphrase.
        "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Home\" auth_failures=4 duration=60 reason=CONN_FAILED",
        "<3>CTRL-EVENT-AUTH-REJECT 02:00:00:00:01:00 auth_type=3 auth_transaction=1 status_code=1",
        "<3>CTRL-EVENT-AUTH-REJECT 02:00:00:00:01:00 auth_type=0 auth_transaction=2 status_code=15",
        "<3>CTRL-EVENT-DISCONNECTED bssid=02:00:00:00:01:00 reason=15",
        "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"\\q\" auth_failures=1 duration=10 reason=WRONG_KEY",
        "CTRL-EVENT-CONNECTED - Connection to 02:00:00:00:01:00 completed",
        "OK\n",
        "PONG\n",
    ] {
        assert_eq!(heard(other), None, "{other}");
    }
}

#[test]
fn wpa_supplicants_escapes_read_back() {
    assert_eq!(unescape_wpa("a\\\\b\\\"c\\e\\n\\r\\t\\x00\\xff"), Some(b"a\\b\"c\x1b\n\r\t\x00\xff".to_vec()));
    let long = "a".repeat(33);
    for bad in ["", "\\", "\\x", "\\xf", "\\xfg", "\\x+f", "\\q", "é", long.as_str()] {
        assert_eq!(unescape_wpa(bad), None, "{bad:?}");
    }
}

#[test]
fn the_kept_name_reads_back_as_iw_prints_it() {
    for ssid in [&b"Home"[..], b" two  spaces ", b"back\\slash", "Ресторан".as_bytes(), b"\x00\x1b\xff"] {
        let printed = crate::wifi::as_iw_prints(ssid);
        assert!(printed.bytes().all(|b| b.is_ascii_graphic() || b == b' '), "{printed:?}");
        assert!(!printed.starts_with(' ') && !printed.ends_with(' '), "{printed:?}");
        assert_eq!(crate::wifi::ssid_from_iw(&printed).as_deref(), Some(ssid), "{printed:?}");
    }
}

#[test]
fn a_radio_is_named_as_the_kernel_names_one() {
    for bad in ["", ".", "..", "a/b", "wlan 0", "wl:0", "sixteen-letters!"] {
        assert!(watch(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_listener_keeps_a_refusal_until_a_join() {
    let dir = std::env::temp_dir().join(format!("kryptik-supplicant-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The supplicant's socket for the radio, where wpa_supplicant binds one.
    let supplicant = UnixDatagram::bind(dir.join("wlan0")).unwrap();
    supplicant.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let listening = {
        let dir = dir.clone();
        std::thread::spawn(move || listen(&dir, "wlan0"))
    };
    let mut buf = [0u8; 64];
    let (n, from) = supplicant.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ATTACH");
    let listener = from.as_pathname().unwrap().to_path_buf();
    let say = |event: &str| {
        supplicant.send_to(event.as_bytes(), &listener).unwrap();
    };
    let refused = dir.join("wlan0.refused");
    let kept = || std::fs::read_to_string(&refused).ok();
    let wait = |want: Option<&str>| {
        for _ in 0..500 {
            if kept().as_deref() == want {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("kept {:?}, not {want:?}", kept());
    };
    say("OK\n");
    say("<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Home net\" auth_failures=1 duration=10 reason=WRONG_KEY");
    wait(Some("Home net\n"));
    assert_eq!(std::fs::metadata(&refused).unwrap().permissions().mode() & 0o777, 0o644);
    say("<3>CTRL-EVENT-CONNECTED - Connection to 02:00:00:00:01:00 completed [id=0 id_str=]");
    wait(None);
    say("<3>SME: Trying to authenticate with 02:00:00:00:01:00 (SSID='Caf\\xc3\\xa9' freq=2412 MHz)");
    say("<3>CTRL-EVENT-AUTH-REJECT 02:00:00:00:01:00 auth_type=3 auth_transaction=2 status_code=15");
    wait(Some("Caf\\xc3\\xa9\n"));
    // A refusal from an access point other than the one being joined names no network.
    say("<3>SME: Trying to authenticate with 02:00:00:00:01:01 (SSID='Other' freq=2412 MHz)");
    say("<3>CTRL-EVENT-AUTH-REJECT 02:00:00:00:01:00 auth_type=3 auth_transaction=2 status_code=15");
    say("<3>CTRL-EVENT-TERMINATING ");
    assert!(listening.join().unwrap().is_ok());
    assert_eq!(kept().as_deref(), Some("Caf\\xc3\\xa9\n"));
    assert!(!listener.exists(), "the listener's own socket is left behind");
    let _ = std::fs::remove_dir_all(&dir);
}
