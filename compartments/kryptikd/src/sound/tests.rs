use super::*;

fn zone(name: &str, mode: &str, uid: Option<u32>, extra: &str) -> Result<Zone, crate::zone::ZoneError> {
    let identity = uid.map(|u| format!("[identity]\nuid_base = {u}\n")).unwrap_or_default();
    let colour = format!("#1234{:02x}", name.bytes().next().unwrap_or(0));
    Zone::from_str(&format!(
        "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n\
         [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{identity}{extra}[ui]\nborder_color = \"{colour}\"\n"
    ))
}

#[test]
fn the_mixer_lists_each_zone_that_plays_by_the_uid_its_root_maps_to() {
    let zones = [
        zone("work", "routed", Some(458752), ""),
        zone("vault", "none", Some(393216), "[sound]\nplay = false\n"),
        zone("personal", "routed", Some(262144), "[sound]\nplay = true\n"),
        zone("net", "nic", Some(196608), ""),
        zone("dev", "routed", None, ""),
    ]
    .map(|z| z.expect("the test zone parses"));
    assert_eq!(zones_list(&zones), "work 458752\npersonal 262144\n");
}

#[test]
fn the_nic_zone_is_never_given_sound() {
    assert!(!zone("net", "nic", Some(196608), "").unwrap().sound);
    assert!(zone("net", "nic", Some(196608), "[sound]\nplay = true\n").is_err());
    assert!(zone("work", "routed", Some(458752), "[sound]\nplay = yes\n").is_err());
}

#[test]
fn no_zone_dir_without_the_mixers_service() {
    assert_eq!(zone_dir("no-such-zone-here"), None);
}
