use super::*;

fn zone(name: &str, mode: &str, uid: Option<u32>) -> Zone {
    let identity = uid.map(|u| format!("[identity]\nuid_base = {u}\n")).unwrap_or_default();
    let colour = format!("#1234{:02x}", name.bytes().next().unwrap_or(0));
    Zone::from_str(&format!(
        "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n\
         [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{identity}[ui]\nborder_color = \"{colour}\"\n"
    ))
    .expect("the test zone parses")
}

#[test]
fn the_mixer_lists_each_zone_by_the_uid_its_root_maps_to() {
    let zones = [
        zone("work", "routed", Some(458752)),
        zone("vault", "none", Some(524288)),
        zone("net", "nic", Some(131072)),
        zone("dev", "routed", None),
    ];
    assert_eq!(zones_list(&zones), "work 458752\nvault 524288\n");
}

#[test]
fn no_zone_dir_without_the_mixers_service() {
    assert_eq!(zone_dir("no-such-zone-here"), None);
}
