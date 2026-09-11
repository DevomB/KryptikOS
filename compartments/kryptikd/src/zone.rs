//! Zone definitions: parsing and validation.
//!
//! The parser is hand-written rather than pulling in a TOML crate. kryptikd
//! runs privileged and mediates every boundary in the system (ADR-010), so the
//! dependency surface is kept to `libc`. Zone files are authored by the system
//! owner and live in zone 0, but they are still parsed defensively: a malformed
//! file must produce an error, never a zone with weaker isolation than intended.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

/// How a zone reaches the network.
///
/// The distinction between `None` and "firewalled off" is the whole point:
/// `None` means the zone's network namespace contains only loopback. There is
/// no interface to misconfigure and no rule that can be dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Network namespace with loopback only. No path to any interface.
    None,
    /// veth into the bridge owned by the `nic` zone.
    Routed,
    /// Holds the physical interface. Exactly one zone may have this.
    Nic,
}

impl NetworkMode {
    fn parse(s: &str) -> Result<Self, ZoneError> {
        match s {
            "none" => Ok(NetworkMode::None),
            "routed" => Ok(NetworkMode::Routed),
            "nic" => Ok(NetworkMode::Nic),
            other => Err(ZoneError::BadValue {
                field: "network.mode".into(),
                value: other.into(),
                expected: "none | routed | nic".into(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    /// Dedicated LUKS2 volume, unlocked on start, keys wiped on stop.
    Encrypted,
    /// tmpfs overlay, destroyed at teardown.
    Ephemeral,
}

impl StorageMode {
    fn parse(s: &str) -> Result<Self, ZoneError> {
        match s {
            "encrypted" => Ok(StorageMode::Encrypted),
            "ephemeral" => Ok(StorageMode::Ephemeral),
            other => Err(ZoneError::BadValue {
                field: "storage.mode".into(),
                value: other.into(),
                expected: "encrypted | ephemeral".into(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Zone {
    pub name: String,
    pub description: String,
    pub network: NetworkMode,
    pub bridge: Option<String>,
    pub storage: StorageMode,
    pub volume: Option<String>,
    pub seccomp: Option<String>,
    pub landlock: Option<String>,
    pub memory_max: Option<String>,
    pub pids_max: Option<u32>,
    pub border_color: String,
}

#[derive(Debug)]
pub enum ZoneError {
    Io(String),
    Syntax { line: usize, msg: String },
    Missing(String),
    BadValue { field: String, value: String, expected: String },
    Invalid(String),
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoneError::Io(e) => write!(f, "io error: {e}"),
            ZoneError::Syntax { line, msg } => write!(f, "line {line}: {msg}"),
            ZoneError::Missing(k) => write!(f, "missing required field: {k}"),
            ZoneError::BadValue { field, value, expected } => {
                write!(f, "{field}: invalid value {value:?} (expected {expected})")
            }
            ZoneError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

/// Every key a zone file may contain. Anything else is refused: a key that is
/// parsed and ignored is a setting the operator believes is in force.
pub const KNOWN_KEYS: &[&str] = &[
    "zone.name", "zone.description",
    "network.mode", "network.bridge",
    "storage.mode", "storage.volume", "storage.unlock", "storage.wipe_keys",
    "policy.seccomp", "policy.landlock",
    "limits.memory_max", "limits.pids_max",
    "ui.border_color",
];

/// A byte size as cgroup v2 memory.max accepts it: digits, optionally
/// followed by one of K, M, G, T. "max" is not accepted - leave the key out.
pub fn is_size(s: &str) -> bool {
    let (digits, suffix) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => s.split_at(i),
        None => (s, ""),
    };
    !digits.is_empty()
        && digits.chars().any(|c| c != '0')
        && matches!(suffix, "" | "K" | "M" | "G" | "T" | "k" | "m" | "g" | "t")
}

/// Minimal TOML reader: `[section]` headers and `key = value` pairs, with `#`
/// comments. Values are strings or bare integers. Anything the zone format does
/// not use (arrays, nested tables, multi-line strings) is rejected rather than
/// ignored, so a file using an unsupported construct fails loudly instead of
/// silently losing the setting it was trying to express.
fn parse_flat_toml(text: &str) -> Result<HashMap<String, String>, ZoneError> {
    let mut out = HashMap::new();
    let mut section = String::new();

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix('[') {
            let name = rest.strip_suffix(']').ok_or(ZoneError::Syntax {
                line: lineno,
                msg: "unterminated section header".into(),
            })?;
            if name.contains('[') || name.contains('.') {
                return Err(ZoneError::Syntax {
                    line: lineno,
                    msg: "nested tables and array-of-tables are not supported".into(),
                });
            }
            section = name.trim().to_string();
            continue;
        }

        let (key, value) = line.split_once('=').ok_or(ZoneError::Syntax {
            line: lineno,
            msg: "expected 'key = value'".into(),
        })?;
        let key = key.trim();
        let value = value.trim();

        if value.starts_with('[') {
            return Err(ZoneError::Syntax {
                line: lineno,
                msg: "arrays are not supported in zone definitions".into(),
            });
        }

        let value = if let Some(inner) = value.strip_prefix('"') {
            inner.strip_suffix('"').ok_or(ZoneError::Syntax {
                line: lineno,
                msg: "unterminated string".into(),
            })?
        } else {
            // Bare value: must be an integer or boolean, not an unquoted word.
            if !value.chars().all(|c| c.is_ascii_digit())
                && value != "true"
                && value != "false"
            {
                return Err(ZoneError::Syntax {
                    line: lineno,
                    msg: format!("unquoted value {value:?}: strings must be quoted"),
                });
            }
            value
        };

        let full = if section.is_empty() {
            key.to_string()
        } else {
            format!("{section}.{key}")
        };

        if out.insert(full.clone(), value.to_string()).is_some() {
            return Err(ZoneError::Syntax {
                line: lineno,
                msg: format!("duplicate key {full:?}"),
            });
        }
    }

    Ok(out)
}

/// Strip a trailing `#` comment, respecting quoted strings so a colour like
/// "#c9a227" survives.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_string = !in_string,
            b'#' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

impl Zone {
    pub fn from_file(path: &Path) -> Result<Self, ZoneError> {
        let text = fs::read_to_string(path)
            .map_err(|e| ZoneError::Io(format!("{}: {e}", path.display())))?;
        Self::from_str(&text)
    }

    pub fn from_str(text: &str) -> Result<Self, ZoneError> {
        let kv = parse_flat_toml(text)?;
        let get = |k: &str| kv.get(k).cloned();
        let need = |k: &str| kv.get(k).cloned().ok_or_else(|| ZoneError::Missing(k.into()));

        for k in kv.keys() {
            if !KNOWN_KEYS.contains(&k.as_str()) {
                return Err(ZoneError::Invalid(format!(
                    "unknown key {k:?}: not a zone setting, and an unknown key would \
                     otherwise be silently ignored"
                )));
            }
        }

        let name = need("zone.name")?;
        let network = NetworkMode::parse(&need("network.mode")?)?;
        let storage = StorageMode::parse(&need("storage.mode")?)?;

        let bad = |field: &str, value: &str, expected: &str| ZoneError::BadValue {
            field: field.into(),
            value: value.into(),
            expected: expected.into(),
        };
        // A limit that does not parse must be an error, not None: the first
        // version turned `pids_max = "lots"` into "no limit".
        let pids_max = match kv.get("limits.pids_max") {
            None => None,
            Some(v) => Some(
                v.parse::<u32>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| bad("limits.pids_max", v, "a positive integer"))?,
            ),
        };
        if let Some(v) = kv.get("limits.memory_max") {
            if !is_size(v) {
                return Err(bad("limits.memory_max", v, "a size such as 512M or 2G"));
            }
        }
        if let Some(v) = kv.get("storage.unlock") {
            if v != "on-start" {
                return Err(bad("storage.unlock", v, "on-start"));
            }
        }
        if let Some(v) = kv.get("storage.wipe_keys") {
            if v != "on-stop" {
                return Err(bad("storage.wipe_keys", v, "on-stop"));
            }
        }

        let zone = Zone {
            description: get("zone.description").unwrap_or_default(),
            bridge: get("network.bridge"),
            volume: get("storage.volume"),
            seccomp: get("policy.seccomp"),
            landlock: get("policy.landlock"),
            memory_max: get("limits.memory_max"),
            pids_max,
            border_color: need("ui.border_color")?,
            name,
            network,
            storage,
        };

        zone.validate()?;
        Ok(zone)
    }

    /// Reject configurations that would silently weaken isolation.
    ///
    /// These are not style checks. Each one corresponds to a way a zone file
    /// could look reasonable while producing a zone that does not isolate.
    fn validate(&self) -> Result<(), ZoneError> {
        if self.name.is_empty() {
            return Err(ZoneError::Invalid("zone.name must not be empty".into()));
        }
        // The name becomes a namespace name, a cgroup path component, and an
        // interface suffix. Anything outside this set is a path-traversal or
        // interface-naming hazard.
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(ZoneError::Invalid(format!(
                "zone.name {:?} must be lowercase alphanumeric or '-' \
                 (it becomes a cgroup path and interface name)",
                self.name
            )));
        }
        // Linux interface names are capped at 15 bytes; "kv-" + name must fit.
        if self.name.len() > 12 {
            return Err(ZoneError::Invalid(format!(
                "zone.name {:?} is {} chars; max 12 so veth names fit IFNAMSIZ",
                self.name,
                self.name.len()
            )));
        }

        if self.storage == StorageMode::Encrypted && self.volume.is_none() {
            return Err(ZoneError::Invalid(format!(
                "zone {:?}: storage.mode is 'encrypted' but no storage.volume given",
                self.name
            )));
        }

        // A zone that owns the NIC must name the bridge it serves, or routed
        // zones have nothing to attach to.
        if self.network == NetworkMode::Nic && self.bridge.is_none() {
            return Err(ZoneError::Invalid(format!(
                "zone {:?}: network.mode is 'nic' but no network.bridge given",
                self.name
            )));
        }

        // The colour is how a human tells zones apart. An empty or malformed
        // one is a real isolation failure at the layer that matters most.
        if !is_hex_colour(&self.border_color) {
            return Err(ZoneError::Invalid(format!(
                "zone {:?}: ui.border_color {:?} is not #rrggbb",
                self.name, self.border_color
            )));
        }

        Ok(())
    }

    /// True when this zone gets a network namespace with no route out.
    pub fn is_airgapped(&self) -> bool {
        self.network == NetworkMode::None
    }
}

fn is_hex_colour(s: &str) -> bool {
    s.len() == 7
        && s.starts_with('#')
        && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Load every zone in a directory and check system-wide invariants.
pub fn load_all(dir: &Path) -> Result<Vec<Zone>, ZoneError> {
    let mut zones = Vec::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| ZoneError::Io(format!("{}: {e}", dir.display())))?;

    for entry in entries {
        let entry = entry.map_err(|e| ZoneError::Io(e.to_string()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        zones.push(Zone::from_file(&path)?);
    }

    zones.sort_by(|a, b| a.name.cmp(&b.name));
    check_invariants(&zones)?;
    Ok(zones)
}

/// Invariants that hold across the whole zone set, not within one file.
pub fn check_invariants(zones: &[Zone]) -> Result<(), ZoneError> {
    // Exactly one zone may hold the physical NIC. Two would mean two
    // independent paths to the network, and the `net` chokepoint that the
    // architecture depends on would not exist.
    let nic: Vec<&str> = zones
        .iter()
        .filter(|z| z.network == NetworkMode::Nic)
        .map(|z| z.name.as_str())
        .collect();

    match nic.len() {
        1 => {}
        0 => {
            return Err(ZoneError::Invalid(
                "no zone holds the physical NIC; routed zones would have no path out"
                    .into(),
            ))
        }
        _ => {
            return Err(ZoneError::Invalid(format!(
                "{} zones claim the physical NIC ({}); exactly one may. \
                 Two paths to the network means no chokepoint.",
                nic.len(),
                nic.join(", ")
            )))
        }
    }

    // Duplicate names would collide in cgroup paths and interface names.
    let mut seen = std::collections::HashSet::new();
    for z in zones {
        if !seen.insert(&z.name) {
            return Err(ZoneError::Invalid(format!("duplicate zone name {:?}", z.name)));
        }
    }

    // Duplicate colours defeat visual attribution, which docs/architecture.md
    // treats as load-bearing rather than cosmetic.
    let mut colours = HashMap::new();
    for z in zones {
        if let Some(prev) = colours.insert(z.border_color.clone(), z.name.clone()) {
            return Err(ZoneError::Invalid(format!(
                "zones {:?} and {:?} share border_color {} - \
                 a user could not tell them apart",
                prev, z.name, z.border_color
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: r##"..."## deliberately, not r#"..."#. The border colour value
    // contains the sequence "# which terminates a single-hash raw string
    // early. This is the same class of quoting bug the colour parser itself
    // has to handle in strip_comment().
    const VAULT: &str = r##"
[zone]
name = "vault"
description = "secrets"
[network]
mode = "none"
[storage]
mode = "encrypted"
volume = "/dev/kryptik/vault"
[limits]
pids_max = 128
[ui]
border_color = "#c9a227"
"##;

    #[test]
    fn parses_a_valid_zone() {
        let z = Zone::from_str(VAULT).expect("should parse");
        assert_eq!(z.name, "vault");
        assert_eq!(z.network, NetworkMode::None);
        assert_eq!(z.storage, StorageMode::Encrypted);
        assert_eq!(z.pids_max, Some(128));
        assert!(z.is_airgapped());
    }

    #[test]
    fn colour_with_hash_is_not_treated_as_a_comment() {
        let z = Zone::from_str(VAULT).unwrap();
        assert_eq!(z.border_color, "#c9a227");
    }

    #[test]
    fn encrypted_storage_requires_a_volume() {
        let bad = VAULT.replace("volume = \"/dev/kryptik/vault\"\n", "");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("storage.volume"), "got: {err}");
    }

    #[test]
    fn nic_mode_requires_a_bridge() {
        let bad = VAULT.replace("mode = \"none\"", "mode = \"nic\"");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("network.bridge"), "got: {err}");
    }

    #[test]
    fn rejects_path_traversal_in_name() {
        let bad = VAULT.replace("\"vault\"", "\"../../etc\"");
        assert!(Zone::from_str(&bad).is_err());
    }

    #[test]
    fn rejects_name_too_long_for_ifnamsiz() {
        let bad = VAULT.replace("\"vault\"", "\"averylongzonename\"");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("IFNAMSIZ"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_network_mode() {
        let bad = VAULT.replace("mode = \"none\"", "mode = \"host\"");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("network.mode"), "got: {err}");
    }

    #[test]
    fn rejects_bad_colour() {
        let bad = VAULT.replace("\"#c9a227\"", "\"gold\"");
        assert!(Zone::from_str(&bad).is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        let bad = format!("{VAULT}\n[ui]\nborder_color = \"#111111\"\n");
        assert!(Zone::from_str(&bad).is_err());
    }

    #[test]
    fn rejects_an_unparseable_limit_rather_than_dropping_it() {
        let bad = VAULT.replace("pids_max = 128", "pids_max = 0");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("limits.pids_max"), "got: {err}");
        let bad = VAULT.replace("pids_max = 128", "pids_max = \"many\"");
        assert!(Zone::from_str(&bad).is_err());
        let bad = VAULT.replace("pids_max = 128", "memory_max = \"2 gigs\"");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("limits.memory_max"), "got: {err}");
        let ok = VAULT.replace("pids_max = 128", "memory_max = \"2G\"");
        assert_eq!(Zone::from_str(&ok).unwrap().memory_max.as_deref(), Some("2G"));
        assert!(is_size("512M") && is_size("1G") && is_size("4096"));
        assert!(!is_size("0") && !is_size("") && !is_size("2GB") && !is_size("max"));
    }

    #[test]
    fn rejects_unknown_keys_rather_than_ignoring_them() {
        let bad = format!("{VAULT}\n[limits]\ncpu_max = 2\n");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("unknown key"), "got: {err}");
        let bad = format!("{VAULT}\n[storage]\nunlock = \"never\"\n");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("storage.unlock"), "got: {err}");
    }

    #[test]
    fn rejects_arrays_rather_than_ignoring_them() {
        let bad = VAULT.replace("pids_max = 128", "pids_max = [1, 2]");
        assert!(Zone::from_str(&bad).is_err());
    }

    fn zone_with(name: &str, mode: &str, colour: &str) -> Zone {
        let bridge = if mode == "nic" { "bridge = \"kryptik0\"\n" } else { "" };
        let text = format!(
            "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n{bridge}\
             [storage]\nmode = \"ephemeral\"\n[ui]\nborder_color = \"{colour}\"\n"
        );
        Zone::from_str(&text).unwrap()
    }

    #[test]
    fn exactly_one_zone_may_hold_the_nic() {
        let two = vec![
            zone_with("net", "nic", "#111111"),
            zone_with("net2", "nic", "#222222"),
        ];
        let err = check_invariants(&two).unwrap_err();
        assert!(format!("{err}").contains("claim the physical NIC"), "got: {err}");

        let none = vec![zone_with("work", "routed", "#111111")];
        assert!(check_invariants(&none).is_err());

        let one = vec![
            zone_with("net", "nic", "#111111"),
            zone_with("work", "routed", "#222222"),
        ];
        assert!(check_invariants(&one).is_ok());
    }

    #[test]
    fn duplicate_colours_are_rejected() {
        let zones = vec![
            zone_with("net", "nic", "#111111"),
            zone_with("work", "routed", "#111111"),
        ];
        let err = check_invariants(&zones).unwrap_err();
        assert!(format!("{err}").contains("border_color"), "got: {err}");
    }
}
