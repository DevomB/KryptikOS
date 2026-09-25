//! Zone definitions: parsing and validation.
//!
//! A hand-written parser rather than a TOML crate, to keep dependencies to
//! `libc` (ADR-010). A malformed file is an error, never a weaker zone.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

/// How a zone reaches the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Loopback only: no interface to misconfigure, no firewall rule to drop.
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
    /// A plain directory on the host filesystem, kept between launches. Not
    /// encrypted at rest, and every report of this mode says so.
    Persistent,
}

impl StorageMode {
    fn parse(s: &str) -> Result<Self, ZoneError> {
        match s {
            "encrypted" => Ok(StorageMode::Encrypted),
            "ephemeral" => Ok(StorageMode::Ephemeral),
            "persistent" => Ok(StorageMode::Persistent),
            other => Err(ZoneError::BadValue {
                field: "storage.mode".into(),
                value: other.into(),
                expected: "encrypted | ephemeral | persistent".into(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Zone {
    pub name: String,
    pub description: String,
    pub network: NetworkMode,
    /// Interface a `nic` zone takes (`nic = "eth0"`), or `"*"` for every
    /// physical one (`netzone::physical_interfaces`). Refused for other modes.
    pub nic: Option<String>,
    pub storage: StorageMode,
    pub volume: Option<String>,
    pub seccomp: Option<String>,
    pub landlock: Option<String>,
    /// Upper bound on an ephemeral zone's tmpfs: required for ephemeral,
    /// refused otherwise. Unbounded, a zone could fill host memory with files.
    pub size: Option<String>,
    pub memory_max: Option<String>,
    pub pids_max: Option<u32>,
    pub border_color: String,
    /// Non-colour identity (`border_pattern`, `glyph`, `label`) for users who
    /// cannot tell the colours apart. Only the shape is checked here; `zoneid
    /// audit` decides whether the set is distinguishable.
    pub border_pattern: Option<String>,
    pub glyph: Option<String>,
    pub label: Option<String>,
    /// Host identity range, `[identity] uid_base = N`: a privileged launch maps
    /// root to N and nobody to N + 65534. Declared, not derived from zone order,
    /// so adding a zone never changes who owns another's files. `None`: a root
    /// launch needs `--zone-uid/--zone-gid`, and `check --target` refuses it.
    pub uid_base: Option<u32>,
    /// `[transfer] to = "work personal"`: zones this one may send files to via
    /// the broker. Never the nic zone (`check_invariants`).
    pub transfer_to: Vec<String>,
}

/// Smallest `identity.uid_base`; every base is a multiple of `IDENTITY_STRIDE`.
pub const IDENTITY_MIN: u32 = 131072;
pub const IDENTITY_STRIDE: u32 = 65536;

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

/// Every key a zone file may contain; any other is refused, not ignored.
pub const KNOWN_KEYS: &[&str] = &[
    "zone.name", "zone.description",
    "network.mode", "network.nic",
    "storage.mode", "storage.volume", "storage.size",
    "policy.seccomp", "policy.landlock",
    "limits.memory_max", "limits.pids_max",
    "identity.uid_base",
    "transfer.to",
    "ui.border_color", "ui.border_pattern", "ui.glyph", "ui.label",
];

/// A byte size as a zone file, cgroup memory.max and `volume init --size`
/// take it: digits with an optional K, M, G or T. None for zero, for
/// anything else (so not "max": omit the key), and on overflow.
pub fn parse_size(s: &str) -> Option<u64> {
    let (digits, shift) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 10),
        b'M' | b'm' => (&s[..s.len() - 1], 20),
        b'G' | b'g' => (&s[..s.len() - 1], 30),
        b'T' | b't' => (&s[..s.len() - 1], 40),
        _ => (s, 0),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok().filter(|&n| n > 0)?.checked_mul(1 << shift)
}

/// Minimal TOML reader: `[section]`, `key = value` (quoted string, integer or
/// boolean) and `#` comments. Arrays and nested tables are errors, not ignored.
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

/// Strip a trailing `#` comment outside quotes, so "#c9a227" survives.
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
        // An unparseable limit is an error, never "no limit".
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
            if parse_size(v).is_none() {
                return Err(bad("limits.memory_max", v, "a size such as 512M or 2G"));
            }
        }
        // storage.size: required for ephemeral, refused where kryptikd cannot enforce it.
        match storage {
            StorageMode::Ephemeral => match kv.get("storage.size") {
                None => {
                    return Err(ZoneError::Invalid(format!(
                        "zone {:?}: storage.mode is \"ephemeral\" but no storage.size given. \
                         An ephemeral zone's data lives in a tmpfs, and an unbounded tmpfs \
                         lets the zone consume host memory by writing files - which the \
                         memory limit does not stop, because those pages outlive the writer.",
                        name
                    )))
                }
                Some(v) if parse_size(v).is_none() => {
                    return Err(bad("storage.size", v, "a size such as 512M or 2G"))
                }
                Some(v) => {
                    /* tmpfs pages are charged to the zone's memcg, so a tmpfs
                     * larger than memory_max never fills: the OOM kill comes first. */
                    if let Some(m) = kv.get("limits.memory_max") {
                        match (parse_size(v), parse_size(m)) {
                            (Some(sz), Some(mm)) if sz > mm => {
                                return Err(ZoneError::Invalid(format!(
                                    "zone {name:?}: storage.size = {v:?} is larger than \
                                     limits.memory_max = {m:?}. The tmpfs is charged to the \
                                     zone's memory limit, so it can never reach {v}: the zone \
                                     would be OOM-killed first. Lower storage.size, or raise \
                                     memory_max."
                                )))
                            }
                            _ => {}
                        }
                    }
                }
            },
            StorageMode::Encrypted => {
                if kv.contains_key("storage.size") {
                    return Err(ZoneError::Invalid(format!(
                        "zone {:?}: storage.size is only meaningful for storage.mode = \
                         \"ephemeral\"; an encrypted zone is sized by its volume",
                        name
                    )));
                }
            }
            StorageMode::Persistent => {
                // Nothing would enforce it: a host directory with no quota.
                if kv.contains_key("storage.size") {
                    return Err(ZoneError::Invalid(format!(
                        "zone {:?}: storage.size is only meaningful for storage.mode = \
                         \"ephemeral\". A persistent zone writes into a directory on the \
                         host filesystem, and kryptikd does not impose a quota on it - \
                         so a size here would be a limit that is not in force.",
                        name
                    )));
                }
            }
        }

        let uid_base = match kv.get("identity.uid_base") {
            None => None,
            Some(v) => {
                let n = v.parse::<u32>().ok().ok_or_else(|| {
                    bad("identity.uid_base", v, "an unsigned integer")
                })?;
                if n < IDENTITY_MIN
                    || n % IDENTITY_STRIDE != 0
                    || n.checked_add(IDENTITY_STRIDE - 1).is_none()
                {
                    return Err(bad(
                        "identity.uid_base",
                        v,
                        "a multiple of 65536, at least 131072, with room for a 65536-wide range",
                    ));
                }
                Some(n)
            }
        };

        let nic = get("network.nic");
        if let Some(n) = &nic {
            if n.is_empty() || n.len() > 15 || n.contains('/') || n.contains(char::is_whitespace) {
                return Err(bad("network.nic", n, "an interface name of at most 15 characters, or \"*\" for every physical interface"));
            }
            if network != NetworkMode::Nic {
                return Err(ZoneError::Invalid(format!(
                    "zone {name:?}: network.nic is only meaningful for network.mode = \"nic\""
                )));
            }
        }

        let transfer_to: Vec<String> = match get("transfer.to") {
            None => Vec::new(),
            Some(v) => {
                let mut out: Vec<String> = Vec::new();
                for n in v.split_whitespace() {
                    if !n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                        return Err(bad("transfer.to", &v, "space-separated zone names"));
                    }
                    if n == name {
                        return Err(ZoneError::Invalid(format!(
                            "zone {name:?}: [transfer] to names the zone itself"
                        )));
                    }
                    if out.iter().any(|o| o == n) {
                        return Err(ZoneError::Invalid(format!(
                            "zone {name:?}: [transfer] to names {n:?} twice"
                        )));
                    }
                    out.push(n.to_string());
                }
                if out.is_empty() {
                    return Err(bad(
                        "transfer.to",
                        &v,
                        "at least one zone name, or omit [transfer] to send nothing",
                    ));
                }
                out
            }
        };

        let zone = Zone {
            nic,
            uid_base,
            transfer_to,
            description: get("zone.description").unwrap_or_default(),
            volume: get("storage.volume"),
            size: get("storage.size"),
            seccomp: get("policy.seccomp"),
            landlock: get("policy.landlock"),
            memory_max: get("limits.memory_max"),
            pids_max,
            // One spelling, so the duplicate check sees #AA3333 and #aa3333 as one colour.
            border_color: need("ui.border_color")?.to_ascii_lowercase(),
            border_pattern: get("ui.border_pattern"),
            glyph: get("ui.glyph"),
            label: get("ui.label"),
            name,
            network,
            storage,
        };

        zone.validate()?;
        Ok(zone)
    }

    /// Reject configurations that would silently weaken isolation.
    fn validate(&self) -> Result<(), ZoneError> {
        if self.name.is_empty() {
            return Err(ZoneError::Invalid("zone.name must not be empty".into()));
        }
        // The name goes into cgroup paths and interface names.
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
        // A persistent zone is a directory and opens no volume.
        if self.storage == StorageMode::Persistent && self.volume.is_some() {
            return Err(ZoneError::Invalid(format!(
                "zone {:?}: storage.volume is only meaningful for storage.mode = \
                 \"encrypted\". A persistent zone keeps its data in a plain directory \
                 under the zone root; it does not open {:?}. If this zone was meant to \
                 be encrypted, say so - kryptikd will refuse to start it until encrypted \
                 volumes exist, which is the point.",
                self.name,
                self.volume.as_deref().unwrap_or("")
            )));
        }

        // The colour is how the user tells zones apart.
        if !is_hex_colour(&self.border_color) {
            return Err(ZoneError::Invalid(format!(
                "zone {:?}: ui.border_color {:?} is not #rrggbb",
                self.name, self.border_color
            )));
        }
        /* Shape only, as zoneid checks it. A printable-ASCII label rules out
         * bidi controls and homographs. */
        if let Some(p) = &self.border_pattern {
            const PATTERNS: [&str; 6] = ["solid", "dashed", "dotted", "double", "dash-dot", "notched"];
            if !PATTERNS.contains(&p.as_str()) {
                return Err(ZoneError::Invalid(format!(
                    "zone {:?}: ui.border_pattern {:?} is not one of {}",
                    self.name, p, PATTERNS.join(", ")
                )));
            }
        }
        if let Some(g) = &self.glyph {
            if g.chars().count() != 1 || g.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(ZoneError::Invalid(format!(
                    "zone {:?}: ui.glyph {:?} must be exactly one printable character",
                    self.name, g
                )));
            }
        }
        if let Some(l) = &self.label {
            if l.is_empty() || l.len() > 12 || !l.chars().all(|c| matches!(c, ' '..='~')) || l.starts_with(' ') || l.ends_with(' ') {
                return Err(ZoneError::Invalid(format!(
                    "zone {:?}: ui.label {:?} must be 1-12 printable ASCII characters, unpadded",
                    self.name, l
                )));
            }
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
        let zone = Zone::from_file(&path)?;
        /* The broker and the net zone open a zone as <name>.toml, so a file
         * named otherwise would launch but never receive a transfer. */
        if path.file_stem().and_then(|s| s.to_str()) != Some(zone.name.as_str()) {
            return Err(ZoneError::Invalid(format!(
                "{}: holds zone {:?}; a zone's file is named {}.toml",
                path.display(),
                zone.name,
                zone.name
            )));
        }
        zones.push(zone);
    }

    zones.sort_by(|a, b| a.name.cmp(&b.name));
    check_invariants(&zones)?;
    Ok(zones)
}

/// Invariants that hold across the whole zone set, not within one file.
pub fn check_invariants(zones: &[Zone]) -> Result<(), ZoneError> {
    /* [transfer] to must name configured zones, never the nic zone. First
     * occurrence wins; duplicate names are refused below. */
    let mut by_name: HashMap<&str, &Zone> = HashMap::with_capacity(zones.len());
    for z in zones {
        by_name.entry(z.name.as_str()).or_insert(z);
    }
    for z in zones {
        for d in &z.transfer_to {
            match by_name.get(d.as_str()) {
                None => {
                    return Err(ZoneError::Invalid(format!(
                        "zone {:?}: [transfer] to names {d:?}, which is not a zone",
                        z.name
                    )))
                }
                Some(o) if o.network == NetworkMode::Nic => {
                    return Err(ZoneError::Invalid(format!(
                        "zone {:?}: [transfer] to names {d:?}, the zone that holds the NIC; \
                         it receives nothing, ever",
                        z.name
                    )))
                }
                Some(_) => {}
            }
        }
    }
    // Exactly one zone holds the NIC: the single path to the network.
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

    /* Zones sharing a range could not be told apart by uid (broker, compositor
     * proxy). Bases are stride-aligned, so distinct bases never overlap. */
    let mut bases: HashMap<u32, &str> = HashMap::new();
    for z in zones {
        if let Some(b) = z.uid_base {
            if let Some(prev) = bases.insert(b, &z.name) {
                return Err(ZoneError::Invalid(format!(
                    "zones {:?} and {:?} both declare identity.uid_base = {b}; \
                     identity ranges must not overlap",
                    prev, z.name
                )));
            }
        }
    }

    // Duplicate colours defeat visual attribution (docs/architecture.md).
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

    // r##: the colour's `"#` would end a single-hash raw string.
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
    fn parses_valid_zone() {
        let z = Zone::from_str(VAULT).expect("should parse");
        assert_eq!(z.name, "vault");
        assert_eq!(z.network, NetworkMode::None);
        assert_eq!(z.storage, StorageMode::Encrypted);
        assert_eq!(z.pids_max, Some(128));
        assert!(z.is_airgapped());
    }

    #[test]
    fn hash_in_colour_is_not_comment() {
        let z = Zone::from_str(VAULT).unwrap();
        assert_eq!(z.border_color, "#c9a227");
    }

    #[test]
    fn tmpfs_larger_than_memory_max_refused() {
        let toml = r##"
[zone]
name = "z"
description = "d"
[network]
mode = "none"
[storage]
mode = "ephemeral"
size = "64M"
[limits]
memory_max = "48M"
[ui]
border_color = "#000000"
"##;
        let err = Zone::from_str(toml).expect_err("64M of tmpfs under a 48M cap must be refused");
        let msg = format!("{err}");
        assert!(msg.contains("storage.size"), "the message must name the key: {msg}");
        assert!(msg.contains("memory_max"), "and the limit it conflicts with: {msg}");

        // The other way round is fine.
        let ok = toml.replace("size = \"64M\"", "size = \"32M\"");
        Zone::from_str(&ok).expect("32M under a 48M cap is a sensible pair");
    }

    fn with_transfer(name: &str, mode: &str, to: Option<&str>) -> Result<Zone, ZoneError> {
        let t = to.map(|v| format!("[transfer]\nto = \"{v}\"\n")).unwrap_or_default();
        // Distinct colours, or check_invariants refuses the set.
        let colour = format!("#1234{:02x}", name.bytes().next().unwrap_or(0));
        Zone::from_str(&format!(
            "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{t}[ui]\nborder_color = \"{colour}\"\n"
        ))
    }

    #[test]
    fn transfer_to_validates_names() {
        assert!(with_transfer("a", "none", None).unwrap().transfer_to.is_empty());
        assert_eq!(with_transfer("a", "none", Some("b c")).unwrap().transfer_to, vec!["b", "c"]);
        for bad in ["a", "b b", "", "B", "../x", "b/c"] {
            assert!(with_transfer("a", "none", Some(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn transfer_targets_exist_and_are_not_nic() {
        let set = |to: &str| {
            vec![
                with_transfer("n", "nic", None).unwrap(),
                with_transfer("b", "none", None).unwrap(),
                with_transfer("a", "none", Some(to)).unwrap(),
            ]
        };
        check_invariants(&set("b")).unwrap();
        let e = check_invariants(&set("zzz")).unwrap_err().to_string();
        assert!(e.contains("not a zone"), "{e}");
        let e = check_invariants(&set("n")).unwrap_err().to_string();
        assert!(e.contains("receives nothing"), "{e}");
    }

    fn persistent(extra: &str) -> Result<Zone, ZoneError> {
        Zone::from_str(&format!(
            "[zone]\nname = \"keeper\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"persistent\"\n{extra}[ui]\nborder_color = \"#123456\"\n"
        ))
    }

    #[test]
    fn persistent_zone_needs_no_volume() {
        let z = persistent("").expect("persistent should be a valid mode");
        assert_eq!(z.storage, StorageMode::Persistent);
        assert_eq!(z.volume, None);
        assert_eq!(z.size, None);
        z.validate().expect("a bare persistent zone is complete as written");
    }

    #[test]
    fn persistent_zone_refuses_size() {
        let e = persistent("size = \"512M\"\n").expect_err("size must be refused");
        let m = e.to_string();
        assert!(m.contains("not in force"), "say why, not just no: {m}");
    }

    #[test]
    fn persistent_zone_refuses_volume() {
        let e = persistent("volume = \"/dev/kryptik/keeper\"\n")
            .expect_err("a persistent zone opens no volume");
        let m = e.to_string();
        assert!(m.contains("/dev/kryptik/keeper"), "name the device: {m}");
        assert!(
            m.contains("refuse"),
            "point at the encrypted mode that WOULD be refused, so the reader learns \
             the difference rather than deleting the line: {m}"
        );
    }

    #[test]
    fn unknown_storage_mode_lists_persistent() {
        let e = Zone::from_str(
            "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"durable\"\n[ui]\nborder_color = \"#123456\"\n",
        )
        .expect_err("durable is not a mode");
        assert!(e.to_string().contains("persistent"), "offer it: {e}");
    }

    #[test]
    fn encrypted_storage_requires_volume() {
        let bad = VAULT.replace("volume = \"/dev/kryptik/vault\"\n", "");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("storage.volume"), "got: {err}");
    }

    #[test]
    fn only_nic_zone_names_interface() {
        let ok = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nnic = \"eth0\"");
        assert_eq!(Zone::from_str(&ok).unwrap().nic.as_deref(), Some("eth0"));
        // "*": every physical interface of zone 0, decided at launch.
        let all = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nnic = \"*\"");
        assert_eq!(Zone::from_str(&all).unwrap().nic.as_deref(), Some("*"));
        let bad = VAULT.replace("mode = \"none\"", "mode = \"none\"\nnic = \"eth0\"");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("only meaningful"), "got: {err}");
        let bad = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nnic = \"averylongname123\"");
        assert!(Zone::from_str(&bad).is_err());
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
    fn rejects_unparseable_limit() {
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
        assert_eq!(parse_size("32M"), Some(32 << 20));
        assert_eq!(parse_size("1g"), Some(1 << 30));
        assert_eq!(parse_size("2T"), Some(2 << 40));
        assert_eq!(parse_size("4096"), Some(4096));
        for bad in ["0", "0M", "", "M", "2GB", "max", "+5", "-5", "1.5G", "17179869184G", "18446744073709551615K"] {
            assert_eq!(parse_size(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn rejects_unknown_keys() {
        for extra in ["[limits]\ncpu_max = 2", "[storage]\nunlock = \"on-start\"", "[network]\nbridge = \"kryptik0\""] {
            let err = Zone::from_str(&format!("{VAULT}\n{extra}\n")).unwrap_err();
            assert!(format!("{err}").contains("unknown key"), "{extra}: {err}");
        }
    }

    #[test]
    fn file_named_for_zone() {
        let dir = std::env::temp_dir().join(format!("kryptik-stem-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // A set needs one zone holding the NIC.
        let net = "[zone]\nname = \"net\"\n[network]\nmode = \"nic\"\n\
                   [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n";
        fs::write(dir.join("net.toml"), net).unwrap();
        fs::write(dir.join("10-vault.toml"), VAULT).unwrap();
        let err = load_all(&dir).unwrap_err();
        assert!(format!("{err}").contains("named vault.toml"), "got: {err}");
        fs::rename(dir.join("10-vault.toml"), dir.join("vault.toml")).unwrap();
        assert_eq!(load_all(&dir).unwrap().len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn colour_case_ignored() {
        let a = zone_with("a", "none", "#AA3333");
        let b = zone_with("b", "none", "#aa3333");
        assert!(check_invariants(&[a, b]).is_err());
    }

    #[test]
    fn identity_base_aligned_above_floor() {
        for bad in ["1000", "100000", "131073", "196607", "0", "\"x\""] {
            let t = VAULT.replace("[ui]", &format!("[identity]\nuid_base = {bad}\n[ui]"));
            let err = Zone::from_str(&t).unwrap_err();
            assert!(format!("{err}").contains("identity.uid_base"), "{bad}: {err}");
        }
        for ok in ["131072", "196608", "4294901760"] {
            let t = VAULT.replace("[ui]", &format!("[identity]\nuid_base = {ok}\n[ui]"));
            assert_eq!(Zone::from_str(&t).unwrap().uid_base, Some(ok.parse().unwrap()), "{ok}");
        }
        // 4294901760 is the last base with room for a full range.
        assert!(Zone::from_str(&VAULT.replace("[ui]", "[identity]\nuid_base = 4294967295\n[ui]")).is_err());
        assert_eq!(Zone::from_str(VAULT).unwrap().uid_base, None);
    }

    #[test]
    fn identity_ranges_must_not_collide() {
        let with = |name: &str, colour: &str, base: u32| {
            let text = format!(
                "[zone]\nname = \"{name}\"\n[network]\nmode = \"routed\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n\
                 [identity]\nuid_base = {base}\n[ui]\nborder_color = \"{colour}\"\n"
            );
            Zone::from_str(&text).unwrap()
        };
        let nic = zone_with("net", "nic", "#111111");
        let err = check_invariants(&[nic.clone(), with("a", "#222222", 131072), with("b", "#333333", 131072)]).unwrap_err();
        assert!(format!("{err}").contains("identity ranges must not overlap"), "{err}");
        assert!(check_invariants(&[nic, with("a", "#222222", 131072), with("b", "#333333", 196608)]).is_ok());
    }

    #[test]
    fn rejects_arrays() {
        let bad = VAULT.replace("pids_max = 128", "pids_max = [1, 2]");
        assert!(Zone::from_str(&bad).is_err());
    }

    fn zone_with(name: &str, mode: &str, colour: &str) -> Zone {
        let text = format!(
            "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"256M\"\n[ui]\nborder_color = \"{colour}\"\n"
        );
        Zone::from_str(&text).unwrap()
    }

    #[test]
    fn exactly_one_nic_zone() {
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
