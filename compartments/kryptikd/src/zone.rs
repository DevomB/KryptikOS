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
    /// A plain directory on the host filesystem, kept between launches.
    ///
    /// Persistence and nothing else: the data is NOT encrypted at rest, and
    /// every place that reports this mode says so. It exists because
    /// "encrypted" is not implemented and refusing to start is the right
    /// answer for a zone that asked for encryption - which left no way at all
    /// to keep a file, and made ephemeral the only working mode. Someone who
    /// needs their editor to still have the document tomorrow is better served
    /// by storage they understand than by a mode that lies.
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
    pub bridge: Option<String>,
    /// The physical interface a `nic` zone takes ownership of (`[network]
    /// nic = "eth0"`). Required for mode = "nic", refused otherwise.
    pub nic: Option<String>,
    pub storage: StorageMode,
    pub volume: Option<String>,
    pub seccomp: Option<String>,
    pub landlock: Option<String>,
    /// Upper bound on an ephemeral zone's tmpfs. Required for ephemeral,
    /// refused for encrypted and persistent: an unbounded tmpfs is a zone that can exhaust
    /// host memory by writing files, which the cgroup memory limit does NOT
    /// catch - tmpfs pages outlive the process that wrote them and are charged
    /// to whoever touches them next.
    pub size: Option<String>,
    pub memory_max: Option<String>,
    pub pids_max: Option<u32>,
    pub border_color: String,
    /// The zone's fixed host identity range: `[identity] uid_base = N`.
    ///
    /// A privileged launch maps the zone's root to host uid/gid N and its
    /// `nobody` to N + 65534; the whole 65536-wide range is reserved to the
    /// zone. Declared in the zone file, never derived from zone order, so
    /// adding a zone can never change which host uid owns another zone's
    /// files. `None` means a root launch must name an identity with
    /// `--zone-uid/--zone-gid`, and is refused on the target (`check --target`).
    pub uid_base: Option<u32>,
}

/// Smallest permitted `identity.uid_base`, and the alignment every base must
/// have. 131072 = 2 * 65536: the first aligned range clear of the host's own
/// users and of the conventional first subordinate range.
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

/// Every key a zone file may contain. Anything else is refused: a key that is
/// parsed and ignored is a setting the operator believes is in force.
pub const KNOWN_KEYS: &[&str] = &[
    "zone.name", "zone.description",
    "network.mode", "network.bridge", "network.nic",
    "storage.mode", "storage.volume", "storage.size", "storage.unlock", "storage.wipe_keys",
    "policy.seccomp", "policy.landlock",
    "limits.memory_max", "limits.pids_max",
    "identity.uid_base",
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

/// A validated size as bytes, for comparing two of them.
///
/// Deliberately separate from cgroup::parse_memory_max: this one is about the
/// relationship between two values in a zone file, runs during parsing, and
/// must not pull the cgroup module into zone validation. Returns None rather
/// than erroring - is_size has already accepted the shape, and a value too
/// large to compare is caught where it is applied.
fn size_bytes(v: &str) -> Option<u64> {
    let (digits, mult) = match v.as_bytes().last() {
        Some(b'K') | Some(b'k') => (&v[..v.len() - 1], 1024u64),
        Some(b'M') | Some(b'm') => (&v[..v.len() - 1], 1024 * 1024),
        Some(b'G') | Some(b'g') => (&v[..v.len() - 1], 1024 * 1024 * 1024),
        Some(b'T') | Some(b't') => (&v[..v.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (v, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
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
        // storage.size: required for ephemeral, refused for the two modes
        // whose size kryptikd does not control.
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
                Some(v) if !is_size(v) => {
                    return Err(bad("storage.size", v, "a size such as 512M or 2G"))
                }
                Some(v) => {
                    // A tmpfs bigger than the zone's memory limit cannot ever
                    // reach its stated size: its pages are charged to the
                    // zone's memcg, so the OOM group-kill fires first. Two
                    // limits where only one can bind misleads the operator
                    // about which one is in force, so say so at parse time
                    // rather than at the OOM (security R-7c).
                    if let Some(m) = kv.get("limits.memory_max") {
                        match (size_bytes(v), size_bytes(m)) {
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
                // A persistent zone writes into a directory on a filesystem
                // kryptikd did not create and does not control. Accepting a
                // size here would record a bound nothing enforces, and the
                // operator would believe the zone could not fill the disk.
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
                return Err(bad("network.nic", n, "an interface name of at most 15 characters"));
            }
            if network != NetworkMode::Nic {
                return Err(ZoneError::Invalid(format!(
                    "zone {name:?}: network.nic is only meaningful for network.mode = \"nic\""
                )));
            }
        }

        let zone = Zone {
            nic,
            uid_base,
            description: get("zone.description").unwrap_or_default(),
            bridge: get("network.bridge"),
            volume: get("storage.volume"),
            size: get("storage.size"),
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
        // storage.volume names the block device an encrypted zone unlocks. A
        // persistent zone has no volume - it is a directory - so a volume line
        // here is either a leftover from the encrypted zone this one was
        // copied from, or a belief that the data lands somewhere it does not.
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

    // Two zones with the same identity range would own each other's files on
    // the host and could not be told apart by anything that authenticates by
    // uid (the broker, the compositor proxy). Bases are aligned to the stride,
    // so distinct bases are disjoint ranges; equality is the whole check.
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
    fn a_tmpfs_larger_than_the_memory_limit_is_refused() {
        // R-7c. Both limits are valid on their own; together only one of them
        // can ever bind, and the operator has no way to tell which.
        // r##"..."## and not r#"..."#: the border colour contains `"#`, which
        // is exactly the sequence that would close a single-hash raw string.
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

        // The same file with the sizes the other way round is fine.
        let ok = toml.replace("size = \"64M\"", "size = \"32M\"");
        Zone::from_str(&ok).expect("32M under a 48M cap is a sensible pair");
    }

    // ---- storage.mode = "persistent" ------------------------------------
    //
    // The mode exists because refusing an "encrypted" zone is right and left
    // nothing that keeps a file. These check that it keeps its own promise
    // narrow: persistence, and no claim about what protects it.

    fn persistent(extra: &str) -> Result<Zone, ZoneError> {
        Zone::from_str(&format!(
            "[zone]\nname = \"keeper\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"persistent\"\n{extra}[ui]\nborder_color = \"#123456\"\n"
        ))
    }

    #[test]
    fn a_persistent_zone_parses_and_needs_no_volume() {
        let z = persistent("").expect("persistent should be a valid mode");
        assert_eq!(z.storage, StorageMode::Persistent);
        assert_eq!(z.volume, None);
        assert_eq!(z.size, None);
        z.validate().expect("a bare persistent zone is complete as written");
    }

    #[test]
    fn a_persistent_zone_refuses_a_size_it_would_not_enforce() {
        // The zone writes into a directory on a filesystem kryptikd neither
        // made nor controls. Accepting a size would record a bound nothing
        // applies, and the operator would believe the zone was capped.
        let e = persistent("size = \"512M\"\n").expect_err("size must be refused");
        let m = e.to_string();
        assert!(m.contains("not in force"), "say why, not just no: {m}");
    }

    #[test]
    fn a_persistent_zone_refuses_a_volume_that_would_never_be_opened() {
        // from_str validates, so the refusal lands here rather than later.
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
    fn an_unknown_storage_mode_lists_persistent_among_the_choices() {
        let e = Zone::from_str(
            "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"durable\"\n[ui]\nborder_color = \"#123456\"\n",
        )
        .expect_err("durable is not a mode");
        assert!(e.to_string().contains("persistent"), "offer it: {e}");
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
    fn only_the_nic_zone_may_name_an_interface_and_it_must_be_a_name() {
        let ok = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nbridge = \"kryptik0\"\nnic = \"eth0\"");
        assert_eq!(Zone::from_str(&ok).unwrap().nic.as_deref(), Some("eth0"));
        let bad = VAULT.replace("mode = \"none\"", "mode = \"none\"\nnic = \"eth0\"");
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("only meaningful"), "got: {err}");
        let bad = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nbridge = \"kryptik0\"\nnic = \"averylongname123\"");
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
        assert_eq!(size_bytes("32M"), Some(32 * 1024 * 1024));
        assert_eq!(size_bytes("1G"), Some(1024 * 1024 * 1024));
        assert!(size_bytes("64M").unwrap() > size_bytes("48M").unwrap());
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
    fn identity_base_is_aligned_and_above_the_floor() {
        for bad in ["1000", "100000", "131073", "196607", "0", "\"x\""] {
            let t = VAULT.replace("[ui]", &format!("[identity]\nuid_base = {bad}\n[ui]"));
            let err = Zone::from_str(&t).unwrap_err();
            assert!(format!("{err}").contains("identity.uid_base"), "{bad}: {err}");
        }
        for ok in ["131072", "196608", "4294901760"] {
            let t = VAULT.replace("[ui]", &format!("[identity]\nuid_base = {ok}\n[ui]"));
            assert_eq!(Zone::from_str(&t).unwrap().uid_base, Some(ok.parse().unwrap()), "{ok}");
        }
        // 4294967296 - 65536 = 4294901760 is the last base with room; one
        // stride above it does not fit in a u32.
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
    fn rejects_arrays_rather_than_ignoring_them() {
        let bad = VAULT.replace("pids_max = 128", "pids_max = [1, 2]");
        assert!(Zone::from_str(&bad).is_err());
    }

    fn zone_with(name: &str, mode: &str, colour: &str) -> Zone {
        let bridge = if mode == "nic" { "bridge = \"kryptik0\"\n" } else { "" };
        let text = format!(
            "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n{bridge}\
             [storage]\nmode = \"ephemeral\"\nsize = \"256M\"\n[ui]\nborder_color = \"{colour}\"\n"
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
