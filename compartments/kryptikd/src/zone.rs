//! Zone definitions, parsed by hand to keep dependencies to `libc` (ADR-010).
//! A malformed file is an error, never a weaker zone.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::broker::TRANSFER_MAX;

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
    /// A plain host directory kept between launches; not encrypted at rest, and reports say so.
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
    /// The `nic` zone's interface (`nic = "eth0"`), or `"*"` for every physical one.
    pub nic: Option<String>,
    /// `[network] local = true`: the nic zone lets this routed zone reach the
    /// networks its uplinks sit on; every other routed zone is refused them
    /// (tools/net/netzone-init.sh reads the same key).
    pub local: bool,
    pub storage: StorageMode,
    pub volume: Option<String>,
    pub seccomp: Option<String>,
    pub landlock: Option<String>,
    /// Required bound on an ephemeral zone's tmpfs, which could otherwise fill host memory.
    pub size: Option<String>,
    pub memory_max: Option<String>,
    pub pids_max: Option<u32>,
    /// A percentage of one CPU (`"150%"`), enforced by cgroup cpu.max.
    pub cpu_max: Option<String>,
    /// Bytes per second each way on the zone's volume (io.max), so encrypted zones only.
    pub io_max: Option<String>,
    pub border_color: String,
    /// Never drawn: only checked here, and `zoneid audit` gives it no weight.
    pub border_pattern: Option<String>,
    /// Glyph and label identify the zone without colour, in the chrome menu.
    pub glyph: Option<String>,
    pub label: Option<String>,
    /// Host uid the zone's root maps to (nobody to it + 65534); declared, not derived from zone
    /// order, so adding a zone never changes who owns another's files. None: a root launch needs
    /// `--zone-uid/--zone-gid`, and `check --target` refuses it.
    pub uid_base: Option<u32>,
    /// `[transfer] to = "work personal"`: zones this one may send files to; never the nic zone.
    pub transfer_to: Vec<String>,
    /// `[transfer] max_bytes = N`: the largest file this zone sends or
    /// receives through the broker, at most its cap. None: the cap alone.
    pub transfer_max: Option<u64>,
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
    "network.mode", "network.nic", "network.local",
    "storage.mode", "storage.volume", "storage.size",
    "policy.seccomp", "policy.landlock",
    "limits.memory_max", "limits.pids_max", "limits.cpu_max", "limits.io_max",
    "identity.uid_base",
    "transfer.to", "transfer.max_bytes",
    "ui.border_color", "ui.border_pattern", "ui.glyph", "ui.label",
];

/// A percentage of one CPU, digits then `%`, at least 1; None for anything else.
pub fn parse_cpu_max(s: &str) -> Option<u32> {
    let digits = s.strip_suffix('%')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().filter(|n| *n > 0)
}

/// Bytes as digits with an optional K, M, G or T; None for zero, "max", other text or overflow.
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

/// Flat TOML: `[section]`, `key = value` (quoted string, integer or boolean) and `#` comments;
/// arrays and nested tables are errors, not ignored.
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
        if let Some(v) = kv.get("limits.cpu_max") {
            if parse_cpu_max(v).is_none() {
                return Err(bad("limits.cpu_max", v, "a percentage of one CPU such as 50% or 200%"));
            }
        }
        if let Some(v) = kv.get("limits.io_max") {
            if parse_size(v).is_none() {
                return Err(bad("limits.io_max", v, "bytes per second such as 20M"));
            }
            if storage != StorageMode::Encrypted {
                return Err(ZoneError::Invalid(format!(
                    "zone {name:?}: limits.io_max bounds reads and writes of the zone's volume, \
                     and this zone has none (storage.mode is not \"encrypted\")"
                )));
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
            // The kernel's rule (dev_valid_name), kept to printable ASCII so no NUL cuts it short.
            let ok = |b: u8| b.is_ascii_graphic() && b != b'/' && b != b':';
            if n.is_empty() || n.len() > 15 || n == "." || n == ".." || !n.bytes().all(ok) {
                return Err(bad("network.nic", n, "an interface name of at most 15 characters, or \"*\" for every physical interface"));
            }
            if network != NetworkMode::Nic {
                return Err(ZoneError::Invalid(format!(
                    "zone {name:?}: network.nic is only meaningful for network.mode = \"nic\""
                )));
            }
        }

        let local = match kv.get("network.local").map(String::as_str) {
            None => false,
            Some(_) if network != NetworkMode::Routed => {
                return Err(ZoneError::Invalid(format!(
                    "zone {name:?}: network.local is only meaningful for network.mode = \"routed\""
                )))
            }
            Some("true") => true,
            Some("false") => false,
            Some(v) => return Err(bad("network.local", v, "true or false")),
        };

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
        // Digits alone, so no sign or unit, and never past the broker's cap.
        let transfer_max = match kv.get("transfer.max_bytes") {
            None => None,
            Some(v) => match v.parse::<u64>() {
                Ok(n @ 1..=TRANSFER_MAX) if v.bytes().all(|b| b.is_ascii_digit()) => Some(n),
                _ => {
                    return Err(bad(
                        "transfer.max_bytes",
                        v,
                        &format!("a whole number of bytes from 1 to {TRANSFER_MAX}"),
                    ))
                }
            },
        };

        let zone = Zone {
            nic,
            uid_base,
            transfer_to,
            transfer_max,
            description: get("zone.description").unwrap_or_default(),
            volume: get("storage.volume"),
            size: get("storage.size"),
            seccomp: get("policy.seccomp"),
            landlock: get("policy.landlock"),
            memory_max: get("limits.memory_max"),
            pids_max,
            cpu_max: get("limits.cpu_max"),
            io_max: get("limits.io_max"),
            // One spelling, so the duplicate check sees #AA3333 and #aa3333 as one colour.
            border_color: need("ui.border_color")?.to_ascii_lowercase(),
            border_pattern: get("ui.border_pattern"),
            glyph: get("ui.glyph"),
            label: get("ui.label"),
            name,
            network,
            local,
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
        if self.storage == StorageMode::Persistent && self.volume.is_some() {
            return Err(ZoneError::Invalid(format!(
                "zone {:?}: storage.volume is only meaningful for storage.mode = \
                 \"encrypted\". A persistent zone keeps its data in a plain directory \
                 under the zone root; it does not open {:?}. If this zone was meant to \
                 be encrypted, say so - kryptikd will refuse to start it until \
                 `kryptikd volume init` has made its volume, which is the point.",
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
        // Shape only, as zoneid checks it.
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
        // Printable ASCII rules out bidi controls and homographs.
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
        // The broker and the net zone open <name>.toml; a file named otherwise gets no transfer.
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
    // Transfer targets must be configured zones, never the nic zone; duplicates are refused below.
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

    // The broker and compositor proxy tell zones apart by uid; aligned bases never overlap.
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
mod tests;
