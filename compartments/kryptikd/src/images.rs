//! Software images over a zone's /usr (docs/design/software-delivery.md). A list the release key
//! signs in `kryptik-image` names each image's dm-verity root hash for one root. kryptikd opens
//! the images a zone file names, over that root alone, and the zone binds one read-only overlay
//! of them over zone 0's /usr. Every start checks the list again, as nobody.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::policy::{self, Policy};
use crate::zone::Zone;

pub const MAGIC: &str = "KRYPTIK-IMAGES-1";
/// Images and the lists that name them, on the state partition, root's alone.
pub const STORE: &str = "/var/lib/kryptik/images";
/// Byte limits for the list and its signature, as for a release manifest.
const LIST_MAX: u64 = 64 * 1024;
const SIG_MAX: u64 = 8 * 1024;
/// Where each opened image is mounted, and where each set of them is stacked over /usr.
const MOUNTS: &str = "/run/kryptik/images";
const SETS: &str = "/run/kryptik/usr";
/// One start at a time opens images, so two never race for one mapping.
const LOCK: &str = "/run/kryptik/images.lock";
/// The largest image taken: the state partition holds every zone's data beside it.
const IMAGE_MAX: u64 = 16 << 30;
const BLOCK: u64 = 4096;

/// One image, as the signed list gives it.
#[derive(Debug, Clone, PartialEq)]
pub struct Image {
    pub name: String,
    pub version: String,
    /// The whole file: the data, then its hash tree.
    pub bytes: u64,
    pub sha256: String,
    pub data_blocks: u64,
    pub root_hash: String,
    pub salt: String,
}

/// The signed list of images built over one root.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub release: String,
    /// The root hash of the root the images were built over.
    pub base: String,
    pub images: Vec<Image>,
    /// The images each image is built over (`requires:`), which a zone naming it must name too.
    pub requires: Vec<(String, Vec<String>)>,
    /// Each image's policy-file lines: what a zone's policy must grant before it gets the image.
    pub needs: Vec<(String, String)>,
}

/// An image's name, as a zone file and the store's paths use it.
pub fn valid_name(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn version_ok(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Digits alone, with no leading zero.
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The list, line by line as stage 06 writes it; anything else is refused, not skipped.
pub fn parse(text: &str) -> Result<Manifest, String> {
    let body = text.strip_suffix('\n').ok_or("the image list does not end with a newline")?;
    let mut lines = body.split('\n');
    if lines.next() != Some(MAGIC) {
        return Err(format!("the image list is not a {MAGIC}"));
    }
    let field = |line: Option<&str>, key: &str| -> Result<String, String> {
        line.and_then(|l| l.strip_prefix(key))
            .and_then(|l| l.strip_prefix(": "))
            .map(str::to_string)
            .ok_or_else(|| format!("the image list has no {key} line where one belongs"))
    };
    let release = field(lines.next(), "release")?;
    if !version_ok(&release) {
        return Err(format!("the image list's release {release:?} is not a version"));
    }
    let base = field(lines.next(), "base")?;
    if !hex64(&base) {
        return Err("the image list's base is not a root hash".into());
    }
    let mut images: Vec<Image> = Vec::new();
    let mut requires: Vec<(String, Vec<String>)> = Vec::new();
    let mut needs: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("image: ") {
            if !requires.is_empty() || !needs.is_empty() {
                return Err("an image line follows the requires or needs lines".into());
            }
            let img = image_line(rest)?;
            // Sorted, which also keeps one line per image.
            if images.last().is_some_and(|last| last.name >= img.name) {
                return Err(format!("image {} is out of order or listed twice", img.name));
            }
            images.push(img);
        } else if let Some(rest) = line.strip_prefix("requires: ") {
            if !needs.is_empty() {
                return Err("a requires line follows the needs lines".into());
            }
            let mut words = rest.split(' ');
            let name = words.next().unwrap_or_default();
            let reqs: Vec<String> = words.map(str::to_string).collect();
            let at = images
                .iter()
                .position(|i| i.name == name)
                .ok_or_else(|| format!("a requires line names {name:?}, which the list does not hold"))?;
            if reqs.is_empty() {
                return Err(format!("the requires line for {name} names no image"));
            }
            for (k, r) in reqs.iter().enumerate() {
                if r == name || !images.iter().any(|i| &i.name == r) || reqs[..k].contains(r) {
                    return Err(format!("image {name} requires {r:?}, which is not another image the list holds"));
                }
            }
            // In image order, one line per image.
            let last = requires.last().and_then(|(n, _)| images.iter().position(|i| &i.name == n));
            if last.is_some_and(|l| l >= at) {
                return Err(format!("the requires line for {name} is out of order or repeated"));
            }
            requires.push((name.to_string(), reqs));
        } else if let Some(rest) = line.strip_prefix("needs: ") {
            let (name, what) = rest.split_once(' ').ok_or_else(|| format!("{line:?} names no policy line"))?;
            let at = images
                .iter()
                .position(|i| i.name == name)
                .ok_or_else(|| format!("a needs line names {name:?}, which the list does not hold"))?;
            let last = needs.last().and_then(|(n, _)| images.iter().position(|i| &i.name == n));
            if last.is_some_and(|l| l > at) {
                return Err(format!("the needs lines for {name} are not with their image's"));
            }
            policy::parse(what, "the image list").map_err(|e| e.to_string())?;
            needs.push((name.to_string(), what.to_string()));
        } else {
            return Err(format!("unexpected line {line:?} in the image list"));
        }
    }
    if images.is_empty() {
        return Err("the image list names no image".into());
    }
    Ok(Manifest { release, base, images, requires, needs })
}

fn image_line(rest: &str) -> Result<Image, String> {
    let bad = || format!("{rest:?} is not `NAME VERSION bytes= sha256= data-blocks= root-hash= salt=`");
    let words: Vec<&str> = rest.split(' ').collect();
    let &[name, version, bytes, sha256, data_blocks, root_hash, salt] = words.as_slice() else {
        return Err(bad());
    };
    if !valid_name(name) || !version_ok(version) {
        return Err(bad());
    }
    let value = |w: &str, key: &str| w.strip_prefix(key).and_then(|v| v.strip_prefix('=')).map(str::to_string);
    let img = Image {
        name: name.to_string(),
        version: version.to_string(),
        bytes: value(bytes, "bytes").as_deref().and_then(number).ok_or_else(bad)?,
        sha256: value(sha256, "sha256").filter(|h| hex64(h)).ok_or_else(bad)?,
        data_blocks: value(data_blocks, "data-blocks").as_deref().and_then(number).ok_or_else(bad)?,
        root_hash: value(root_hash, "root-hash").filter(|h| hex64(h)).ok_or_else(bad)?,
        salt: value(salt, "salt").filter(|h| hex64(h)).ok_or_else(bad)?,
    };
    // The data, then its hash tree, in whole blocks, and nothing past the cap.
    let data = img.data_blocks.checked_mul(BLOCK).filter(|d| *d > 0);
    if !data.is_some_and(|d| img.bytes > d) || img.bytes % BLOCK != 0 || img.bytes > IMAGE_MAX {
        return Err(format!(
            "image {}: {} bytes cannot hold {} data blocks and their hash tree",
            img.name, img.bytes, img.data_blocks
        ));
    }
    Ok(img)
}

/// The running root's dm-verity root hash, from the signed kernel's command line: the word after
/// `sha256` in the verity table of `dm-mod.create`'s root device.
pub fn root_hash_from(cmdline: &str) -> Option<String> {
    const KEY: &str = "dm-mod.create=\"";
    let start = cmdline.find(KEY)? + KEY.len();
    let end = start + cmdline[start..].find('"')?;
    let table = cmdline[start..end].split(';').find(|d| d.starts_with("kroot,"))?;
    let mut words = table.split_whitespace().skip_while(|w| *w != "verity");
    words.find(|w| *w == "sha256")?;
    words.next().filter(|h| hex64(h)).map(str::to_string)
}

/// Whether the zone's policy grants every line the list says `image` needs: an image widens
/// nothing, and a line the base policy already allows needs no grant.
pub fn needs_met(m: &Manifest, image: &str, granted: Option<&Policy>) -> Result<(), String> {
    fn holds(want: &[String], have: Option<&Vec<String>>) -> bool {
        want.iter().all(|w| have.is_some_and(|h| h.contains(w)))
    }
    for (_, line) in m.needs.iter().filter(|(n, _)| n == image) {
        let need = policy::parse(line, "the image list").map_err(|e| e.to_string())?;
        let ok = holds(&need.extra_syscall_names, granted.map(|p| &p.extra_syscall_names))
            && holds(&need.socket_names, granted.map(|p| &p.socket_names))
            && holds(&need.netlink_names, granted.map(|p| &p.netlink_names))
            && holds(&need.keep_cap_names, granted.map(|p| &p.keep_cap_names));
        if !ok {
            return Err(format!("image {image:?} needs `{line}`, which the zone's policy file does not grant"));
        }
    }
    Ok(())
}

/// Whether a zone that names `named` also names every image each of them is built over.
pub fn requires_met(m: &Manifest, named: &[String]) -> Result<(), String> {
    for (image, reqs) in m.requires.iter().filter(|(i, _)| named.contains(i)) {
        if let Some(r) = reqs.iter().find(|r| !named.contains(r)) {
            return Err(format!("image {image:?} is built over {r:?}, which the zone does not name"));
        }
    }
    Ok(())
}

/// Where a set of images is stacked: one directory per set, whichever zone asks for it.
pub fn set_dir(images: &[&Image]) -> String {
    let parts: Vec<String> = images.iter().map(|i| format!("{}-{}", i.name, &i.root_hash[..16])).collect();
    format!("{SETS}/{}", parts.join("+"))
}

/// Open the images `zone` names over the root this kernel runs and stack them over /usr, in name
/// order: the directory the zone binds as its /usr.
pub fn prepare(zone: &Zone, granted: Option<&Policy>) -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("only a root launch opens software images".into());
    }
    let _one = crate::update::lock(Path::new(LOCK))?;
    let cmdline = fs::read_to_string("/proc/cmdline").map_err(|e| format!("/proc/cmdline: {e}"))?;
    let base = root_hash_from(&cmdline)
        .ok_or("this kernel's command line names no verity root, so no image can be matched to it")?;
    let m = verified_list(&base)?;
    let chosen: Vec<&Image> = m.images.iter().filter(|i| zone.images.contains(&i.name)).collect();
    for name in &zone.images {
        if !chosen.iter().any(|i| &i.name == name) {
            return Err(format!("the image list for this root ({}) holds no image {name:?}", m.release));
        }
        needs_met(&m, name, granted)?;
    }
    requires_met(&m, &zone.images)?;
    let mut lower: Vec<String> = Vec::new();
    for img in &chosen {
        lower.push(format!("{}/usr", open(img)?));
    }
    lower.push("/usr".into());
    let set = set_dir(&chosen);
    let lowerdir = format!("lowerdir={}", lower.join(":"));
    let mounts = fs::read_to_string("/proc/self/mounts").map_err(|e| format!("/proc/self/mounts: {e}"))?;
    if !stacked(&mounts, &set, &lowerdir)? {
        fs::create_dir_all(&set).map_err(|e| format!("{set}: {e}"))?;
        // No redirect in a lower layer is followed, though no image is built with one.
        mount("kryptik-usr", &set, "overlay", Some(format!("{lowerdir},redirect_dir=nofollow").as_str()))?;
    }
    Ok(set)
}

/// Whether the set at `at` is mounted already with exactly `lowerdir` (use it), not at all (stack
/// it), or over other images (refused): a set's name holds 64 bits of each root hash, the mounts
/// in its lowerdir the whole hash. `mounts` is /proc/self/mounts; the topmost mount at `at` counts.
fn stacked(mounts: &str, at: &str, lowerdir: &str) -> Result<bool, String> {
    let options = mounts
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 4 && f[1] == at).then(|| f[3])
        })
        .last();
    match options {
        None => Ok(false),
        Some(o) if o.split(',').any(|x| x == lowerdir) => Ok(true),
        Some(_) => Err(format!("{at} already stacks other images than these")),
    }
}

/// The list for `base`, read once, its signature checked as nobody on a copy of those bytes.
fn verified_list(base: &str) -> Result<Manifest, String> {
    let list = Path::new(STORE).join(format!("{base}.manifest"));
    let text = read_bounded(&list, LIST_MAX)
        .map_err(|e| format!("no software images are kept for this root ({}...): {e}", &base[..12]))?;
    let sig = read_bounded(&list.with_extension("manifest.sig"), SIG_MAX)?;
    signed(&text, &sig).map_err(|e| format!("the image list for this root is refused: {e}"))?;
    let m = parse(std::str::from_utf8(&text).map_err(|_| "the image list is not text".to_string())?)?;
    if m.base != base {
        return Err(format!("the image list kept for this root is for another root ({})", m.release));
    }
    Ok(m)
}

/// Whether `sig` signs `text` as an image list, checked as nobody on a copy of these bytes.
fn signed(text: &[u8], sig: &[u8]) -> Result<(), String> {
    let dir = crate::update::make_scratch(Path::new("/run/kryptik"))?;
    let checked = fs::write(dir.join("manifest"), text)
        .and_then(|_| fs::write(dir.join("manifest.sig"), sig))
        .map_err(|e| format!("{}: {e}", dir.display()))
        .and_then(|_| crate::update::check_images(&dir));
    let _ = fs::remove_dir_all(&dir);
    checked.map(|_| ())
}

/// A medium's images.manifest and images.manifest.sig in `dir`, checked as the installer has them
/// before it writes anything: signed as an image list, read as a kept list is, for the root `base`
/// it installs, and naming only images `dir` holds as NAME.img at the size the list signs. Each
/// image's hash is checked as it is copied (image-store.sh).
pub fn check_medium(dir: &Path, base: &str) -> Result<String, String> {
    check_medium_with(dir, base, &signed)
}

fn check_medium_with(dir: &Path, base: &str, check: &dyn Fn(&[u8], &[u8]) -> Result<(), String>) -> Result<String, String> {
    let text = read_bounded(&dir.join("images.manifest"), LIST_MAX)?;
    let sig = read_bounded(&dir.join("images.manifest.sig"), SIG_MAX)?;
    check(&text, &sig).map_err(|e| format!("the medium's image list is refused: {e}"))?;
    let m = parse(std::str::from_utf8(&text).map_err(|_| "the image list is not text".to_string())?)?;
    if m.base != base {
        return Err(format!("the medium's image list ({}) is for another root than the one it installs", m.release));
    }
    for img in &m.images {
        let file = dir.join(format!("{}.img", img.name));
        let md = fs::metadata(&file).map_err(|e| format!("image {}: {}: {e}", img.name, file.display()))?;
        if !md.is_file() || md.len() != img.bytes {
            return Err(format!("image {}: {} holds {} bytes, and the list signs {}", img.name, file.display(), md.len(), img.bytes));
        }
    }
    Ok(format!("{} images of release {} for this root\n", m.images.len(), m.release))
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let f = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    f.take(max + 1).read_to_end(&mut bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > max {
        return Err(format!("{} is larger than {max} bytes", path.display()));
    }
    Ok(bytes)
}

/// Open one image with dm-verity and mount it read-only: where it is mounted.
fn open(img: &Image) -> Result<String, String> {
    let file = PathBuf::from(format!("{STORE}/{}/{}.img", img.name, img.root_hash));
    let shown = file.display().to_string();
    let md = fs::symlink_metadata(&file).map_err(|e| format!("image {}: {shown}: {e}", img.name))?;
    if !md.file_type().is_file() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(format!("image {}: {shown} is not a regular file only root writes", img.name));
    }
    if md.len() != img.bytes {
        return Err(format!("image {}: {shown} holds {} bytes, and the list signs {}", img.name, md.len(), img.bytes));
    }
    // The whole root hash: at most 111 characters, inside device-mapper's 127.
    let mapper = format!("kryptik-image-{}-{}", img.name, img.root_hash);
    let dev = format!("/dev/mapper/{mapper}");
    if Path::new(&dev).exists() {
        // dm-verity marks a mapping corrupted at the first block that reads back other than signed.
        let status = crate::volume::run("veritysetup status", "veritysetup", &["status", mapper.as_str()], None).map_err(|e| e.1)?;
        if status.lines().any(|l| l.split_whitespace().eq(["status:", "corrupted"])) {
            return Err(format!(
                "image {} read back other than signed while in use, so it is not used again until this machine restarts",
                img.name
            ));
        }
    } else {
        let blocks = format!("--data-blocks={}", img.data_blocks);
        let offset = format!("--hash-offset={}", img.data_blocks * BLOCK);
        let salt = format!("--salt={}", img.salt);
        let args: [&str; 12] = [
            "open", "--no-superblock", "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096",
            &blocks, &offset, &salt, &shown, &mapper, &shown, &img.root_hash,
        ];
        crate::volume::run("veritysetup open", "veritysetup", &args, None).map_err(|e| format!("image {}: {}", img.name, e.1))?;
    }
    let at = format!("{MOUNTS}/{}/{}", img.name, img.root_hash);
    if !crate::volume::is_mountpoint(&at) {
        fs::create_dir_all(&at).map_err(|e| format!("{at}: {e}"))?;
        // A journal is never replayed: the device under it is read-only.
        mount(&dev, &at, "ext4", Some("noload"))?;
    }
    if !Path::new(&at).join("usr").is_dir() {
        return Err(format!("image {} holds no usr directory to stack over /usr", img.name));
    }
    Ok(at)
}

/// Read-only, with no set-id programs and no device files, whatever the image holds.
fn mount(src: &str, at: &str, fstype: &str, data: Option<&str>) -> Result<(), String> {
    let c = |s: &str| std::ffi::CString::new(s).map_err(|_| format!("{s:?} holds a NUL"));
    let (src_c, at_c, fs_c) = (c(src)?, c(at)?, c(fstype)?);
    let data_c = data.map(c).transpose()?;
    let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    let data_p = data_c.as_ref().map_or(std::ptr::null(), |d| d.as_ptr().cast());
    if unsafe { libc::mount(src_c.as_ptr(), at_c.as_ptr(), fs_c.as_ptr(), flags, data_p) } < 0 {
        return Err(format!("mount {fstype} at {at}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
