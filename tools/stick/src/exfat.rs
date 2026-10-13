//! exFAT, read only: the boot region, the FAT, the root's allocation bitmap, up-case table and
//! label, and each directory's entry sets (docs/design/removable-storage.md). Whoever had the
//! stick last wrote all of it, so every field is checked against the volume, and the volume
//! against the device, before anything is read or allocated by it: a set's checksum before any
//! of its fields, a cluster before it is read, a chain against the heap's cluster count.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::{here, local_name, on_stick, shown, DIR_ENTRIES_MAX, MALFORMED, MAX_DEPTH};

/// Directories are read this much at a time, so a walk holds no more per level.
const PIECE: usize = 4096;
/// The spec's largest up-case table: one 16-bit unit for each of 65536 characters.
const UPCASE_MAX: u64 = 131_072;
/// The spec's longest directory.
const DIR_MAX: u64 = 256 << 20;

fn bad(why: &str) -> String {
    format!("the stick's exFAT is malformed: {why}")
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from(le32(b, at)) | u64::from(le32(b, at + 4)) << 32
}

fn read_at<D: Read + Seek>(disk: &mut D, at: u64, buf: &mut [u8]) -> Result<(), String> {
    disk.seek(SeekFrom::Start(at)).and_then(|_| disk.read_exact(buf)).map_err(|e| format!("reading the stick: {e}"))
}

/// Whether the partition's first sector names exFAT.
pub fn is_exfat<D: Read + Seek>(disk: &mut D) -> io::Result<bool> {
    let mut name = [0u8; 8];
    disk.seek(SeekFrom::Start(3))?;
    let found = match disk.read_exact(&mut name) {
        Ok(()) => &name == b"EXFAT   ",
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => false,
        Err(e) => return Err(e),
    };
    disk.seek(SeekFrom::Start(0))?;
    Ok(found)
}

/// Where a file's or a directory's data lies: from its first cluster, along the FAT or straight
/// on, for its length; the root directory has none, and ends with its chain.
#[derive(Clone, Copy)]
struct Run {
    first: u32,
    len: Option<u64>,
    straight: bool,
}

/// How far a run has been read.
struct Reading {
    run: Run,
    cluster: u32,
    clusters: u64,
    offset: u64,
    done: u64,
}

impl Reading {
    fn new(run: Run) -> Reading {
        Reading { run, cluster: 0, clusters: 0, offset: 0, done: 0 }
    }
}

/// A directory's 32-byte entries, a piece at a time.
struct Slots {
    cur: Reading,
    buf: Vec<u8>,
    at: usize,
    len: usize,
}

impl Slots {
    fn new(run: Run) -> Slots {
        Slots { cur: Reading::new(run), buf: vec![0; PIECE], at: 0, len: 0 }
    }
}

/// What one command may read: no more entries than the heap has room for, nor bytes, nor
/// directory clusters, which a sound volume's walk reads once each. A directory that names an
/// ancestor, or a run of unused entries along a chain that loops, stops on the last.
struct Budget {
    entries: u64,
    bytes: u64,
    dir_clusters: u64,
}

impl Budget {
    fn entry(&mut self, n: &mut u64) -> Result<(), String> {
        *n += 1;
        if *n > DIR_ENTRIES_MAX {
            return Err(MALFORMED.into());
        }
        self.entries = self.entries.checked_sub(1).ok_or(MALFORMED)?;
        Ok(())
    }

    fn take(&mut self, bytes: u64) -> Result<(), String> {
        self.bytes = self.bytes.checked_sub(bytes).ok_or(MALFORMED)?;
        Ok(())
    }

    fn dir_cluster(&mut self) -> Result<(), String> {
        self.dir_clusters = self.dir_clusters.checked_sub(1).ok_or(MALFORMED)?;
        Ok(())
    }
}

/// A file or a directory, from an entry set that passed its checksum.
pub struct Entry {
    pub name: String,
    units: Vec<u16>,
    pub dir: bool,
    pub len: u64,
    valid: u64,
    run: Run,
}

pub struct ExFat<D> {
    disk: D,
    sector: u64,
    cluster: u64,
    fat: u64,
    heap: u64,
    count: u32,
    root: u32,
    active: u8,
    upcase: Vec<u16>,
    label: String,
    free: u64,
    cached: Option<(u64, Vec<u8>)>,
}

impl<D: Read + Seek> ExFat<D> {
    pub fn open(mut disk: D) -> Result<ExFat<D>, String> {
        let size = disk.seek(SeekFrom::End(0)).map_err(|e| format!("reading the stick: {e}"))?;
        let mut boot = [0u8; 512];
        read_at(&mut disk, 0, &mut boot)?;
        if &boot[3..11] != b"EXFAT   " {
            return Err("no exFAT filesystem".into());
        }
        if boot[510..512] != [0x55, 0xaa] || boot[11..64].iter().any(|&b| b != 0) {
            return Err(bad("its boot sector is not exFAT's"));
        }
        let (bps, spc) = (boot[108], boot[109]);
        if !(9..=12).contains(&bps) || spc > 25 - bps {
            return Err(bad("its sector or cluster size is out of range"));
        }
        let sector = 1u64 << bps;
        let cluster = sector << spc;
        let volume = le64(&boot, 72);
        let (fat_at, fat_len, heap_at) = (u64::from(le32(&boot, 80)), u64::from(le32(&boot, 84)), u64::from(le32(&boot, 88)));
        let (count, root, fats) = (le32(&boot, 92), le32(&boot, 96), u64::from(boot[110]));
        let active = (le16(&boot, 106) & 1) as u8;
        // Each sum below is of 32-bit fields times small powers of two: none overflows a u64.
        let inside = (1..=2).contains(&fats)
            && u64::from(active) < fats
            && fat_at >= 24
            && fat_len > 0
            && fat_at + fat_len * fats <= heap_at
            && (u64::from(count) + 2) * 4 <= fat_len * sector
            && (1..=0xffff_fff5).contains(&count)
            && heap_at + (u64::from(count) << spc) <= volume
            && volume.checked_mul(sector).is_some_and(|bytes| bytes <= size)
            && (2..=count + 1).contains(&root);
        if !inside {
            return Err(bad("its FAT, heap or root lie outside the volume, or the volume outside the stick"));
        }
        // The boot region's checksum, over its first eleven sectors less the fields that change.
        let mut region = vec![0u8; (sector * 12) as usize];
        read_at(&mut disk, 0, &mut region)?;
        let (sectors, check) = region.split_at((sector * 11) as usize);
        let mut sum = 0u32;
        for (i, &b) in sectors.iter().enumerate() {
            if i != 106 && i != 107 && i != 112 {
                sum = sum.rotate_right(1).wrapping_add(u32::from(b));
            }
        }
        if check.chunks(4).any(|c| le32(c, 0) != sum) {
            return Err(bad("its boot checksum does not match"));
        }
        let mut x = ExFat {
            disk,
            sector,
            cluster,
            fat: (fat_at + u64::from(active) * fat_len) * sector,
            heap: heap_at * sector,
            count,
            root,
            active,
            upcase: Vec::new(),
            label: String::new(),
            free: 0,
            cached: None,
        };
        x.read_root()?;
        Ok(x)
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn free(&self) -> u64 {
        self.free
    }

    fn budget(&self) -> Budget {
        let heap = u64::from(self.count) * self.cluster;
        Budget { entries: heap / 32 + DIR_ENTRIES_MAX, bytes: heap, dir_clusters: u64::from(self.count) }
    }

    fn root_run(&self) -> Run {
        Run { first: self.root, len: None, straight: false }
    }

    /// The FAT's entry for cluster c: the next of its chain, None at the chain's end.
    fn next(&mut self, c: u32) -> Result<Option<u32>, String> {
        let at = self.fat + u64::from(c) * 4;
        let base = at - at % self.sector;
        let fresh = match &self.cached {
            Some((b, _)) => *b != base,
            None => true,
        };
        if fresh {
            let mut s = vec![0u8; self.sector as usize];
            read_at(&mut self.disk, base, &mut s)?;
            self.cached = Some((base, s));
        }
        let v = match &self.cached {
            Some((_, s)) => le32(s, (at - base) as usize),
            None => unreachable!("the sector was just read"),
        };
        match v {
            0xffff_ffff => Ok(None),
            v if (2..=self.count + 1).contains(&v) => Ok(Some(v)),
            _ => Err(bad("a cluster chain leaves the heap")),
        }
    }

    /// Up to buf's length of a run's next bytes, within one cluster; 0 at the run's end.
    fn read_run(&mut self, c: &mut Reading, buf: &mut [u8]) -> Result<usize, String> {
        if c.run.len.is_some_and(|len| c.done >= len) {
            return Ok(0);
        }
        if c.cluster == 0 || c.offset == self.cluster {
            let next = if c.cluster == 0 {
                c.run.first
            } else if c.run.straight {
                c.cluster + 1
            } else {
                match self.next(c.cluster)? {
                    Some(n) => n,
                    None if c.run.len.is_none() => return Ok(0),
                    None => return Err(bad("a file or directory ends before its length")),
                }
            };
            if !(2..=self.count + 1).contains(&next) {
                return Err(bad("a file or directory lies outside the heap"));
            }
            c.clusters += 1;
            if c.clusters > u64::from(self.count) {
                return Err(bad("a cluster chain loops"));
            }
            c.cluster = next;
            c.offset = 0;
        }
        let mut n = (self.cluster - c.offset).min(buf.len() as u64);
        if let Some(len) = c.run.len {
            n = n.min(len - c.done);
        }
        let at = self.heap + u64::from(c.cluster - 2) * self.cluster + c.offset;
        read_at(&mut self.disk, at, &mut buf[..n as usize])?;
        c.offset += n;
        c.done += n;
        Ok(n as usize)
    }

    /// A directory's next entry, its cluster counted against the budget when one is entered.
    fn slot(&mut self, s: &mut Slots, budget: &mut Budget) -> Result<Option<[u8; 32]>, String> {
        if s.at == s.len {
            let before = s.cur.clusters;
            let n = self.read_run(&mut s.cur, &mut s.buf)?;
            if s.cur.clusters != before {
                budget.dir_cluster()?;
            }
            if n == 0 {
                return Ok(None);
            }
            if n % 32 != 0 {
                return Err(bad("a directory that is not whole entries"));
            }
            s.at = 0;
            s.len = n;
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(&s.buf[s.at..s.at + 32]);
        s.at += 32;
        Ok(Some(e))
    }

    /// The root's allocation bitmap, up-case table and label, each checked before it is read.
    fn read_root(&mut self) -> Result<(), String> {
        let mut budget = self.budget();
        let mut s = Slots::new(self.root_run());
        let (mut bitmap, mut upcase) = (None, None);
        while let Some(e) = self.slot(&mut s, &mut budget)? {
            match e[0] {
                0x00 => break,
                0x81 if e[1] & 1 == self.active => bitmap = Some((le32(&e, 20), le64(&e, 24))),
                0x82 => upcase = Some((le32(&e, 4), le32(&e, 20), le64(&e, 24))),
                0x83 => {
                    let n = usize::from(e[1]);
                    if n > 11 {
                        return Err(bad("its label is longer than 11 characters"));
                    }
                    let units: Vec<u16> = (0..n).map(|k| le16(&e, 2 + 2 * k)).collect();
                    self.label = String::from_utf16_lossy(&units);
                }
                _ => {}
            }
        }
        let (sum, first, len) = upcase.ok_or_else(|| bad("it has no up-case table"))?;
        if len == 0 || len > UPCASE_MAX || len % 2 != 0 {
            return Err(bad("its up-case table's length is impossible"));
        }
        let mut table = vec![0u8; len as usize];
        let mut c = Reading::new(Run { first, len: Some(len), straight: false });
        let mut at = 0;
        while at < table.len() {
            let n = self.read_run(&mut c, &mut table[at..])?;
            if n == 0 {
                return Err(bad("its up-case table ends before its length"));
            }
            at += n;
        }
        if table.iter().fold(0u32, |s, &b| s.rotate_right(1).wrapping_add(u32::from(b))) != sum {
            return Err(bad("its up-case table's checksum does not match"));
        }
        // Runs of characters that are their own capitals come as 0xffff and the run's length.
        let units: Vec<u16> = table.chunks(2).map(|c| le16(c, 0)).collect();
        let mut map: Vec<u16> = (0..=u16::MAX).collect();
        let (mut i, mut k) = (0usize, 0usize);
        while k < units.len() {
            if units[k] == 0xffff && k + 1 < units.len() {
                i += usize::from(units[k + 1]);
                k += 2;
            } else {
                *map.get_mut(i).ok_or_else(|| bad("its up-case table maps past U+FFFF"))? = units[k];
                i += 1;
                k += 1;
            }
            if i > map.len() {
                return Err(bad("its up-case table maps past U+FFFF"));
            }
        }
        self.upcase = map;

        let (first, len) = bitmap.ok_or_else(|| bad("it has no allocation bitmap"))?;
        let need = u64::from(self.count).div_ceil(8);
        if len < need || len > need + self.cluster {
            return Err(bad("its allocation bitmap's length does not fit its clusters"));
        }
        let mut c = Reading::new(Run { first, len: Some(need), straight: false });
        let (mut used, mut last, mut piece) = (0u64, 0u8, vec![0u8; PIECE]);
        loop {
            let n = self.read_run(&mut c, &mut piece)?;
            if n == 0 {
                break;
            }
            used += piece[..n].iter().map(|b| u64::from(b.count_ones())).sum::<u64>();
            last = piece[n - 1];
        }
        // The last byte's high bits lie past the last cluster, and are no cluster's.
        let spare = need * 8 - u64::from(self.count);
        if spare > 0 {
            used -= u64::from((last >> (8 - spare)).count_ones());
        }
        self.free = (u64::from(self.count) - used.min(u64::from(self.count))) * self.cluster;
        Ok(())
    }

    /// The next file or directory of the directory `s` reads, None at its end.
    fn entry(&mut self, s: &mut Slots, budget: &mut Budget) -> Result<Option<Entry>, String> {
        loop {
            let Some(e) = self.slot(s, budget)? else { return Ok(None) };
            match e[0] {
                0x00 => return Ok(None),
                t if t & 0x80 == 0 => continue,
                0x81..=0x83 => continue,
                0x85 => return self.file_set(e, s, budget).map(Some),
                t if t & 0x40 != 0 => return Err(bad("a secondary entry with no primary before it")),
                t if t & 0x20 != 0 => {
                    // A benign primary this reader has no use for, with its secondaries.
                    for _ in 0..e[1] {
                        if self.slot(s, budget)?.is_none() {
                            return Err(bad("an entry set runs off the end of its directory"));
                        }
                    }
                }
                _ => return Err(bad("an entry this reader does not know and may not skip")),
            }
        }
    }

    /// A file's entry set, read whole and its checksum verified before any field of it is used.
    fn file_set(&mut self, primary: [u8; 32], s: &mut Slots, budget: &mut Budget) -> Result<Entry, String> {
        let count = usize::from(primary[1]);
        if !(2..=18).contains(&count) {
            return Err(bad("a file's entry set is of an impossible size"));
        }
        let mut set = Vec::with_capacity(32 * (count + 1));
        set.extend_from_slice(&primary);
        for _ in 0..count {
            let e = self.slot(s, budget)?.ok_or_else(|| bad("an entry set runs off the end of its directory"))?;
            set.extend_from_slice(&e);
        }
        let mut sum = 0u16;
        for (i, &b) in set.iter().enumerate() {
            if i != 2 && i != 3 {
                sum = sum.rotate_right(1).wrapping_add(u16::from(b));
            }
        }
        if sum != le16(&primary, 2) {
            return Err(bad("a file's entry set fails its checksum"));
        }
        let stream = &set[32..64];
        if stream[0] != 0xc0 {
            return Err(bad("a file has no stream extension"));
        }
        let name_len = usize::from(stream[3]);
        let names = name_len.div_ceil(15);
        if name_len == 0 || 1 + names > count {
            return Err(bad("a file's name runs past its entry set"));
        }
        let mut units = Vec::with_capacity(name_len);
        for k in 0..names {
            let n = &set[64 + 32 * k..96 + 32 * k];
            if n[0] != 0xc1 {
                return Err(bad("a file's name entries are out of order"));
            }
            for j in 0..15 {
                if units.len() < name_len {
                    units.push(le16(n, 2 + 2 * j));
                }
            }
        }
        let (flags, valid, first, len) = (stream[1], le64(stream, 8), le32(stream, 20), le64(stream, 24));
        let dir = le16(&primary, 4) & 0x10 != 0;
        let straight = flags & 0x02 != 0;
        if valid > len {
            return Err(bad("a file's valid data is longer than the file"));
        }
        if len > 0 {
            if flags & 0x01 == 0 || !(2..=self.count + 1).contains(&first) {
                return Err(bad("a file's data lies outside the heap"));
            }
            let clusters = len.div_ceil(self.cluster);
            if clusters > u64::from(self.count) || (straight && u64::from(first) + clusters - 1 > u64::from(self.count) + 1) {
                return Err(bad("a file's data runs past the heap"));
            }
        }
        if dir && (len % 32 != 0 || len > DIR_MAX) {
            return Err(bad("a directory's length is impossible"));
        }
        // An unpaired surrogate is no character: it shows as U+FFFD, never as itself.
        let name = String::from_utf16_lossy(&units);
        Ok(Entry { name, units, dir, len, valid, run: Run { first, len: Some(len), straight } })
    }

    /// Names compare as exFAT compares them, through the volume's own up-case table.
    fn same(&self, a: &[u16], b: &[u16]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| self.upcase[usize::from(x)] == self.upcase[usize::from(y)])
    }

    /// The entry PATH names, its directories walked within the budget; None for the root.
    fn find(&mut self, path: &str, budget: &mut Budget) -> Result<Option<Entry>, String> {
        let mut found: Option<Entry> = None;
        for part in on_stick(path).split('/').filter(|p| !p.is_empty()) {
            let run = match found.take() {
                None => self.root_run(),
                Some(e) if e.dir => e.run,
                Some(_) => return Err(format!("{}: not a directory", shown(path))),
            };
            let want: Vec<u16> = part.encode_utf16().collect();
            let mut s = Slots::new(run);
            let mut n = 0;
            while let Some(e) = self.entry(&mut s, budget)? {
                budget.entry(&mut n)?;
                if self.same(&e.units, &want) {
                    found = Some(e);
                    break;
                }
            }
            if found.is_none() {
                return Err(format!("{}: not on the stick", shown(path)));
            }
        }
        Ok(found)
    }

    /// A directory's entries: name, whether a directory, length.
    pub fn entries(&mut self, dir: &str) -> Result<Vec<(String, bool, u64)>, String> {
        let mut budget = self.budget();
        let run = match self.find(dir, &mut budget)? {
            None => self.root_run(),
            Some(e) if e.dir => e.run,
            Some(_) => return Err(format!("{}: not a directory", shown(dir))),
        };
        let (mut s, mut out, mut n) = (Slots::new(run), Vec::new(), 0);
        while let Some(e) = self.entry(&mut s, &mut budget)? {
            budget.entry(&mut n)?;
            out.push((e.name, e.dir, e.len));
        }
        Ok(out)
    }

    /// PATH copied off the stick: into DEST when it is a directory, else as DEST; the bytes copied.
    pub fn get(&mut self, path: &str, dest: &Path) -> Result<u64, String> {
        let mut budget = self.budget();
        let p = on_stick(path);
        let name = p.rsplit('/').next().unwrap_or(p);
        let target = if dest.is_dir() && !p.is_empty() { dest.join(local_name(name)?) } else { dest.to_path_buf() };
        match self.find(path, &mut budget)? {
            None => {
                let root = self.root_run();
                self.copy_dir_out(root, &target, 0, &mut budget)
            }
            Some(e) if e.dir => self.copy_dir_out(e.run, &target, 0, &mut budget),
            Some(e) => self.copy_file_out(&e, &target, &mut budget),
        }
    }

    fn copy_dir_out(&mut self, run: Run, to: &Path, depth: usize, budget: &mut Budget) -> Result<u64, String> {
        if depth > MAX_DEPTH {
            return Err(format!("{}: directories nested more than {MAX_DEPTH} deep", here(to)));
        }
        fs::create_dir(to).map_err(|e| format!("{}: {e}", here(to)))?;
        let (mut s, mut copied, mut n) = (Slots::new(run), 0, 0);
        while let Some(e) = self.entry(&mut s, budget)? {
            budget.entry(&mut n)?;
            let target = to.join(local_name(&e.name)?);
            copied += if e.dir { self.copy_dir_out(e.run, &target, depth + 1, budget)? } else { self.copy_file_out(&e, &target, budget)? };
        }
        Ok(copied)
    }

    /// A file of the stick copied to `to`, which must not exist yet; past its valid data it reads
    /// as zeros, whatever its clusters hold.
    fn copy_file_out(&mut self, e: &Entry, to: &Path, budget: &mut Budget) -> Result<u64, String> {
        budget.take(e.len)?;
        let mut out = fs::OpenOptions::new().write(true).create_new(true).open(to).map_err(|err| format!("{}: {err}", here(to)))?;
        let (mut c, mut buf, mut done) = (Reading::new(e.run), vec![0u8; 65_536], 0u64);
        loop {
            let n = self.read_run(&mut c, &mut buf)?;
            if n == 0 {
                break;
            }
            let keep = e.valid.saturating_sub(done).min(n as u64) as usize;
            buf[keep..n].fill(0);
            out.write_all(&buf[..n]).map_err(|err| format!("{}: {err}", here(to)))?;
            done += n as u64;
        }
        Ok(done)
    }
}

#[cfg(test)]
mod tests;
