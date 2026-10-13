use super::*;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 512-byte sectors and 4 KiB clusters on a 2 MiB volume: the FAT in sectors 24-31, the heap's
/// 508 clusters from sector 32, the bitmap in cluster 2, the up-case table in 3, the root in 4.
const SECTOR: usize = 512;
const CLUSTER: usize = 4096;
const COUNT: u32 = 508;

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn at(cluster: u32) -> usize {
    32 * SECTOR + (cluster as usize - 2) * CLUSTER
}

fn set_checksum(set: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in set.iter().enumerate() {
        if i != 2 && i != 3 {
            sum = sum.rotate_right(1).wrapping_add(u16::from(b));
        }
    }
    sum
}

/// A file's or directory's entry set, its checksum made as a formatter makes it.
fn file_set(name: &[u16], dir: bool, first: u32, len: u64, valid: u64, straight: bool) -> Vec<u8> {
    let names = name.len().div_ceil(15);
    let mut set = vec![0u8; 32 * (2 + names)];
    set[0] = 0x85;
    set[1] = (1 + names) as u8;
    put16(&mut set, 4, if dir { 0x10 } else { 0x20 });
    set[32] = 0xc0;
    set[33] = match (len, straight) {
        (0, _) => 0,
        (_, true) => 3,
        (_, false) => 1,
    };
    set[35] = name.len() as u8;
    put64(&mut set, 40, valid);
    put32(&mut set, 52, first);
    put64(&mut set, 56, len);
    for (k, part) in name.chunks(15).enumerate() {
        set[64 + 32 * k] = 0xc1;
        for (j, &u) in part.iter().enumerate() {
            put16(&mut set, 64 + 32 * k + 2 + 2 * j, u);
        }
    }
    let sum = set_checksum(&set);
    put16(&mut set, 2, sum);
    set
}

fn units(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}

/// A volume made here as a formatter makes one, the root's entries written in order.
struct Image {
    b: Vec<u8>,
    next: u32,
    root_at: usize,
}

impl Image {
    fn new() -> Image {
        let mut b = vec![0u8; 4096 * SECTOR];
        b[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        b[3..11].copy_from_slice(b"EXFAT   ");
        put64(&mut b, 72, 4096);
        put32(&mut b, 80, 24);
        put32(&mut b, 84, 8);
        put32(&mut b, 88, 32);
        put32(&mut b, 92, COUNT);
        put32(&mut b, 96, 4);
        put16(&mut b, 104, 0x0100);
        (b[108], b[109], b[110], b[111]) = (9, 3, 1, 0x80);
        (b[510], b[511]) = (0x55, 0xaa);
        let fat = 24 * SECTOR;
        put32(&mut b, fat, 0xffff_fff8);
        put32(&mut b, fat + 4, 0xffff_ffff);
        let mut img = Image { b, next: 5, root_at: at(4) };
        for c in 2..=4 {
            img.chain(&[c]);
        }
        // a to z capitalized, every other character its own capital
        let mut up = vec![0xffff, 97];
        up.extend(65u16..=90);
        up.extend([0xffff, 65_413]);
        let table: Vec<u8> = up.iter().flat_map(|u| u.to_le_bytes()).collect();
        img.b[at(3)..at(3) + table.len()].copy_from_slice(&table);
        let sum = table.iter().fold(0u32, |s, &x| s.rotate_right(1).wrapping_add(u32::from(x)));
        let mut label = [0u8; 32];
        label[0] = 0x83;
        label[1] = 6;
        for (k, u) in "KSTICK".encode_utf16().enumerate() {
            put16(&mut label, 2 + 2 * k, u);
        }
        img.root(&label);
        let mut bitmap = [0u8; 32];
        bitmap[0] = 0x81;
        put32(&mut bitmap, 20, 2);
        put64(&mut bitmap, 24, u64::from(COUNT.div_ceil(8)));
        img.root(&bitmap);
        let mut upcase = [0u8; 32];
        upcase[0] = 0x82;
        put32(&mut upcase, 4, sum);
        put32(&mut upcase, 20, 3);
        put64(&mut upcase, 24, table.len() as u64);
        img.root(&upcase);
        img
    }

    fn root(&mut self, entries: &[u8]) {
        self.b[self.root_at..self.root_at + entries.len()].copy_from_slice(entries);
        self.root_at += entries.len();
    }

    /// Clusters marked used in the bitmap and chained in the FAT, in the order given.
    fn chain(&mut self, clusters: &[u32]) {
        for (k, &c) in clusters.iter().enumerate() {
            let next = clusters.get(k + 1).copied().unwrap_or(0xffff_ffff);
            put32(&mut self.b, 24 * SECTOR + 4 * c as usize, next);
            self.b[at(2) + (c as usize - 2) / 8] |= 1 << ((c - 2) % 8);
        }
    }

    /// Clusters for `data`, straight on, written and marked used; the first of them.
    fn data(&mut self, data: &[u8]) -> u32 {
        let first = self.next;
        let n = data.len().div_ceil(CLUSTER) as u32;
        self.b[at(first)..at(first) + data.len()].copy_from_slice(data);
        for c in first..first + n {
            self.b[at(2) + (c as usize - 2) / 8] |= 1 << ((c - 2) % 8);
        }
        self.next += n;
        first
    }

    fn file(&mut self, name: &str, data: &[u8]) {
        let first = if data.is_empty() { 0 } else { self.data(data) };
        let set = file_set(&units(name), false, first, data.len() as u64, data.len() as u64, true);
        self.root(&set);
    }

    /// A directory of one cluster in the root, holding `entries`.
    fn dir(&mut self, name: &str, entries: &[u8]) {
        let mut cluster = vec![0u8; CLUSTER];
        cluster[..entries.len()].copy_from_slice(entries);
        let first = self.data(&cluster);
        let set = file_set(&units(name), true, first, CLUSTER as u64, CLUSTER as u64, true);
        self.root(&set);
    }

    /// The boot region's checksum, made over what the boot sector now says.
    fn sealed(mut self) -> Vec<u8> {
        let mut sum = 0u32;
        for (i, &b) in self.b[..11 * SECTOR].iter().enumerate() {
            if i != 106 && i != 107 && i != 112 {
                sum = sum.rotate_right(1).wrapping_add(u32::from(b));
            }
        }
        for k in 0..SECTOR / 4 {
            put32(&mut self.b, 11 * SECTOR + 4 * k, sum);
        }
        self.b
    }
}

fn open(b: Vec<u8>) -> Result<ExFat<Cursor<Vec<u8>>>, String> {
    ExFat::open(Cursor::new(b))
}

/// A directory of the call's own here, made empty: the tests run at once, several of them through
/// refused().
fn scratch(name: &str) -> PathBuf {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let n = CALLS.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("kryptik-stick-exfat-{}-{name}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// The volume most tests start from: a photo, an empty file, and a directory holding a note.
fn sample() -> Image {
    let mut img = Image::new();
    let photo: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    img.file("Photo.JPG", &photo);
    img.file("empty.txt", b"");
    let mut inner = Image { b: vec![0u8; CLUSTER], next: 0, root_at: 0 };
    let note = img.data(b"a note");
    inner.root(&file_set(&units("Note.txt"), false, note, 6, 6, true));
    let entries = inner.b[..inner.root_at].to_vec();
    img.dir("DCIM", &entries);
    img
}

#[test]
fn a_card_is_named_listed_and_copied_off() {
    let mut x = open(sample().sealed()).unwrap();
    assert_eq!(x.label(), "KSTICK");
    assert_eq!(x.free(), u64::from(COUNT - 3 - 3 - 1 - 1) * CLUSTER as u64);
    assert_eq!(x.entries("/").unwrap(), vec![
        ("Photo.JPG".to_string(), false, 10_000),
        ("empty.txt".to_string(), false, 0),
        ("DCIM".to_string(), true, CLUSTER as u64),
    ]);
    let out = scratch("copy");
    assert_eq!(x.get("/photo.jpg", &out).unwrap(), 10_000, "names compare without regard to case");
    let photo = fs::read(out.join("photo.jpg")).unwrap();
    assert!(photo.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
    assert_eq!(x.get("/", &out.join("all")).unwrap(), 10_006);
    assert_eq!(fs::read(out.join("all/DCIM/Note.txt")).unwrap(), b"a note");
    assert_eq!(fs::read(out.join("all/empty.txt")).unwrap(), b"");
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn a_file_reads_as_zeros_past_its_valid_data() {
    let mut img = Image::new();
    let first = img.data(&[0xaa; 100]);
    img.root(&file_set(&units("half"), false, first, 100, 40, true));
    let mut x = open(img.sealed()).unwrap();
    let out = scratch("valid");
    x.get("half", &out).unwrap();
    let back = fs::read(out.join("half")).unwrap();
    assert_eq!(back.len(), 100);
    assert!(back[..40].iter().all(|&b| b == 0xaa) && back[40..].iter().all(|&b| b == 0));
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn a_file_along_the_fat_is_read_in_its_chain_order() {
    let mut img = Image::new();
    let (a, b) = (img.data(&[1; CLUSTER]), img.data(&[2; CLUSTER]));
    img.chain(&[b, a]);
    img.root(&file_set(&units("chained"), false, b, 2 * CLUSTER as u64, 2 * CLUSTER as u64, false));
    let mut x = open(img.sealed()).unwrap();
    let out = scratch("chain");
    x.get("chained", &out).unwrap();
    let back = fs::read(out.join("chained")).unwrap();
    assert!(back[..CLUSTER].iter().all(|&v| v == 2) && back[CLUSTER..].iter().all(|&v| v == 1));
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn a_name_that_is_not_utf16_shows_as_replacement_characters() {
    let mut img = Image::new();
    img.root(&file_set(&[0x61, 0xd800, 0x62], false, 0, 0, 0, true));
    let mut x = open(img.sealed()).unwrap();
    assert_eq!(x.entries("/").unwrap(), vec![("a\u{fffd}b".to_string(), false, 0)]);
}

/// Each malformed volume is refused, at open or at the walk, with the reason.
fn refused(b: Vec<u8>, why: &str) {
    let err = match open(b) {
        Err(e) => e,
        Ok(mut x) => {
            let out = scratch("refused");
            let walked = x.get("/", &out.join("all")).err();
            let _ = fs::remove_dir_all(&out);
            walked.unwrap_or_else(|| panic!("a volume with {why} was read"))
        }
    };
    assert!(err.contains(why), "wanted {why:?}, got {err:?}");
}

#[test]
fn a_root_whose_chain_loops_through_unused_entries_stops() {
    let mut img = sample();
    // No end marker in the root's cluster, only deleted entries, and its chain back to itself.
    let end = at(4) + CLUSTER;
    for slot in (img.root_at..end).step_by(32) {
        img.b[slot] = 0x05;
    }
    put32(&mut img.b, 24 * SECTOR + 4 * 4, 4);
    refused(img.sealed(), "loops");
}

#[test]
fn a_straight_run_past_the_heap_is_refused() {
    let mut img = Image::new();
    img.root(&file_set(&units("long"), false, COUNT, 3 * CLUSTER as u64, 3 * CLUSTER as u64, true));
    refused(img.sealed(), "runs past the heap");
}

#[test]
fn a_set_that_fails_its_checksum_is_refused() {
    let mut img = Image::new();
    let first = img.data(b"x");
    let mut set = file_set(&units("x"), false, first, 1, 1, true);
    set[56] = 2;
    img.root(&set);
    refused(img.sealed(), "fails its checksum");
}

#[test]
fn an_up_case_table_too_long_is_refused() {
    let mut img = Image::new();
    let upcase = at(4) + 64;
    assert_eq!(img.b[upcase], 0x82);
    put64(&mut img.b, upcase + 24, 200_000);
    refused(img.sealed(), "up-case table's length");
}

#[test]
fn an_up_case_table_whose_checksum_fails_is_refused() {
    let mut img = Image::new();
    img.b[at(3) + 4] ^= 1;
    refused(img.sealed(), "up-case table's checksum");
}

#[test]
fn a_set_running_off_its_directory_is_refused() {
    let mut img = Image::new();
    // The directory's last entry starts a set of three, and the directory ends after it.
    let mut entries = vec![0u8; CLUSTER];
    let set = file_set(&units("cut"), false, 0, 0, 0, true);
    entries[CLUSTER - 32..].copy_from_slice(&set[..32]);
    for slot in (0..CLUSTER - 32).step_by(32) {
        entries[slot] = 0x05;
    }
    img.dir("D", &entries);
    refused(img.sealed(), "runs off the end of its directory");
}

#[test]
fn a_set_of_more_than_eighteen_secondaries_is_refused() {
    let mut img = Image::new();
    let mut set = file_set(&units("x"), false, 0, 0, 0, true);
    set[1] = 19;
    let sum = set_checksum(&set);
    put16(&mut set, 2, sum);
    img.root(&set);
    refused(img.sealed(), "impossible size");
}

#[test]
fn a_directory_that_names_the_root_stops_the_copy() {
    let mut img = Image::new();
    img.root(&file_set(&units("loop"), true, 4, CLUSTER as u64, CLUSTER as u64, true));
    refused(img.sealed(), "nested more than");
}

#[test]
fn a_boot_region_whose_checksum_fails_is_refused() {
    let mut b = sample().sealed();
    b[100] ^= 1;
    refused(b, "boot checksum");
}

#[test]
fn a_volume_larger_than_its_stick_is_refused() {
    let mut img = sample();
    put32(&mut img.b, 92, COUNT * 4);
    put64(&mut img.b, 72, 4096 * 4);
    refused(img.sealed(), "outside the stick");
}

#[test]
fn a_cluster_size_past_the_spec_is_refused() {
    let mut img = sample();
    img.b[109] = 17;
    refused(img.sealed(), "cluster size");
}

#[test]
fn a_fat_that_is_not_exfat_is_not_taken_for_one() {
    assert!(!is_exfat(&mut Cursor::new(vec![0u8; 8])).unwrap());
    let mut fat = Cursor::new(vec![0u8; 2 * 1024 * 1024]);
    fatfs::format_volume(&mut fat, fatfs::FormatVolumeOptions::new()).unwrap();
    assert!(!is_exfat(&mut fat).unwrap());
    assert!(is_exfat(&mut Cursor::new(sample().sealed())).unwrap());
}
