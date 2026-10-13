use super::*;
use std::io::Cursor;

/// A blank FAT volume of 2 MiB in memory, as a small stick would come.
fn volume() -> FileSystem<Cursor<Vec<u8>>> {
    let mut disk = Cursor::new(vec![0u8; 2 * 1024 * 1024]);
    fatfs::format_volume(&mut disk, fatfs::FormatVolumeOptions::new()).unwrap();
    disk.set_position(0);
    FileSystem::new(disk, FsOptions::new().time_provider(&CLOCK)).unwrap()
}

/// A directory of the test's own here, made empty.
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kryptik-stick-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_file_put_on_the_stick_comes_back_whole() {
    let dir = scratch("round");
    let src = dir.join("notes.txt");
    fs::write(&src, b"what the zone wrote").unwrap();
    let fs = volume();
    assert_eq!(put(&fs, &src, "/").unwrap(), 19);
    assert_eq!(entries(&fs, "/").unwrap(), vec![("notes.txt".to_string(), false, 19)]);
    let back = dir.join("back");
    fs::create_dir(&back).unwrap();
    assert_eq!(get(&fs, "/notes.txt", &back).unwrap(), 19);
    assert_eq!(fs::read(back.join("notes.txt")).unwrap(), b"what the zone wrote");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn nothing_is_written_over_either_way() {
    let dir = scratch("over");
    let src = dir.join("a.txt");
    fs::write(&src, b"first").unwrap();
    let fs = volume();
    put(&fs, &src, "/").unwrap();
    let again = put(&fs, &src, "/").unwrap_err();
    assert!(again.contains("on the stick already"), "{again}");
    get(&fs, "a.txt", &dir.join("copy")).unwrap();
    assert!(get(&fs, "a.txt", &dir.join("copy")).is_err(), "a file here was written over");
    assert_eq!(fs::read(dir.join("copy")).unwrap(), b"first");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_directory_comes_off_with_what_it_holds() {
    let out = scratch("tree");
    let fs = volume();
    let root = fs.root_dir();
    root.create_dir("photos").unwrap().create_dir("2026").unwrap();
    let mut f = root.create_file("photos/2026/a.jpg").unwrap();
    f.write_all(b"jpeg").unwrap();
    drop(f);
    assert_eq!(get(&fs, "photos", &out).unwrap(), 4);
    assert_eq!(fs::read(out.join("photos/2026/a.jpg")).unwrap(), b"jpeg");
    assert_eq!(entries(&fs, "photos").unwrap(), vec![("2026".to_string(), true, 0)]);
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn a_tree_nested_past_the_limit_stops_the_copy() {
    let out = scratch("deep");
    let fs = volume();
    let mut d = fs.root_dir().create_dir("deep").unwrap();
    for _ in 0..=MAX_DEPTH {
        d = d.create_dir("d").unwrap();
    }
    let err = get(&fs, "deep", &out).unwrap_err();
    assert!(err.contains(&format!("nested more than {MAX_DEPTH} deep")), "{err}");
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn a_stick_given_read_only_takes_no_write() {
    let dir = scratch("ro");
    let image = dir.join("stick.img");
    let mut disk = Cursor::new(vec![0u8; 2 * 1024 * 1024]);
    fatfs::format_volume(&mut disk, fatfs::FormatVolumeOptions::new()).unwrap();
    fs::write(&image, disk.into_inner()).unwrap();
    let before = fs::read(&image).unwrap();
    // Opened to write, so what refuses is the grant, not the descriptor.
    let file = fs::OpenOptions::new().read(true).write(true).open(&image).unwrap();
    let fs = FileSystem::new(Disk { file, writable: false }, FsOptions::new().time_provider(&CLOCK)).unwrap();
    let src = dir.join("x.txt");
    fs::write(&src, b"x").unwrap();
    let refused = put(&fs, &src, "/").unwrap_err();
    assert!(refused.contains("read-only"), "{refused}");
    assert!(entries(&fs, "/").unwrap().is_empty());
    drop(fs);
    assert!(fs::read(&image).unwrap() == before, "the image changed under a read-only grant");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_name_from_the_stick_steers_neither_the_terminal_nor_the_path() {
    assert_eq!(shown("a\u{1b}[2Jb\n"), "a?[2Jb?");
    for bad in ["", ".", "..", "a/b", "a\0b"] {
        assert!(local_name(bad).is_err(), "{bad:?} was taken as a file name");
    }
    assert_eq!(local_name("report.pdf"), Ok("report.pdf"));
}

#[test]
fn a_volume_that_is_not_fat_is_refused() {
    assert!(FileSystem::new(Cursor::new(vec![0xffu8; 65_536]), FsOptions::new()).is_err());
    assert!(FileSystem::new(Cursor::new(vec![0u8; 512]), FsOptions::new()).is_err());
}

#[test]
fn the_clock_reads_as_a_fat_date() {
    assert_eq!(civil(0), (1980, 1, 1, 0, 0, 0), "before 1980, FAT's first day");
    assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
    assert_eq!(civil(1_700_000_000), (2023, 11, 14, 22, 13, 20));
    assert_eq!(civil(u64::MAX / 2), (2107, 12, 31, 23, 59, 59), "past 2107, FAT's last second");
}
