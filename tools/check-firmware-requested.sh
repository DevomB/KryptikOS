#!/usr/bin/env bash
# Fail on a file a module under ROOT names (MODULE_FIRMWARE) that linux-firmware's WHENCE has and
# ROOT's /usr/lib/firmware lacks, unless build/config/firmware-accepted.txt says why it stays out.
#
#   tools/check-firmware-requested.sh ROOT [--accepted FILE]

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
# The verdict is python's exit status; the ERR trap would abort before it is read.
trap - ERR
set +e

ROOT=""
ACCEPTED="${KRYPTIK_ROOT}/build/config/firmware-accepted.txt"
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --accepted) ACCEPTED="${2:?--accepted needs a file}"; shift 2 ;;
        -*)         die "unknown option: $1" ;;
        *)          ROOT="$1"; shift ;;
    esac
done
[[ -n "$ROOT" ]] || die "usage: check-firmware-requested.sh ROOT [--accepted FILE]"
[[ -d "$ROOT" ]] || die "not a directory: ${ROOT}"
[[ -f "$ACCEPTED" ]] || die "no accepted list at ${ACCEPTED}"

log "Firmware the modules under ${ROOT} name, against linux-firmware's WHENCE"
python3 - "$ROOT" "$ACCEPTED" <<'EOF'
import fnmatch, glob, lzma, os, re, struct, subprocess, sys

root, accepted = sys.argv[1:3]
whence = os.path.join(root, "usr/share/licenses/linux-firmware/WHENCE")
fwdir = os.path.join(root, "usr/lib/firmware")

# Every name linux-firmware installs: its files and the links copy-firmware.sh makes.
upstream = set()
with open(whence, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        m = re.match(r"(?:File|RawFile|Link):\s*(.+?)\s*(?:->.*)?$", line)
        if m:
            upstream.add(m.group(1).strip('"'))

def module_bytes(path):
    if path.endswith(".zst"):
        return subprocess.run(["zstd", "-dcq", path], check=True, capture_output=True).stdout
    if path.endswith(".xz"):
        with lzma.open(path) as fh:
            return fh.read()
    with open(path, "rb") as fh:
        return fh.read()

def firmware_names(data):
    # The firmware= strings of the .modinfo section; every module here is 64-bit little-endian ELF.
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a 64-bit little-endian ELF object")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    def section(i):
        name, _, _, _, off, size = struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize)
        return name, off, size
    _, stroff, _ = section(shstrndx)
    for i in range(shnum):
        name, off, size = section(i)
        if data[stroff + name:].split(b"\0", 1)[0] == b".modinfo":
            for item in data[off:off + size].split(b"\0"):
                if item.startswith(b"firmware="):
                    yield item[len(b"firmware="):].decode()

def shipped(name):
    return any(os.path.lexists(os.path.join(fwdir, name + ext)) for ext in ("", ".zst", ".xz"))

modules = sorted(p for p in glob.glob(os.path.join(root, "usr/lib/modules/*/**/*.ko*"), recursive=True)
                 if re.search(r"\.ko(\.zst|\.xz)?$", p))
if not modules:
    sys.exit(f"no modules under {root}/usr/lib/modules")
wanted = {}   # a name linux-firmware has -> the modules naming it
for path in modules:
    mod = re.sub(r"\.ko(\.zst|\.xz)?$", "", os.path.basename(path))
    try:
        names = list(firmware_names(module_bytes(path)))
    except (ValueError, struct.error, subprocess.CalledProcessError, lzma.LZMAError) as e:
        sys.exit(f"{path}: {e}")
    for pattern in names:
        # A name may be a glob: ath11k names whole directories.
        if any(c in pattern for c in "*?["):
            hits = fnmatch.filter(upstream, pattern)
        else:
            hits = [pattern] if pattern in upstream else []
        for name in hits:
            wanted.setdefault(name, set()).add(mod)

acc = []   # [pattern, line, uses]
for n, line in enumerate(open(accepted, encoding="utf-8"), 1):
    entry, _, why = line.partition("#")
    entry = entry.strip()
    if not entry:
        continue
    if not why.strip():
        sys.exit(f"{accepted}:{n}: {entry}: no reason after #")
    acc.append([entry, n, 0])

missing, accepted_n = [], 0
for name in sorted(wanted):
    if shipped(name):
        continue
    hit = next((a for a in acc if fnmatch.fnmatchcase(name, a[0])), None)
    if hit:
        hit[2] += 1
        accepted_n += 1
    else:
        missing.append(name)

print(f"  {len(modules)} modules name {len(wanted)} files linux-firmware has: "
      f"{len(wanted) - accepted_n - len(missing)} shipped, {accepted_n} accepted")
for name in missing:
    print(f"  NOT SHIPPED  {name}  ({', '.join(sorted(wanted[name]))})", file=sys.stderr)
stale = [a for a in acc if not a[2]]
for a in stale:
    print(f"  ACCEPTS NOTHING  line {a[1]}: {a[0]}", file=sys.stderr)
if missing or stale:
    sys.exit(f"{len(missing)} named file(s) not shipped, {len(stale)} accepted entr{'y' if len(stale) == 1 else 'ies'} "
             "matching none: add the file to build/config/firmware.list, or say in the accepted list why it stays out")
EOF
rc=$?
[[ "$rc" -eq 0 ]] || exit "$rc"
ok "every file a module names and linux-firmware has ships, or the accepted list says why not"
