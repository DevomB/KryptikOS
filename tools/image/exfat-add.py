#!/usr/bin/env python3
"""Put files into an exFAT image mkfs.exfat made, as a camera fills a card: each file's
clusters chained in the FAT and marked in the bitmap, its directory made on the way, and
each entry set's name hash and checksum as the spec computes them. For the zones suite's
card (tools/image/zones-test.sh), whose result fsck.exfat checks; standard library only.

usage: exfat-add.py IMAGE SRC:PATH...    PATH is where on the card SRC goes, a/b/c
"""
import struct
import sys
import time


def u16(b, at):
    return struct.unpack_from("<H", b, at)[0]


def u32(b, at):
    return struct.unpack_from("<I", b, at)[0]


def u64(b, at):
    return struct.unpack_from("<Q", b, at)[0]


def utf16(name):
    raw = name.encode("utf-16-le")
    return list(struct.unpack("<%dH" % (len(raw) // 2), raw))


class Card:
    def __init__(self, path):
        self.f = open(path, "r+b")
        boot = self.read(0, 512)
        if boot[3:11] != b"EXFAT   ":
            sys.exit(f"exfat-add: {path} is not exFAT")
        self.sector = 1 << boot[108]
        self.cluster = self.sector << boot[109]
        self.fat = u32(boot, 80) * self.sector
        self.heap = u32(boot, 88) * self.sector
        self.count = u32(boot, 92)
        self.root = u32(boot, 96)
        root = self.clusters_of(self.root)
        bitmap = upcase = None
        for at in range(0, len(root), 32):
            if root[at] == 0x81:
                bitmap = (u32(root, at + 20), u64(root, at + 24))
            elif root[at] == 0x82:
                upcase = (u32(root, at + 20), u64(root, at + 24))
        if not bitmap or not upcase:
            sys.exit("exfat-add: the card has no bitmap or no up-case table")
        self.bitmap = bitmap
        self.bits = bytearray(self.clusters_of(bitmap[0])[: bitmap[1]])
        table = self.clusters_of(upcase[0])[: upcase[1]]
        units = [u16(table, k) for k in range(0, len(table), 2)]
        self.up = list(range(65536))
        i = k = 0
        while k < len(units):
            if units[k] == 0xFFFF and k + 1 < len(units):
                i += units[k + 1]
                k += 2
            else:
                self.up[i] = units[k]
                i += 1
                k += 1

    def read(self, at, n):
        self.f.seek(at)
        return self.f.read(n)

    def write(self, at, data):
        self.f.seek(at)
        self.f.write(data)

    def at(self, c):
        return self.heap + (c - 2) * self.cluster

    def chain(self, c):
        out = []
        while c != 0xFFFFFFFF:
            out.append(c)
            c = u32(self.read(self.fat + 4 * c, 4), 0)
        return out

    def clusters_of(self, c):
        return b"".join(self.read(self.at(x), self.cluster) for x in self.chain(c))

    def alloc(self, n):
        """n free clusters, marked used and chained in the FAT in the order found."""
        got = []
        for c in range(2, self.count + 2):
            if not (self.bits[(c - 2) // 8] >> ((c - 2) % 8)) & 1:
                got.append(c)
                if len(got) == n:
                    break
        if len(got) < n:
            sys.exit("exfat-add: the card is full")
        for k, c in enumerate(got):
            self.bits[(c - 2) // 8] |= 1 << ((c - 2) % 8)
            self.write(self.fat + 4 * c, struct.pack("<I", got[k + 1] if k + 1 < n else 0xFFFFFFFF))
        return got

    def name_hash(self, units):
        h = 0
        for u in units:
            u = self.up[u]
            for byte in (u & 0xFF, u >> 8):
                h = ((((h & 1) << 15) | (h >> 1)) + byte) & 0xFFFF
        return h

    def entry_set(self, name, directory, first, length):
        units = utf16(name)
        names = -(-len(units) // 15)
        s = bytearray(32 * (2 + names))
        s[0], s[1] = 0x85, 1 + names
        struct.pack_into("<H", s, 4, 0x10 if directory else 0x20)
        t = time.gmtime(1_767_225_600)  # 2026-01-01, a date the card's camera could have set
        stamp = ((t.tm_year - 1980) << 25) | (t.tm_mon << 21) | (t.tm_mday << 16)
        for at in (8, 12, 16):
            struct.pack_into("<I", s, at, stamp)
        s[32], s[33], s[35] = 0xC0, 0x01 if length else 0x00, len(units)
        struct.pack_into("<H", s, 36, self.name_hash(units))
        struct.pack_into("<Q", s, 40, length)  # all of it valid
        struct.pack_into("<I", s, 52, first)
        struct.pack_into("<Q", s, 56, length)
        for k in range(names):
            s[64 + 32 * k] = 0xC1
            for j, u in enumerate(units[15 * k:15 * k + 15]):
                struct.pack_into("<H", s, 64 + 32 * k + 2 + 2 * j, u)
        sum_ = 0
        for i, b in enumerate(s):
            if i not in (2, 3):
                sum_ = ((((sum_ & 1) << 15) | (sum_ >> 1)) + b) & 0xFFFF
        struct.pack_into("<H", s, 2, sum_)
        return bytes(s)

    def entries(self, first):
        """A directory's sets: (name, is a directory, first cluster), and where its end marker is."""
        data = self.clusters_of(first)
        found, at = [], 0
        while at < len(data) and data[at] != 0:
            if data[at] == 0x85:
                count = data[at + 1]
                n = data[at + 32 + 3]
                units = [u16(data, at + 64 + 32 * (k // 15) + 2 + 2 * (k % 15)) for k in range(n)]
                found.append((units, bool(u16(data, at + 4) & 0x10), u32(data, at + 32 + 20)))
                at += 32 * (1 + count)
            else:
                at += 32
        return found, at

    def add_set(self, first, entry_set):
        """A set written at the directory's end marker, which must have room before its last cluster ends."""
        _, end = self.entries(first)
        clusters = self.chain(first)
        if end + len(entry_set) > len(clusters) * self.cluster:
            sys.exit("exfat-add: a directory is full")
        c, off = clusters[end // self.cluster], end % self.cluster
        if off + len(entry_set) > self.cluster:
            sys.exit("exfat-add: a set would cross a cluster")
        self.write(self.at(c) + off, entry_set)

    def dir_of(self, parts):
        """The directory PARTS name, made where missing: one cluster, chained in the FAT."""
        here = self.root
        for part in parts:
            want = [self.up[u] for u in utf16(part)]
            for units, directory, first in self.entries(here)[0]:
                if directory and [self.up[u] for u in units] == want:
                    here = first
                    break
            else:
                (first,) = self.alloc(1)
                self.write(self.at(first), bytes(self.cluster))
                self.add_set(here, self.entry_set(part, True, first, self.cluster))
                here = first
        return here

    def add(self, src, path):
        parts = [p for p in path.split("/") if p]
        data = open(src, "rb").read()
        where = self.dir_of(parts[:-1])
        first = 0
        if data:
            got = self.alloc(-(-len(data) // self.cluster))
            for k, c in enumerate(got):
                self.write(self.at(c), data[k * self.cluster:(k + 1) * self.cluster])
            first = got[0]
        self.add_set(where, self.entry_set(parts[-1], False, first, len(data)))

    def close(self):
        bits = bytes(self.bits)
        for k, c in enumerate(self.chain(self.bitmap[0])):
            piece = bits[k * self.cluster:(k + 1) * self.cluster]
            if piece:
                self.write(self.at(c), piece)
        self.f.close()


def main(argv):
    if len(argv) < 3 or any(":" not in a for a in argv[2:]):
        sys.exit(__doc__)
    card = Card(argv[1])
    for a in argv[2:]:
        src, path = a.split(":", 1)
        card.add(src, path)
    card.close()


if __name__ == "__main__":
    main(sys.argv)
