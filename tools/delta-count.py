#!/usr/bin/env python3
"""What a delta update from release A would fetch of release B (docs/design/delta-updates.md).

    delta-count.py PAYLOAD_A PAYLOAD_B

Each payload directory holds root.json and the root image, as kryptik-root.img or
kryptik-root.img.zst. A delta matches blocks by content: B's 4 KiB data blocks that no data
block of A holds would travel, and B's hash tree, which the client checks first, travels
whole. The last line, "delta: ...", is what the acceptance report shows. Exit 1 on a payload
whose image is not what its root.json describes.
"""
import hashlib
import json
import os
import subprocess
import sys

BLOCK = 4096
MIB = 1 << 20


def meta_of(payload):
    with open(os.path.join(payload, "root.json"), encoding="utf-8") as f:
        meta = json.load(f)
    blocks, total = int(meta["data_blocks"]), int(meta["total_bytes"])
    if blocks <= 0 or total < blocks * BLOCK:
        raise ValueError(f"{payload}/root.json: {blocks} data blocks do not fit in {total} bytes")
    return meta["version"], blocks, total


def packed_size(payload):
    p = os.path.join(payload, "kryptik-root.img.zst")
    return os.path.getsize(p) if os.path.isfile(p) else None


def digests(payload):
    """Each data block's digest, in order; the tree after them is only measured. An image
    shorter or longer than root.json says, or one zstd cannot unpack, is refused."""
    _, blocks, total = meta_of(payload)
    plain = os.path.join(payload, "kryptik-root.img")
    unpack = None
    if os.path.isfile(plain):
        stream = open(plain, "rb")
    elif packed_size(payload) is not None:
        unpack = subprocess.Popen(["zstd", "-dcq", plain + ".zst"], stdout=subprocess.PIPE)
        stream = unpack.stdout
    else:
        raise ValueError(f"{payload} holds no kryptik-root.img or kryptik-root.img.zst")
    with stream:
        for _ in range(blocks):
            b = stream.read(BLOCK)
            if len(b) != BLOCK:
                raise ValueError(f"{payload}: the image ends before root.json's {blocks} data blocks")
            yield hashlib.blake2b(b, digest_size=16).digest()
        rest = 0
        while chunk := stream.read(MIB):
            rest += len(chunk)
    if unpack is not None and unpack.wait() != 0:
        raise ValueError(f"{payload}: zstd could not unpack kryptik-root.img.zst")
    if blocks * BLOCK + rest != total:
        raise ValueError(f"{payload}: the image is {blocks * BLOCK + rest} bytes, and root.json says {total}")


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    a, b = argv[1:]
    try:
        (va, na, _), (vb, nb, total) = meta_of(a), meta_of(b)
        have = set(digests(a))
        found = sum(d in have for d in digests(b))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"delta-count: {e}", file=sys.stderr)
        return 1
    tree = total - nb * BLOCK
    fetch = (nb - found) * BLOCK + tree
    print(f"delta-count: A {va}: {na} data blocks; B {vb}: {nb} data blocks and a hash tree of {tree} bytes")
    print(f"delta-count: of B's data blocks {found} are in A and {nb - found} are not")
    packed = packed_size(b)
    whole = f"; its kryptik-root.img.zst is {packed / MIB:.0f} MiB" if packed is not None else ""
    print(f"delta: {fetch / MIB:.0f} MiB of B's {total / MIB:.0f} MiB image from A ({100 * fetch / total:.0f}%){whole}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
