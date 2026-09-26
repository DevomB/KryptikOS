# zlib 1.3.1: 1.3.2's negative-length fix, without 1.3.2

Applied by `s_zlib` in stage 04 through `apply_repo_patches`; `SHA256SUMS` is
verified before anything is applied.

`crc32_combine()`, `crc32_combine_gen()` and their 64-bit forms never return
when the length they are given is negative. They walk the length's bits by
shifting it right until it is zero, and a negative length shifted right never
is. zlib.h already said the length must not be negative. This is
CVE-2026-27171; the fix has them return 0 instead.

zlib 1.3.2 is the release that fixes it, and it is not taken because it adds
CVE-2026-85091: `gz_vacate()`, new in 1.3.2 with the non-blocking `gz*`
support, can overflow a heap buffer. 1.3.1 has no such function. The fix for
that (upstream df84af25dc) is on zlib's develop branch and in no release
(`tools/pin-reviews.tsv`).

binutils and gcc are built `--with-system-zlib`, so they use this one. perl
builds a zlib of its own for Compress::Raw::Zlib, before this one exists:
perl 5.40.5's is 1.3.2's core, which has this fix and none of the `gz*`
files that hold 1.3.2's overflow.

## Where it comes from

The patch is upstream's commit ba829a458576d1ff0f26fc7230c6de816d1f6a77
("Check for negative lengths in crc32_combine functions.", Mark Adler,
2025-12-21), as github.com/madler/zlib serves it with `.patch`, unedited.
`UPSTREAM-SHA256SUMS` holds that output's hash, and it equals `SHA256SUMS`.
It changes `crc32.c` and zlib.h's description of the two functions; the
zlib.h hunk lands 90 lines earlier than in upstream's tree, with no fuzz.

## How it was checked

`s_zlib` builds a call of both functions with a length of -1 against the
library it has just compiled, and fails unless both return 0 within ten
seconds. Against the released 1.3.1 that check fails: the call is still
running when it is killed. Against the patched tree it passes, and so do
zlib's own tests (`make check`: static, shared and 64-bit).

Delete this directory when the zlib pin moves on.
