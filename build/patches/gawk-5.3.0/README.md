# gawk 5.3.0: upstream's memory-safety fixes from 5.4.1

Applied by `s_gawk` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

gawk 5.4.1 fixes four advisories (CERT Polska, July 2026). Three reach
Kryptik's x86-64 build and are carried, each as upstream wrote it, with its
ChangeLog hunk dropped:

- `0001`, CVE-2026-40467: `do_getline_redir()` in io.c released the
  redirection's name and then read it on the path for a closed two-way pipe.
  Upstream a2d18c74109e41bec29a23098eba2e00057286d8, "Small memory
  management fix in io.c.", made against 5.3.0's text, which differs in the
  lines around it.
- `0002`, CVE-2026-40468: `do_sub()` kept its output offset in an `int`, and
  `parse_escape()` gathered a `\u` escape's eight hex digits in an `int`.
  Both are widened as in upstream 062f2f2581b991362c046f7f2e238ffa34e6f8c7,
  "Minor integer overflow fixes."; 5.3.0 declares the escape's value `int`
  where upstream had `long`.
- `0003` and `0004`, CVE-2026-40553: `ftype()` in the readdir extension.
  Upstream cca0366144336b49aaa7d5d949966ce8e2c70843, "Avoid buffer overflow
  in extension/readdir.c.", and bfa2e4b890a44100a99d26b54af385479528b12e,
  "Small fix in extension/readdir.c.", which makes the truncation check
  `>=`; both unchanged.

Not carried: CVE-2026-40469, upstream
aa7272a6e1184cdd21ab8f89200219abd8053eda, "Add overflow checking in do_sub
for 32 bit systems". It guards a product that cannot exceed a 64-bit
`size_t`, and upstream's comment says it only replaces a later failure with
a clearer message. Kryptik builds for x86-64 only.

Checked inside the image's sysroot, with its compiler, stage 04's flags and
hardened_malloc preloaded: all four apply to the 5.3.0 tarball with no
fuzz, the build gives the same warnings as unpatched 5.3.0, and `make check`
passes in full either way.

Delete this directory when the gawk pin moves to 5.4.1 or later. 5.4 also
makes MinRX the default regexp engine, a behaviour change to take on its own.
