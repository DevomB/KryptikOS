# util-linux 2.42.3: the restricted-mount flag, where libc does not define it

Applied by `s_util_linux` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

util-linux 2.42 makes a restricted mount refuse symlinks in its paths by
passing `RESOLVE_NO_SYMLINKS` to `openat2()`. On a C library whose `<fcntl.h>`
does not bring `<linux/openat2.h>` in (glibc before 2.43; Kryptik is on 2.40)
that has two defects:

- `libmount/src/hook_idmap.c` uses the constant and includes nothing that
  defines it. It does not compile: this is what stopped the build.
- `include/fileutils.h` defines a fallback of `0x02`. In the kernel's ABI
  `0x02` is `RESOLVE_NO_MAGICLINKS`; `RESOLVE_NO_SYMLINKS` is `0x04`.
  `context.c` compiled with the fallback, so a restricted mount asked the
  kernel to block the wrong thing.

The patch makes `fileutils.h` include the kernel header where configure found
it, corrects the fallback, and has `hook_idmap.c` include `fileutils.h` as
`context.c` and `hook_mount.c` do. Checked on a glibc 2.39 host: the released
tarball fails at `hook_idmap.c:335`; patched, it builds, and `context.c`
preprocesses to `0x04` where it had `0x02`.

Kryptik's `mount` is not setuid, so its restricted mode is not reachable here;
the value is corrected because a carried patch should not leave a known-wrong
constant beside the line it fixes. Not upstream when this was written. Delete
this directory when a util-linux release carries the fix.
