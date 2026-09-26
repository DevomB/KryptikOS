# tar 1.35: builds against acl 2.4.0

Applied by `s_tar` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

tar 1.35 defines three private helpers, `acl_get_file_at()`,
`acl_set_file_at()` and `acl_delete_def_file_at()`, in `src/xattrs.c`.
acl 2.4.0 declares public functions of those names with other signatures in
`<acl/libacl.h>`, so tar no longer compiles against it ("conflicting types
for 'acl_get_file_at'"). The patch is upstream's rename to `tar_acl_*`,
08c3fc2e9337094aff01a511170fd35fdb8f1ee3, "Avoid acl_ prefix for functions",
made against 1.35's text: the same three names renamed at the same
declarations, calls and messages, where the lines around them differ.

No other package Kryptik builds against libacl uses those names: coreutils
9.12, sed 4.10 and shadow 4.16.0 contain none of the four `acl_*_at`
functions acl 2.4.0 adds.

Checked inside the image's sysroot with stage 04's flags: unpatched 1.35
fails against acl 2.4.0 as above; patched, it builds, and its test suite
gives the same result as unpatched 1.35 against acl 2.3.2 (the same two
failures, trusted.* xattrs and raw capabilities, which need privileges a
user namespace does not have, and the same 20 skips).

Delete this directory when the tar pin moves to a release that contains the
commit.
