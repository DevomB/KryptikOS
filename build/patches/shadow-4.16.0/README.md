# shadow 4.16.0: sgetgrent requires every field of a group line

Applied by `s_shadow` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

`sgetgrent()` parses one line of /etc/group for the group database code
every shadow tool goes through (`lib/groupio.c`). 4.16.0 accepted a line
with three fields instead of four, and then took the member list from a
pointer left over from the previous line, which can point into a buffer it
has since freed. The patch is upstream's fix, unchanged:
8424d7c49462a6587c773f9b08c1867d7750f5ec, "lib/sgetgrent.c: sgetgrent():
Fix use-after-free bug" (https://github.com/shadow-maint/shadow/issues/1144),
first released in 4.17.0. A line missing a field is now refused like any
other malformed line. /etc/group is root's file, so this is hardening, not a
boundary.

Delete this directory when the shadow pin moves to 4.17.0 or later.
