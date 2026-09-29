# Releases

A release is one tagged revision, built and tested whole, on the
repository's Releases page. Everything on the page comes from the directory
`make acceptance` exports when every suite passed ([user guide](user-guide.md),
"What is in the release directory"); a run that did not pass puts nothing
there.

## Numbering

A release is numbered MAJOR.MINOR.PATCH and tagged `v<version>`, as
[release keys](release-keys.md) says: the patch number rises for fixes, the
minor for new features, the major for a change that needs a reinstall. While
every release is a development one the major number is 0: `0.1.0`, then
`0.1.1` and `0.2.0`. `1.0.0` is the first production release, signed with
the release key made offline. The dated builds CI makes of every push to main
(`0.1.<date>.<commit>`) are not releases and never reach the page.

## Two kinds

| | development, a pre-release on the page | production |
| --- | --- | --- |
| keys | made by that build and then gone | the key medium, kept offline |
| Secure Boot | a certificate per release, enrolled by hand | one certificate, enrolled once |
| the next release | a reinstall from its medium | an update from the channel, signed by the release key |
| built by | the Distro workflow, from the tag | you, with the medium attached, and `KRYPTIK_CHANNEL=https://<owner>.github.io/<repo>/stable/` |

## Cutting one

1. Pick the revision: a commit on main whose Distro run passed whole.
2. Tag it and push the tag:

   ```sh
   git tag v0.1.0 <revision>
   git push origin v0.1.0
   ```

3. The Distro workflow builds that version as the release under test, over a
   `0.0.0` build the update suite updates from, runs every suite on the
   images, and its last job drafts the release: the export, the corresponding
   source (`make source-bundle`) and the acceptance logs, with the release
   notes as the page's text. Read the draft and publish it from the page.
4. A production release is built by hand with the key medium and its export
   published with the same tool once the tag is pushed:
   `tools/release-publish.sh DIR --source-bundle FILE --publish`. Its payload
   goes up with it, and the `Update channel` workflow, run with the tag,
   makes it what installed machines update to
   ([release keys](release-keys.md#using-them)).

## What the page carries

| file | what it is |
| --- | --- |
| `kryptik-VERSION-usb.img.zst`, `kryptik-VERSION.iso.zst` | the install media, compressed: `zstd -d` restores the files the signed checksums cover |
| `kryptik-VERSION.SHA256SUMS`, `.sig`, `release-signers` | the media's hashes, the release key's signature over them, and the anchor that checks it |
| `kryptik-sb.crt`, `kryptik-sb.der` | the Secure Boot certificate that signed the kernels |
| `root.json`, `manifest-VERSION`, `.sig` | the root's dm-verity record and the signed release manifest |
| `source-REVISION.tar` | the corresponding source: every tarball with its signatures, the crates the Rust binaries link, and the tree |
| `RELEASE.txt`, `REVISION.txt`, `RELEASE-NOTES.md`, `INSTRUCTIONS.md`, `ACCEPTANCE-REPORT.md`, `SHA256SUMS`, `kryptik-VERSION-acceptance-logs.tar.zst` | the record: the verdict, the revision, the notes, the instructions, and every item's result and log |

The page's text ends with the size and hash of each file as uploaded. Check
a download after decompressing it:

```sh
zstd -d kryptik-VERSION-usb.img.zst
ssh-keygen -Y verify -f release-signers -I kryptik-release -n kryptik-media \
    -s kryptik-VERSION.SHA256SUMS.sig < kryptik-VERSION.SHA256SUMS
sha256sum -c kryptik-VERSION.SHA256SUMS
```

The anchor comes with the download, so this proves the files belong
together, not who made them: a machine that runs Kryptik holds the same file
at `/usr/share/kryptik/trust/release-signers`, and a production release's
anchor is the one on the key medium.
