# Release keys

How the keys that sign Kryptik releases are made, kept, used, replaced and
given up. They live in the repository's protected `release` environment, and
only a release tag's build signs with them, after the maintainer approves the
run. The build never makes these keys (`build/lib/release-keys.sh`).

## The keys

| Key | Signs | Where it lives | If it is stolen |
| --- | --- | --- | --- |
| `kryptik-release` (Ed25519) | every release's manifest, and the checksums of its install media | the `release` environment's `KRYPTIK_KEY_MEDIUM` secret, and the backup | the thief can sign a release that every machine installs |
| `kryptik-latest` (Ed25519) | the channel's "this release is current" statement, daily | the `KRYPTIK_LATEST_KEY` repository secret, `KRYPTIK_KEY_MEDIUM`, and the backup | machines can be held on an old release; nothing can be installed with it |
| `kryptik-sb` (RSA, X.509) | the kernels, for Secure Boot | `KRYPTIK_KEY_MEDIUM`, and the backup | the thief can sign kernels that machines which enrolled it will boot |
| `kryptik-testctl` (Ed25519) | a control disk that arms an unattended install or recovery on a machine booting a release's medium (the suites' installs) | the `release-tests` environment's `KRYPTIK_TESTCTL_KEY` secret, and the backup | the thief can wipe a disk on a machine they boot a release's medium on with a control disk attached; nothing can be signed or installed with it |
| the module key | the kernel's modules | nowhere: each kernel build makes one and throws it away | nothing to steal |

An image trusts the three Ed25519 keys through its anchor,
`/usr/share/kryptik/trust/release-signers`. Each key is listed under its own
name and held to its own namespaces: the release key to `kryptik-release` for
manifests and `kryptik-media` for the media's checksums, the statement key to
`kryptik-latest`, the control-disk key to `kryptik-testctl`. So a statement
key cannot sign a release or its media, a control-disk key can arm nothing
but an install, and no signature passes for one of another kind. A machine
trusts the Secure Boot key once its certificate is enrolled in the machine's
firmware.

The public halves are in the tree, `build/config/release/release-signers` and
`build/config/release/kryptik-sb.crt`: a release's root is bound to that
anchor, and a download can be compared with it.

## Where they are used

A release tag's Distro run builds the system as any run does, then binds each
release's root and kernels to the public halves alone
(`KRYPTIK_MEDIA_PHASE=bind`). That job ran every upstream build script as
root, so no private key reaches it. The `sign` job then waits for the
maintainer's approval and takes the key medium from the `release` environment
on a fresh runner. It treats what the build job handed over as hostile: it
unpacks only the bound releases and the stamps, refuses anything in them that
is not a plain file or directory, takes the versions from the tag rather than
from the build job, and checks the bound root against the medium. Then, as an
unprivileged user, it signs and assembles the media with host tools
(`KRYPTIK_MEDIA_PHASE=sign`), checks that no line of a private key is in
anything it made or logged, and deletes the medium. Only `v*` tags may use the
environment. The acceptance parts take the control-disk key from
`release-tests` the same way, so no artifact carries it, and the part that
runs sysroot programs on the host never gets it.

A release is therefore as trustworthy as the maintainer's GitHub account and
the runners that build it: whoever can push a `v*` tag and approve its run
can sign a release. Keep the account behind a passkey or a hardware security
key.

## Making them

Once, on a machine you trust, outside any checkout:

```sh
mkdir kryptik-keys && cd kryptik-keys
for k in kryptik-release kryptik-latest kryptik-testctl; do
    ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$k"
done
{
    printf 'kryptik-release namespaces="kryptik-release,kryptik-media" %s\n' "$(cut -d' ' -f1,2 kryptik-release.pub)"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 kryptik-latest.pub)"
    printf 'kryptik-testctl namespaces="kryptik-testctl" %s\n' "$(cut -d' ' -f1,2 kryptik-testctl.pub)"
} > release-signers
openssl req -new -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -subj "/CN=Kryptik Secure Boot/" -keyout kryptik-sb.key -out kryptik-sb.crt
chmod 600 kryptik-release kryptik-latest kryptik-testctl kryptik-sb.key
```

The keys carry no passphrase, since the workflow signs unattended; GitHub
keeps the secrets encrypted, and the backup is encrypted as a whole.

1. Make the two environments. `release` takes only `v*` tags and waits for a
   reviewer; `release-tests` takes only `v*` tags:

   ```sh
   me="$(gh api user --jq .id)"
   gh api -X PUT repos/{owner}/{repo}/environments/release --input - <<EOF
   {"reviewers": [{"type": "User", "id": ${me}}], "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
   EOF
   gh api -X PUT repos/{owner}/{repo}/environments/release-tests --input - <<EOF
   {"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
   EOF
   for e in release release-tests; do
       gh api -X POST "repos/{owner}/{repo}/environments/$e/deployment-branch-policies" -f name='v*' -f type=tag
   done
   ```

   Check both before any secret goes in: a run that names an environment
   before it exists creates one with no rules.

   ```sh
   gh api repos/{owner}/{repo}/environments/release --jq '.protection_rules'
   gh api repos/{owner}/{repo}/environments/release/deployment-branch-policies --jq '.branch_policies'
   ```

2. Put the keys where the workflows read them. The medium leaves out the
   control-disk key, which only the suites use:

   ```sh
   tar -cz release-signers kryptik-release kryptik-release.pub kryptik-latest kryptik-latest.pub \
       kryptik-sb.key kryptik-sb.crt | base64 -w0 | gh secret set KRYPTIK_KEY_MEDIUM --env release
   gh secret set KRYPTIK_TESTCTL_KEY --env release-tests < kryptik-testctl
   gh secret set KRYPTIK_LATEST_KEY < kryptik-latest
   ```

3. Commit `release-signers` and `kryptik-sb.crt` to `build/config/release/`.
4. Encrypt the directory, keep the result in two places (a password manager's
   file store and a USB stick, say), and delete the plaintext:

   ```sh
   cd .. && tar -cz kryptik-keys | openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -out kryptik-keys.tar.gz.enc
   ```

Losing `kryptik-release` without a backup means no installed machine can be
updated again. A new key can only reach them in a release signed by the old
one, so each machine would have to be reinstalled from a medium carrying a
new anchor.

## Using them

For each release:

1. Tag a commit on main whose CI and Distro runs passed, and push the tag:
   `git tag v1.0.1 <commit> && git push origin v1.0.1`.
2. The run checks the tag, the pins, the sources and CI on the commit
   ([releases](releases.md#cutting-one)), builds from nothing, binds, and
   waits: approve the `sign` job's deployment to `release` on the run's page,
   within the week its bound releases are kept.
3. It signs, runs every suite on the signed media and drafts the release with
   its export, source and acceptance logs. Read the draft, then publish it:
   `gh release edit v1.0.1 --draft=false --latest`.
4. Publish it into the channel: run the `Update channel` workflow with the
   tag (`gh workflow run channel.yml -f release=v1.0.1`). Its daily schedule
   signs the statement again; a machine that hears nothing for 30 days says
   so.

`gh workflow run distro.yml -f role=production` rehearses the whole flow on
any branch, with a throwaway medium made for that run.

A production image can also be built on one machine with a key medium
([building](building.md)). That machine then holds the keys while its chroot
runs; `KRYPTIK_MEDIA_PHASE=bind` and then `sign` split the build as the
workflow does.

## Numbering a release

A production release is numbered MAJOR.MINOR.PATCH, such as `1.0.3`: digits
only, with no leading zeros. Raise the patch number for fixes, the minor for
new features, and the major for a change that needs a reinstall. The build
refuses any other form for a production image, and a missing version too. A
machine installs only a release newer than the one it runs, ordered as
`sort -V` orders them, so `1.0.10` comes after `1.0.9`.

## Enrolling the Secure Boot certificate

A machine boots Kryptik's signed kernels once `kryptik-sb.crt` is in its
firmware's database of allowed keys (db). The USB medium carries the
certificate at `/kryptik/kryptik-sb.crt` and the ISO at its root, the release
record has it in DER form as well, and the tree keeps it in
`build/config/release/`. How to enrol it depends on the firmware; most setup
screens can enrol a key from a file on a FAT volume.

## Replacing a key

A machine accepts only what the anchor of the release it runs lists, and the
channel names one release at a time. So a new key has to arrive in a release
the old key signed, whose anchor lists both keys, and that release has to
stay the channel's current one until the machines you care about have
installed it. The build accepts an anchor that lists a name more than once,
as long as no key is listed twice. Each change updates the secret, the
backup and `build/config/release/`.

- **Statement key.** Make the new key as above. Ship a release whose anchor
  lists both the old and the new `kryptik-latest`, and keep signing
  statements with the old key until every machine runs it. Then switch
  `KRYPTIK_LATEST_KEY` to the new key, and drop the old line from a later
  release's anchor.
- **Release key.** Make the new key as above. Ship release N+1, signed by the
  old key, with an anchor that lists both, and keep it the channel's current
  release until the machines you care about have installed it. Then sign N+2
  with the new key and drop the old line from its anchor. A machine still on
  N after that cannot take N+2: install N+1 on it from a payload on a disk,
  and it updates as usual from there.
- **Secure Boot key.** Enrol the new certificate on every machine before you
  ship kernels signed by it. Remove the old certificate from db, or add it to
  dbx, once no machine needs it.

## When a key is stolen

A stolen GitHub account, or a way into the `release` environment, is a stolen
release key: revoke the account's sessions and tokens first.

- **Statement key.** Machines can be held on an old release, which a hostile
  network can do anyway, and they report it after 30 days. Replace the key as
  above.
- **Release key.** The thief can sign a release that machines will install.
  Machines trust no other key yet, so your answer has to be signed with the
  stolen one too. Make a new release key, and ship a release, signed by the
  stolen key, whose anchor lists only the new one. It is a race, since the
  thief can ship a competing release until machines install yours: publish it
  and tell users to update at once. A machine that installed the thief's
  release has to be reinstalled from a medium you made.
- **Secure Boot key.** The thief can sign kernels that enrolled machines will
  boot. Add its certificate to each machine's dbx and enrol a new one.
