# Release keys

How to make, keep, use, replace and give up the keys that sign Kryptik
releases. You do all of it by hand, on machines you control. The build never
makes these keys and never keeps a copy (`build/lib/release-keys.sh`).

## The keys

| Key | Signs | Where it lives | If it is stolen |
| --- | --- | --- | --- |
| `kryptik-release` (Ed25519) | every release's manifest | offline, on the key medium | the thief can sign a release that every machine installs |
| `kryptik-latest` (Ed25519) | the channel's "this release is current" statement, daily | on the release host, for its timer | machines can be held on an old release; nothing can be installed with it |
| `kryptik-sb` (RSA, X.509) | the kernels, for Secure Boot | offline, on the key medium | the thief can sign kernels that machines which enrolled it will boot |
| the module key | the kernel's modules | nowhere: each kernel build makes one and throws it away | nothing to steal |

An image trusts the two Ed25519 keys through its anchor,
`/usr/share/kryptik/trust/release-signers`. Each key is listed under its own
name and held to its own namespace, so a statement key cannot sign a release,
and a release key's signature is not a statement. A machine trusts the Secure
Boot key once its certificate is enrolled in the machine's firmware.

## Making them

Do this once, on a machine that has never been on a network and will not be:
a live system started from read-only media will do. You need two removable
media, the key medium and its backup, ideally encrypted.

```sh
mkdir kryptik-keys && cd kryptik-keys
ssh-keygen -t ed25519 -C kryptik-release -f kryptik-release     # set a passphrase
ssh-keygen -t ed25519 -C kryptik-latest -f kryptik-latest       # set a passphrase
{
    printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 kryptik-release.pub)"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 kryptik-latest.pub)"
} > release-signers
openssl req -new -x509 -newkey rsa:3072 -sha256 -days 3650 \
    -subj "/CN=Kryptik Secure Boot/" -keyout kryptik-sb.key -out kryptik-sb.crt   # set a passphrase
chmod 600 kryptik-release kryptik-latest kryptik-sb.key
```

The backup gets the whole directory. The key medium gets everything except
`kryptik-latest` and `kryptik-latest.pub`: the build does not need them. The
statement key goes to the release host, and nowhere else that is online.

The build takes the key medium as it is. It refuses a private key anyone but
its owner can read, a key owned by anyone but root or the user running the
build, a medium inside its own work tree, and an anchor not written as above.

Losing `kryptik-release` without a backup means no installed machine can be
updated again. A new key can only reach them in a release signed by the old
one, so each machine would have to be reinstalled from a medium carrying a
new anchor. Keep the backup somewhere else.

## Using them

For each release:

1. Build up to the kernel on the build machine as usual (`make kernel`). No
   key is needed for that, and none is ever inside the chroot.
2. Attach the key medium and make the media. `ssh-keygen` and `sbsign` ask
   for the passphrases:

   ```sh
   make media KRYPTIK_ROLE=production KRYPTIK_KEYS=/media/<medium>/kryptik-keys \
       KRYPTIK_VERSION=<version> KRYPTIK_CHANNEL=https://<host>/<channel>/
   ```

3. Detach the medium. The signed payload is in
   `<work>/images/payload-<version>`, and the release record is under
   `KRYPTIK_OUT`.
4. Copy the payload and `release-signers` to the release host. It needs a
   checkout of this repository for `tools/release-channel.sh`. Publish with
   the statement key there:

   ```sh
   tools/release-channel.sh publish --key <statement key> --signers release-signers \
       --payload payload-<version> --out /srv/<channel>
   ```

5. Keep the host's daily timer running `tools/release-channel.sh reissue`
   with the same key and signers file. A machine that hears nothing for 30
   days says so.

## Enrolling the Secure Boot certificate

A machine boots Kryptik's signed kernels once `kryptik-sb.crt` is in its
firmware's database of allowed keys (db). The USB medium carries the
certificate at `/kryptik/kryptik-sb.crt` and the ISO at its root, and the
release record has it in DER form as well. How to enrol it depends on the
firmware; most setup screens can enrol a key from a file on a FAT volume.

## Replacing a key

A machine accepts only what the anchor of the release it runs lists. So a new
key has to arrive in a release the old key signed, and that release's anchor
has to list both keys. The build accepts an anchor that lists a name more
than once, as long as no key is listed twice.

- **Statement key.** Make the new key offline. Ship a release whose anchor
  lists both the old and the new `kryptik-latest`. Once machines run it, sign
  statements with the new key, and drop the old line from a later release's
  anchor.
- **Release key.** Make the new key offline. Ship release N+1, signed by the
  old key, with an anchor that lists both. Sign N+2 with the new key, and drop
  the old line from its anchor. A machine still on N passes through N+1.
- **Secure Boot key.** Enrol the new certificate on every machine before you
  ship kernels signed by it. Remove the old certificate from db, or add it to
  dbx, once no machine needs it.

## When a key is stolen

- **Statement key.** Machines can be held on an old release, which a hostile
  network can do anyway, and they report it after 30 days. Replace the key as
  above.
- **Release key.** The thief can sign a release that machines will install.
  While you still hold the key too, ship a release whose anchor drops it, and
  tell users to update at once. A machine that installed the thief's release
  has to be reinstalled from a medium you made.
- **Secure Boot key.** The thief can sign kernels that enrolled machines will
  boot. Add its certificate to each machine's dbx and enrol a new one.
