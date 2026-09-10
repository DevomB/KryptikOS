# Building Kryptik

Kryptik must be built on Linux. `make check` refuses to run anywhere else.

## On Windows (WSL2)

```powershell
wsl --install -d Ubuntu
```

Then inside the WSL shell:

```sh
sudo apt update
sudo apt install -y build-essential bison flex texinfo cpio rsync bc \
                    gawk libssl-dev python3 git curl xz-utils

# /bin/sh must be bash, not dash — LFS build scripts use bashisms.
sudo dpkg-reconfigure dash        # answer "No"

# Needed from Phase 4 onward, not required now:
sudo apt install -y qemu-system-x86 cryptsetup-bin sbsigntool
```

The above was derived from an actual `make check` run against a stock Ubuntu
WSL2 image on 2026-09-10, which reported exactly these as missing: `bison`,
`texinfo`, `cpio`, `flex`, and `/bin/sh -> dash`.

### Build on the Linux filesystem, not `/mnt/c`

Building across the Windows filesystem boundary is slow and, worse, `/mnt/c`
does not preserve POSIX ownership and permission bits — which the LFS chroot
stages depend on.

```sh
git clone <your-remote> ~/kryptik
cd ~/kryptik
```

Keep the repo on `/mnt/c` for editing if you like, but run builds from a clone
inside the WSL filesystem.

### Memory

GCC's bootstrap wants 8 GB. WSL2 defaults to roughly half of host RAM. If
`make check` warns about memory, raise it in `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=12GB
processors=8
```

Then `wsl --shutdown` and reopen.

## First run

```sh
make check      # tells you exactly what your host is missing
make lock       # generates sources.lock — AUDIT IT (docs/supply-chain.md)
make sources    # fetches and verifies
```

Stages past `00-host-check` are not implemented. They exit with a message
naming their roadmap phase rather than failing obscurely — that is intentional,
not a bug. See [roadmap.md](roadmap.md).
