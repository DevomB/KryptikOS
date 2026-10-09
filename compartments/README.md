# Compartments

The compartment manager `kryptikd`, the zone definitions it loads, and the
suites that attack it. A zone is what this project calls a compartment: the
word in every command, file and message is zone, and this directory is where
the code that makes zones lives. The zone model is in
[docs/architecture.md](../docs/architecture.md).

## Layout

```text
compartments/
  zones/          One TOML definition per shipped zone (vault, net, work, …)
    policy/       Per-zone seccomp additions, named by each definition
  kryptikd/       The compartment manager (Rust)
  tests/          The suites that run it: adversarial, launcher, cli, serve
```

## A zone definition

The shipped `vault` (`zones/vault.toml`), abridged, with a `cpu_max` added:

```toml
[zone]
name        = "vault"
description = "Keys, password store, secrets. No network stack."

[network]
mode = "none"          # a namespace with only loopback, not a firewall rule

[storage]
mode   = "encrypted"   # opened when the zone starts, closed (key gone) when it stops
volume = "/var/lib/kryptik/volumes/vault.luks"

[policy]
seccomp  = "policy/vault.seccomp"

[limits]
memory_max = "2G"
pids_max   = 128
cpu_max    = "200%"    # two CPUs' worth of time; io_max = "20M" bounds bytes per second on the volume

[identity]
uid_base = 393216      # fixed host uid range, never derived from zone order

[ui]
border_color   = "#9e80ac"
border_pattern = "double"
glyph          = "★"
label          = "VAULT"
```

[Zone policy files](../docs/design/zone-policy-files.md) covers the seccomp
policy files and the optional `[policy] landlock` file, which narrows the
Landlock ruleset every zone gets at entry. No shipped zone names a Landlock
file.

## What a zone cannot do

From inside `untrusted`, with root in that zone, each of these must fail, and
a committed test must show it:

- listing processes in another zone
- reading another zone's filesystem
- reaching the physical NIC
- reading anything in `vault`
- making a syscall the zone filter denies

`tests/adversarial.sh` makes each attempt under the part of a zone that
refuses it: its namespaces, its Landlock rules or its seccomp filter, in CI
and in `make acceptance`'s host suites. The zones suite
(`build/guest-tests/zones-check.sh`) starts the shipped zones themselves on
the installed system.
