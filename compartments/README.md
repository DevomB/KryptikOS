# Compartments

Zone definitions and the compartment manager (`kryptikd`).

The compartment manager `kryptikd`, the zone definitions it loads and the
suites that attack it live here; in [../docs/roadmap.md](../docs/roadmap.md)
this is the compartment layer. The model it implements is specified in
[../docs/architecture.md](../docs/architecture.md).

## Layout

```
compartments/
  zones/          One TOML definition per shipped zone (vault, net, work, …)
    policy/       Per-zone seccomp additions, named by each definition
  kryptikd/       The compartment manager (Rust)
  tests/          The suites that run it as root: adversarial, launcher, cli, serve, update
```

## A zone definition

The shipped `vault`, abridged (the full file is `zones/vault.toml`):

```toml
[zone]
name        = "vault"
description = "Keys, password store, secrets. No network stack."

[network]
mode = "none"          # a namespace with only loopback, not a firewall rule

[storage]
mode      = "encrypted"
volume    = "/var/lib/kryptik/volumes/vault.luks"
unlock    = "on-start"
wipe_keys = "on-stop"

[policy]
seccomp  = "policy/vault.seccomp"

[limits]
memory_max = "2G"
pids_max   = 128

[identity]
uid_base = 393216      # fixed host uid range, never derived from zone order

[ui]
border_color   = "#9e80ac"
border_pattern = "double"
glyph          = "★"
label          = "VAULT"
```

The seccomp policy files are described in the
[zone policy files design](../docs/design/zone-policy-files.md). A
`[policy] landlock` entry is refused, not ignored: per-zone Landlock rules
are not implemented.

## Test requirement

The isolation exit test is adversarial, not descriptive. From inside `untrusted`,
**with root in that zone**, each of the following must be demonstrably
impossible, each proven by a committed test:

1. Listing processes in another zone
2. Reading another zone's filesystem
3. Reaching the physical NIC
4. Reading anything in `vault`

A zone model that has not been attacked has not been tested.
