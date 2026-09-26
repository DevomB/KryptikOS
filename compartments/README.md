# Compartments

The compartment manager `kryptikd`, the zone definitions it loads, and the
suites that attack it. The model is described in
[../docs/architecture.md](../docs/architecture.md).

## Layout

```
compartments/
  zones/          One TOML definition per shipped zone (vault, net, work, …)
    policy/       Per-zone seccomp additions, named by each definition
  kryptikd/       The compartment manager (Rust)
  tests/          The suites that run it: adversarial, launcher, cli, serve
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
mode   = "encrypted"       # opened when the zone starts, closed (key gone) when it stops
volume = "/var/lib/kryptik/volumes/vault.luks"

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

From inside `untrusted`, with root in that zone, each of these must fail, and
a committed test must show it:

1. Listing processes in another zone
2. Reading another zone's filesystem
3. Reaching the physical NIC
4. Reading anything in `vault`
