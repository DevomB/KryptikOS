# Compartments

Zone definitions and the compartment manager (`kryptikd`).

**Nothing here is implemented.** This is Phase 5 in [../docs/roadmap.md](../docs/roadmap.md)
— the phase where Kryptik stops being "LFS with good compiler flags" and becomes
Kryptik. The model it implements is specified in
[../docs/architecture.md](../docs/architecture.md).

## Planned layout

```
compartments/
  zones/          One TOML definition per zone (vault, net, work, …)
  policy/         Per-zone seccomp filters and Landlock rulesets
  kryptikd/       The compartment manager
```

## Zone definition sketch

Not a stable format — recorded so the design discussion has something concrete
to argue with.

```toml
[zone]
name        = "vault"
description = "Long-term secrets. No network stack."

[network]
mode = "none"          # none | routed | nic
                       # "none" means no net namespace at all, not a firewall rule

[storage]
mode       = "encrypted"   # encrypted | ephemeral
volume     = "/dev/kryptik/vault"
unlock     = "on-start"
wipe_keys  = "on-stop"

[policy]
seccomp  = "policy/vault.seccomp"     # default-deny allowlist
landlock = "policy/vault.landlock"

[limits]
memory_max = "2G"
pids_max   = 128

[ui]
border_color = "#c9a227"   # load-bearing: the user must be able to tell zones apart
```

## Test requirement

Phase 5's exit test is adversarial, not descriptive. From inside `untrusted`,
**with root in that zone**, each of the following must be demonstrably
impossible, each proven by a committed test:

1. Listing processes in another zone
2. Reading another zone's filesystem
3. Reaching the physical NIC
4. Reading anything in `vault`

A zone model that has not been attacked has not been tested.
