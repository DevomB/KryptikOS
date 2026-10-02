# Security policy

## Reporting a vulnerability

Report it privately, through this repository's Security tab ("Report a
vulnerability"), not in a public issue. Say what you found, how to reproduce
it, and which release and machine you saw it on.

A confirmed vulnerability is fixed in a release that reaches installed
machines through the update channel. It is then described in a GitHub
security advisory, crediting you if you want to be.

## What is supported

The newest release. Production releases, 1.0.0 and later, update over the
channel. Development releases (0.x) are superseded by 1.0.0 and get no fixes.

## Scope

[docs/threat-model.md](docs/threat-model.md) says what Kryptik defends and
what it does not. In scope:
- a way across a zone's boundary;
- a flaw in the update chain, the boot chain or the release signing;
- a flaw in Kryptik's own code (kryptikd, kryptik-wlproxy and the tools).

A flaw in an upstream package belongs to its upstream. Tell us as well:
Kryptik pins and patches what it ships.
