#!/usr/bin/env bash
# Stage 04 — Hardened base system
# Phase 3 of docs/roadmap.md

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config
load_hardening

die "Stage 04-base-system is not implemented yet.

  Hardened base system
  Tracked as Phase 3 in docs/roadmap.md.

Kryptik is pre-alpha; the build system is scaffolded but no stage past
00-host-check produces output. This message is deliberate — a stub that
silently succeeded would be worse than one that stops."
