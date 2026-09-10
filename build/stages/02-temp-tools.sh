#!/usr/bin/env bash
# Stage 02 — Temporary tools and chroot entry
# Phase 2 of docs/roadmap.md

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config
load_hardening

die "Stage 02-temp-tools is not implemented yet.

  Temporary tools and chroot entry
  Tracked as Phase 2 in docs/roadmap.md.

Kryptik is pre-alpha; the build system is scaffolded but no stage past
00-host-check produces output. This message is deliberate — a stub that
silently succeeded would be worse than one that stops."
