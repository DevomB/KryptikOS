#!/usr/bin/env bash
# Stage 01 — Cross toolchain (binutils/gcc/glibc, two passes)
# Phase 1 of docs/roadmap.md

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config
load_hardening

die "Stage 01-toolchain is not implemented yet.

  Cross toolchain (binutils/gcc/glibc, two passes)
  Tracked as Phase 1 in docs/roadmap.md.

Kryptik is pre-alpha; the build system is scaffolded but no stage past
00-host-check produces output. This message is deliberate — a stub that
silently succeeded would be worse than one that stops."
