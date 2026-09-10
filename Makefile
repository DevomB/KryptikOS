# Kryptik build orchestrator
# Kryptik must be built on Linux. On Windows use WSL2.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ROOT    := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
STAGES  := $(ROOT)/build/stages
TOOLS   := $(ROOT)/tools

export KRYPTIK_ROOT := $(ROOT)

.PHONY: help check check-kernel-eol sources lock verify validate-kernel validate-kernel-hardened toolchain temp-tools chroot system kernel iso audit zones zone-test clean distclean

help:
	@echo "Kryptik build targets"
	@echo
	@echo "  make check       verify the host can build Kryptik"
	@echo "  make sources     fetch upstream tarballs, verify against sources.lock"
	@echo "  make lock        fetch and regenerate sources.lock (audit before committing)"
	@echo "  make toolchain   stage 01: cross toolchain           [Phase 1]"
	@echo "  make temp-tools  stage 02: temporary tools + chroot  [Phase 2]"
	@echo "  make chroot      stage 03: prepare chroot (needs root) [Phase 3]"
	@echo "  make system      stage 04: hardened base system      [Phase 3]"
	@echo "  make kernel      stage 05: hardened kernel           [Phase 4]"
	@echo "  make iso         stage 06: bootable image            [Phase 7]"
	@echo
	@echo "  make verify      verify upstream GPG signatures on fetched sources"
	@echo "  make validate-kernel   check kernel fragment against pinned source"
	@echo "  make check-kernel-eol  fail if the pinned kernel is EOL or not LTS"
	@echo "  make validate-kernel-hardened  check the linux-hardened fragment"
	@echo "  make zones       validate zone definitions + kernel support"
	@echo "  make zone-test   run the Phase 5 adversarial exit test"
	@echo "  make audit       run security audits over the build tree"
	@echo "  make clean       remove build work directory"
	@echo "  make distclean   also remove downloaded sources and output"
	@echo
	@echo "Status: pre-alpha. See docs/roadmap.md for what actually works."

check:
	@$(STAGES)/00-host-check.sh
	@$(TOOLS)/check-kernel-eol.sh

sources:
	@$(TOOLS)/fetch-sources.sh

lock:
	@$(TOOLS)/fetch-sources.sh --lock

verify:
	@$(TOOLS)/verify-signatures.sh

validate-kernel:
	@$(TOOLS)/validate-kernel-config.sh

check-kernel-eol:
	@$(TOOLS)/check-kernel-eol.sh

validate-kernel-hardened:
	@$(TOOLS)/validate-kernel-config.sh --hardened

toolchain: check sources
	@$(STAGES)/01-toolchain.sh

temp-tools: toolchain
	@$(STAGES)/02-temp-tools.sh

chroot: temp-tools
	@echo "stage 03 needs root:"
	@echo "  sudo $(STAGES)/03-chroot-prep.sh mount"

system: temp-tools
	@$(STAGES)/04-base-system.sh

kernel: system
	@$(STAGES)/05-kernel.sh

iso: kernel
	@$(STAGES)/06-iso.sh

zones:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/kryptikd/target/debug/kryptikd check --zones compartments/zones

zone-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/adversarial.sh

audit:
	@$(TOOLS)/audit-setuid.sh

clean:
	@rm -rf "$(ROOT)/build/work"
	@echo "removed build/work"

distclean: clean
	@rm -rf "$(ROOT)/out" "$(ROOT)/sources"
	@echo "removed out/ and sources/"
