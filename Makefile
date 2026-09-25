# Kryptik build. Linux only; on Windows use WSL2.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# $(CURDIR) rather than $(dir $(abspath ...)): make's text functions split on
# spaces, and a checkout path may contain one. Quote paths in recipes too.
ROOT    := $(CURDIR)
STAGES  := $(ROOT)/build/stages
TOOLS   := $(ROOT)/tools
CHROOTD := $(STAGES)/03-chroot-prep.sh

# --- build contract ---------------------------------------------------------
#
# Every stage and the chroot agree on these names. `?=` lets the environment
# win, so `KRYPTIK_WORK=/build/kryptik make toolchain` works; the work tree
# must be on a filesystem with POSIX ownership (not /mnt/c under WSL2).
KRYPTIK_WORK    ?= $(ROOT)/build/work
KRYPTIK_SOURCES ?= $(ROOT)/sources
KRYPTIK_OUT     ?= $(ROOT)/out
# Empty: build/lib/common.sh picks a job count from CPUs and RAM.
KRYPTIK_JOBS    ?=
# refuse | rebuild (see the stamp notes in build/lib/common.sh).
KRYPTIK_STALE   ?= refuse
# Stamped into /etc/os-release; --dirty so an image never claims a clean tree.
KRYPTIK_BUILD_COMMIT ?= $(shell git -C "$(ROOT)" describe --always --dirty --abbrev=40 2>/dev/null || echo unknown)
# kryptikd and kryptik-wlproxy are static Rust binaries built outside the
# chroot and installed by stage 04.
KRYPTIK_KRYPTIKD_BIN ?=
KRYPTIK_WLPROXY_BIN ?=

export KRYPTIK_ROOT := $(ROOT)
# Read through the shell: versions.env is shell syntax, not make syntax.
V_LINUX := $(shell . "$(ROOT)/build/config/versions.env" && echo $$V_LINUX)
# Release name stamped into the media.
KRYPTIK_VERSION ?=
export KRYPTIK_VERSION
# Where the image's net zone asks for releases (docs/design/update-channel.md);
# empty, the image names none and fetches nothing.
KRYPTIK_CHANNEL ?=
export KRYPTIK_WORK
export KRYPTIK_SOURCES
export KRYPTIK_OUT
export KRYPTIK_JOBS
export KRYPTIK_STALE

# --- privilege --------------------------------------------------------------
#
# Only stage 03's mounts and the chroot call need root, so SUDO wraps the
# chroot driver and nothing else. SUDO= when already root; SUDO=doas etc.
SUDO ?= sudo

# sudo resets the environment, so the contract is passed explicitly.
CHROOT_ENV := KRYPTIK_ROOT="$(ROOT)" \
              KRYPTIK_WORK="$(KRYPTIK_WORK)" \
              KRYPTIK_SOURCES="$(KRYPTIK_SOURCES)" \
              KRYPTIK_JOBS="$(KRYPTIK_JOBS)" \
              KRYPTIK_STALE="$(KRYPTIK_STALE)" \
              KRYPTIK_BUILD_COMMIT="$(KRYPTIK_BUILD_COMMIT)" \
              KRYPTIK_KRYPTIKD_BIN="$(KRYPTIK_KRYPTIKD_BIN)" \
              KRYPTIK_WLPROXY_BIN="$(KRYPTIK_WLPROXY_BIN)" \
              TERM="$(TERM)" \
              NO_COLOR="$(NO_COLOR)" \
              $(if $(CARGO_TARGET_DIR),CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)") \
              $(if $(TMPDIR),TMPDIR="$(TMPDIR)")

CHROOT_RUN := $(SUDO) env $(CHROOT_ENV) "$(CHROOTD)"

.PHONY: help paths check sources lock verify verify-provenance check-pins \
        validate-kernel validate-kernel-hardened validate-kernel-boot check-kernel-eol \
        resolve-kernel-config check-kernel-hardening \
        toolchain temp-tools sysroot-ready system kernel \
        chroot chroot-enter chroot-umount chroot-status \
        iso media ovmf-vars media-smoke-usb media-smoke-iso media-smoke-secureboot \
        media-refused-foreign-keys install-test integrity-test update-test \
        state-test zones-test gui-test acceptance \
        zones zone-test launcher-test zone-tests cli-test serve-test \
        test test-libc-unwind smoke-userspace \
        audit-artifacts audit-artifacts-strict manifest verify-manifest \
        reset-stamps clean distclean

help:
	@echo "Kryptik build targets"
	@echo
	@echo "  make check       verify the host can build Kryptik"
	@echo "  make sources     fetch upstream tarballs, verify against sources.lock"
	@echo "  make lock        fetch and regenerate sources.lock (audit before committing)"
	@echo "  make toolchain   stage 01: cross toolchain"
	@echo "  make temp-tools  stage 02: temporary tools"
	@echo "                   (stages 01 and 02 are UNPRIVILEGED - run them as you)"
	@echo "  make system      stage 04: hardened base system"
	@echo "  make kernel      stage 05: hardened kernel"
	@echo "  make iso         stage 06: verified root image, signed kernels, USB image + ISO"
	@echo "  make media       stage 06 only (sysroot and kernel already built)"
	@echo
	@echo "  'system' and 'kernel' build INSIDE the chroot. They mount it, run"
	@echo "  the stage, and unmount again. Only the mounts and the chroot call"
	@echo "  are privileged; override the escalation with SUDO=... or SUDO= ."
	@echo
	@echo "  make chroot          mount the chroot and leave it mounted"
	@echo "  make chroot-enter    interactive shell inside the chroot"
	@echo "  make chroot-umount   unmount it"
	@echo "  make chroot-status   what is mounted right now"
	@echo
	@echo "  make acceptance  every installed-system suite under KVM, one verdict"
	@echo "  make media-smoke-usb | media-smoke-iso   boot the media under OVMF, assert"
	@echo "  make media-smoke-secureboot              same with the developer key enrolled"
	@echo "  make media-refused-foreign-keys          Microsoft keys only: must be refused"
	@echo "  make install-test  install to a blank virtual disk, boot it alone, refusals"
	@echo "  make integrity-test  Secure Boot enforced, foreign boot file refused, root tamper refused, recovery"
	@echo "  make update-test PAYLOAD_A=.. PAYLOAD_B=..  A/B update, rollback, refusals, interruptions"
	@echo "  make state-test | zones-test | gui-test    the state partition, zones, the desktop"
	@echo
	@echo "  make verify      verify upstream GPG signatures on fetched sources"
	@echo "  make verify-provenance  signed tags + publisher checksums for the rest"
	@echo "  make check-pins        survey every pin against its upstream (network), then"
	@echo "                   fail on one that is behind without a current review in"
	@echo "                   tools/pin-reviews.tsv. PINS_FLAGS=--no-held is what a release asks"
	@echo "  make validate-kernel | validate-kernel-hardened | validate-kernel-boot"
	@echo "                   check a kernel fragment's symbols against the pinned source"
	@echo "  make check-kernel-eol  fail if the pinned kernel is EOL or not LTS"
	@echo "  make check-kernel-hardening  resolve the config as stage 05 does, refuse a"
	@echo "                   dropped fragment line, run kernel-hardening-checker on it"
	@echo
	@echo "  make test        every unit suite (tools/test-*), then the compartment suites"
	@echo "  make test-NAME   one suite: tools/test-NAME.sh"
	@echo "  make zones       validate zone definitions + kernel support"
	@echo "  make zone-test   run the isolation exit test (the primitives)"
	@echo "  make launcher-test  attack \`kryptikd run\` itself (the launch path)"
	@echo "  make zone-tests  both of the above; what a zone change must pass"
	@echo "  make cli-test    test \`kryptik\`, the command a person types"
	@echo "  make serve-test  drive \`kryptikd serve\`, the launch daemon, over its socket"
	@echo "  make test-libc-unwind  prove the target libc can unwind (needs root)"
	@echo "  make smoke-userspace   RUN the built userland in the chroot (needs root)"
	@echo
	@echo "  make audit-artifacts   audit the ELF objects the build actually produced"
	@echo "  make audit-artifacts-strict   ... and fail on reported findings too"
	@echo "  make manifest          record what was built and what built it"
	@echo "  make verify-manifest   check the tree still matches that record"
	@echo "  make paths       print the resolved build contract"
	@echo "  make reset-stamps  archive all build stamps (does not delete)"
	@echo "  make clean       remove the build work directory"
	@echo "  make distclean   also remove downloaded sources and output"
	@echo
	@echo "Contract (override any of these on the command line or in the env):"
	@echo "  KRYPTIK_WORK     = $(KRYPTIK_WORK)"
	@echo "  KRYPTIK_SOURCES  = $(KRYPTIK_SOURCES)"
	@echo "  KRYPTIK_JOBS     = $(if $(KRYPTIK_JOBS),$(KRYPTIK_JOBS),auto)"
	@echo "  KRYPTIK_STALE    = $(KRYPTIK_STALE)"
	@echo "  KRYPTIK_BUILD_COMMIT = $(KRYPTIK_BUILD_COMMIT)"
	@echo "  KRYPTIK_KRYPTIKD_BIN = $(if $(KRYPTIK_KRYPTIKD_BIN),$(KRYPTIK_KRYPTIKD_BIN),(not set - the image will have no kryptikd))"
	@echo "  KRYPTIK_WLPROXY_BIN  = $(if $(KRYPTIK_WLPROXY_BIN),$(KRYPTIK_WLPROXY_BIN),(not set - zones will have no display))"
	@echo "  KRYPTIK_CHANNEL  = $(if $(KRYPTIK_CHANNEL),$(KRYPTIK_CHANNEL),(not set - the image fetches no updates))"
	@echo "  SUDO             = $(if $(SUDO),$(SUDO),(none))"
	@echo
	@echo "Status: pre-alpha. See docs/roadmap.md for what actually works."

paths:
	@echo "KRYPTIK_ROOT    = $(ROOT)"
	@echo "KRYPTIK_BUILD_COMMIT = $(KRYPTIK_BUILD_COMMIT)"
	@echo "KRYPTIK_SOURCES = $(KRYPTIK_SOURCES)"
	@echo "KRYPTIK_WORK    = $(KRYPTIK_WORK)"
	@echo "  sysroot       = $(KRYPTIK_WORK)/sysroot"
	@echo "  stamps        = $(KRYPTIK_WORK)/.stamps"
	@echo "  logs          = $(KRYPTIK_WORK)/logs"
	@echo "  build trees   = $(KRYPTIK_WORK)/build"
	@echo "KRYPTIK_OUT     = $(KRYPTIK_OUT)"
	@echo
	@echo "Inside the chroot these appear as /kryptik, /kryptik-sources and"
	@echo "/kryptik-work; the sysroot is / and there is no second view of it."

# --- host and sources -------------------------------------------------------

check:
	@"$(STAGES)"/00-host-check.sh
	@"$(TOOLS)"/check-kernel-eol.sh

sources:
	@"$(TOOLS)"/fetch-sources.sh

lock:
	@"$(TOOLS)"/fetch-sources.sh --lock

verify:
	@"$(TOOLS)"/verify-signatures.sh

verify-provenance:
	@"$(TOOLS)"/verify-provenance.sh

# The survey asks the network and judges nothing; the gate reads the survey
# and tools/pin-reviews.tsv and never the network.
PINS_SURVEY ?= $(KRYPTIK_WORK)/pin-survey.tsv
check-pins:
	@mkdir -p "$(dir $(PINS_SURVEY))"
	@"$(TOOLS)"/check-source-currency.sh --tsv > "$(PINS_SURVEY)"
	@"$(TOOLS)"/check-pin-reviews.sh --survey "$(PINS_SURVEY)" $(PINS_FLAGS)

# --- kernel configuration ---------------------------------------------------

validate-kernel:
	@"$(TOOLS)"/validate-kernel-config.sh

validate-kernel-hardened:
	@"$(TOOLS)"/validate-kernel-config.sh --hardened

validate-kernel-boot:
	@"$(TOOLS)"/validate-kernel-config.sh --boot

check-kernel-eol:
	@"$(TOOLS)"/check-kernel-eol.sh

# Needs the kernel tarball, the linux-hardened patch and the checker from
# `make sources`, and host gcc plugin headers (gcc-N-plugin-dev).
resolve-kernel-config:
	@"$(TOOLS)"/resolve-kernel-config.sh

check-kernel-hardening: resolve-kernel-config
	@"$(TOOLS)"/check-kernel-hardening.sh --config "$(KRYPTIK_WORK)/kconfig-tree/kryptik.config"

# --- stages -----------------------------------------------------------------

toolchain: check sources
	@"$(STAGES)"/01-toolchain.sh

temp-tools: toolchain
	@"$(STAGES)"/02-temp-tools.sh

# Checks that stage 02 finished rather than running it: under sudo it would
# rebuild the cross toolchain as root.
sysroot-ready:
	@if [[ ! -x "$(KRYPTIK_WORK)/sysroot/usr/bin/gcc" ]]; then \
	    echo "Stage 02 has not completed: no target compiler at"; \
	    echo "  $(KRYPTIK_WORK)/sysroot/usr/bin/gcc"; \
	    echo; \
	    echo "Build it first, UNPRIVILEGED:"; \
	    echo "  make temp-tools"; \
	    exit 1; \
	fi

system: sysroot-ready
	@$(CHROOT_RUN) run /kryptik/build/stages/04-base-system.sh

# The EOL check needs the network and the chroot has none, so it runs here first.
kernel: check-kernel-eol system
	@$(CHROOT_RUN) run /kryptik/build/stages/05-kernel.sh

chroot: sysroot-ready
	@$(CHROOT_RUN) mount

chroot-enter:
	@$(CHROOT_RUN) enter

chroot-umount:
	@$(CHROOT_RUN) umount

chroot-status:
	@"$(CHROOTD)" status

# --- install media and acceptance (docs/design/boot-and-updates.md) ----------

# Stage 06 runs as root: the sysroot has root-only paths and the relink goes
# through the chroot.
iso: kernel
	@$(SUDO) env $(CHROOT_ENV) KRYPTIK_VERSION="$(KRYPTIK_VERSION)" KRYPTIK_CHANNEL="$(KRYPTIK_CHANNEL)" "$(STAGES)"/06-iso.sh

media:
	@$(SUDO) env $(CHROOT_ENV) KRYPTIK_VERSION="$(KRYPTIK_VERSION)" KRYPTIK_CHANNEL="$(KRYPTIK_CHANNEL)" "$(STAGES)"/06-iso.sh

MEDIA_USB ?= $(shell ls -t "$(KRYPTIK_WORK)"/images/kryptik-*-usb.img 2>/dev/null | head -1)
MEDIA_ISO ?= $(shell ls -t "$(KRYPTIK_WORK)"/images/kryptik-*.iso 2>/dev/null | head -1)

# OVMF variable stores: clean (no keys), enrolled (developer key, Secure Boot
# on), ms (Microsoft keys only, so ours are refused).
ovmf-vars:
	@"$(TOOLS)"/image/ovmf-vars.sh

media-smoke-usb:
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/media-smoke.sh --usb "$(MEDIA_USB)" --vars clean

media-smoke-iso:
	@test -n "$(MEDIA_ISO)" || { echo "no ISO under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/media-smoke.sh --iso "$(MEDIA_ISO)" --vars clean

media-smoke-secureboot: ovmf-vars
	@"$(TOOLS)"/image/media-smoke.sh --usb "$(MEDIA_USB)" --vars enrolled

media-refused-foreign-keys:
	@"$(TOOLS)"/image/media-smoke.sh --usb "$(MEDIA_USB)" --vars ms --expect-refused

install-test:
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/install-test.sh --usb "$(MEDIA_USB)" --vars $(or $(VARS),clean)

integrity-test: ovmf-vars
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/integrity-test.sh --usb "$(MEDIA_USB)"

# PAYLOAD_A and PAYLOAD_B are the stage 06 payloads of two releases;
# MEDIA_USB is release A's medium.
PAYLOAD_A ?=
PAYLOAD_B ?=
update-test:
	@test -n "$(PAYLOAD_A)" -a -n "$(PAYLOAD_B)" || { echo "set PAYLOAD_A=... PAYLOAD_B=... (stage 06 payload dirs of two releases)"; exit 1; }
	@"$(TOOLS)"/image/update-test.sh --usb-a "$(MEDIA_USB)" --payload-a "$(PAYLOAD_A)" --payload-b "$(PAYLOAD_B)" --vars $(or $(VARS),clean)

state-test:
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/state-test.sh --usb "$(MEDIA_USB)"

zones-test:
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/zones-test.sh --usb "$(MEDIA_USB)"

gui-test:
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/gui-test.sh --usb "$(MEDIA_USB)"

# Every acceptance suite, one verdict, as root. MEDIA_USB/MEDIA_ISO are passed
# on only when named explicitly; otherwise acceptance.sh tests the
# highest-versioned medium and updates to it from the release before it.
# EXPORT=DIR copies the tested media, hashes and report there.
EXPORT ?=
acceptance:
	@$(SUDO) env $(CHROOT_ENV) "$(TOOLS)"/acceptance.sh \
	    $(if $(filter command line environment,$(origin MEDIA_USB)),--media-usb "$(MEDIA_USB)") \
	    $(if $(filter command line environment,$(origin MEDIA_ISO)),--media-iso "$(MEDIA_ISO)") \
	    $(if $(PAYLOAD_A),--payload-a "$(PAYLOAD_A)") $(if $(PAYLOAD_B),--payload-b "$(PAYLOAD_B)") \
	    $(if $(EXPORT),--export "$(EXPORT)") $(if $(ONLY),--only "$(ONLY)")

# --- compartment suites -----------------------------------------------------

zones:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/kryptikd/target/debug/kryptikd check --zones compartments/zones

# adversarial.sh tests the isolation primitives, launcher.sh tests how
# `kryptikd run` applies them; a zone change must pass both (zone-tests).
zone-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/adversarial.sh

launcher-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/launcher.sh

zone-tests: zone-test launcher-test

cli-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/cli.sh

serve-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/serve.sh

# --- unit suites ------------------------------------------------------------

# Runs every suite and names the ones it could not run.
test:
	@"$(TOOLS)"/run-tests.sh

test-%:
	@"$(TOOLS)"/test-$*.sh

# Inside the chroot: it is the target's libc that has to unwind.
test-libc-unwind:
	@$(CHROOT_RUN) run /kryptik/tools/test-libc-unwind.sh

# Runs the built userland, compiles with the target compiler and loads
# hardened_malloc. Needs root and a finished sysroot.
smoke-userspace:
	@$(SUDO) "$(TOOLS)"/test-userspace-smoke.sh

# --- build output -----------------------------------------------------------

# Reads the ELF headers of what stage 04 installed: a package can ignore the
# hardening flags without failing its build.
audit-artifacts:
	@"$(TOOLS)"/check-artifact-hardening.sh "$(KRYPTIK_WORK)/sysroot"

audit-artifacts-strict:
	@"$(TOOLS)"/check-artifact-hardening.sh "$(KRYPTIK_WORK)/sysroot" --strict

# A record of the tree and of what produced it.
manifest:
	@"$(TOOLS)"/artifact-manifest.sh --root "$(KRYPTIK_WORK)/sysroot" \
	                                  --out  "$(KRYPTIK_WORK)/artifact-manifest.txt"

verify-manifest:
	@"$(TOOLS)"/artifact-manifest.sh --root "$(KRYPTIK_WORK)/sysroot" \
	                                  --verify "$(KRYPTIK_WORK)/artifact-manifest.txt"

# --- housekeeping -----------------------------------------------------------

# Archives the stamps rather than deleting them.
reset-stamps:
	@if [[ -d "$(KRYPTIK_WORK)/.stamps" ]]; then \
	    dest="$(KRYPTIK_WORK)/.stamps/legacy/reset-$$(date +%Y%m%dT%H%M%S)"; \
	    mkdir -p "$$dest"; \
	    found=0; \
	    for f in "$(KRYPTIK_WORK)/.stamps"/*; do \
	        [[ -f "$$f" ]] || continue; \
	        mv "$$f" "$$dest/"; found=1; \
	    done; \
	    if [[ "$$found" == 1 ]]; then echo "archived stamps to $$dest"; \
	    else rmdir "$$dest" 2>/dev/null || true; echo "no stamps to archive"; fi; \
	else echo "no stamp directory at $(KRYPTIK_WORK)/.stamps"; fi

# Refuses while anything is mounted inside the tree: the chroot binds the
# host's /dev.
clean:
	@"$(CHROOTD)" guard-unmounted
	@rm -rf "$(KRYPTIK_WORK)"
	@echo "removed $(KRYPTIK_WORK)"

distclean: clean
	@rm -rf "$(KRYPTIK_OUT)" "$(KRYPTIK_SOURCES)"
	@echo "removed $(KRYPTIK_OUT) and $(KRYPTIK_SOURCES)"
