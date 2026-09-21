# Path to the WireGuard profile `make install` stores as this user's
# Automatic connection; the session agent itself just reconnects whatever is
# currently stored that way, not this variable.
# Override on other machines/users: make install WGD_PROFILE=/path/to/your.conf
WGD_PROFILE ?= $(HOME)/private/.wireguard/andi_split.conf
CONNECTION_NAME ?= andi_split
WGD_BIN ?= /usr/local/bin/wgd

.PHONY: hooks
hooks:
	git config core.hooksPath scripts/hooks

.PHONY: build.release
build.release:
	cargo build --release

.PHONY: install.binary
install.binary:
	@# Binary copy is a dev stand-in for the future Homebrew bottle.
	sudo install -m 0755 target/release/wgd $(WGD_BIN)

.PHONY: install.privileged
install.privileged: install.binary
	sudo $(WGD_BIN) launchd install


.PHONY: install.connection
install.connection:
	@# Exercises the privileged connection-store RPCs (AddConnection,
	@# ConnectConnection, and RemoveConnection via --force) for real against
	@# the daemon `reload` just re-registered, instead of only through unit
	@# tests. Per-user (no --global), matching the session agent's own
	@# per-user model below. --start-mode automatic means this user's session
	@# agent reconnects it on every future login. Fingerprint identity is
	@# separate from --name: --force removes any older "direct" record left
	@# over from a previous, since-edited profile so repeated installs don't
	@# accumulate stale connections. An unmodified re-run of `make install` is
	@# a silent no-op either way. A genuinely new/changed config triggers a
	@# macOS admin-authentication prompt (password or Touch ID) for the add
	@# and, if there was a stale record to clean up, a second one for that
	@# removal.
	$(WGD_BIN) connection add \
		--file $(WGD_PROFILE) \
		--name $(CONNECTION_NAME) \
		--force \
		--start-mode automatic
	$(WGD_BIN) connection connect $(CONNECTION_NAME)

.PHONY: install.completion
install.completion:
	@# Bash completion. `wgd` serves its own completions: run with
	@# COMPLETE=bash it prints the registration script, and the shell then
	@# calls back into the binary for candidates, so completions follow the
	@# CLI without a checked-in script to regenerate. Appended only when
	@# absent, so repeated `make install` runs don't stack duplicate lines.
	@#
	@# `eval "$$(...)"` rather than clap_complete's documented
	@# `source <(COMPLETE=bash wgd)`: process substitution loses the
	@# script under macOS's system bash 3.2 (/bin/bash), leaving the
	@# completion function undefined. The eval form registers correctly on
	@# both 3.2 and bash 5. stderr is dropped so a removed binary (see
	@# `make purge`) leaves a dead no-op here instead of an error on every
	@# new shell.
	@#
	@# zsh and fish use the same mechanism (`COMPLETE=zsh`/`COMPLETE=fish`);
	@# only bash is wired up here.
	@#
	@# Invoked by the same `WGD_BIN` path the rest of this file installs to,
	@# not a bare `wgd`, so a custom install location that isn't on PATH
	@# still registers. The generated script binds to the command name
	@# `wgd` either way -- clap uses its own command name there, not the
	@# path it was invoked by -- so completion works for whichever `wgd`
	@# the user's PATH resolves.
	@grep -qxF 'eval "$$(COMPLETE=bash $(WGD_BIN) 2>/dev/null)"' "$(HOME)/.bashrc" 2>/dev/null || \
		echo 'eval "$$(COMPLETE=bash $(WGD_BIN) 2>/dev/null)"' >> "$(HOME)/.bashrc"

.PHONY: uninstall.legacy-autoconnect
uninstall.legacy-autoconnect:
	@# One-time migration cleanup: `me.pansen.tunmux.autoconnect` (the label
	@# used before the project was renamed to wgd) was replaced by the
	@# session agent (`launchd agent install`, wired up via `reload` below)
	@# in the Phase 5 CLI migration. src/autoconnect.rs is gone, so there's
	@# no subcommand left to tear down a plist installed by an older
	@# checkout. Safe to delete once no dev machine still has one.
	@launchctl bootout gui/$$(id -u)/me.pansen.tunmux.autoconnect 2>/dev/null || true
	@rm -f "$(HOME)/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist"

.PHONY: install
install: build.release install.binary uninstall.legacy-autoconnect
	@# `wgd launchd reload` registers the privileged daemon (escalating on its own),
	@# drops any leftover tunnels, and re-registers the session agent -- do
	@# not re-run `launchd agent install` after `install.connection`
	@# below: that would SIGTERM the instance `reload` just started (bootout
	@# before bootstrap), disconnecting the connection `install.connection`
	@# only just brought up, for no benefit.
	$(WGD_BIN) launchd reload
	$(MAKE) install.connection
	$(MAKE) install.completion


.PHONY: reload
reload:
	@# Re-registers both launchd services and reconnects this user's
	@# `automatic` connections.
	$(WGD_BIN) launchd reload


.PHONY: uninstall.autostart
uninstall.autostart:
	$(WGD_BIN) launchd agent uninstall

.PHONY: uninstall.dns
uninstall.dns:
	@# Clear any tunnel DNS override back to DHCP. A graceful daemon teardown
	@# already restores DNS; this is the fallback for a force-killed daemon
	@# (bootout/pkill above) that skipped cleanup. wgd only ever writes the
	@# primary service's DNS, so clear that one — resolved dynamically instead
	@# of assuming Wi-Fi. Falls back to Wi-Fi if the primary can't be determined.
	@svc=$$(echo 'show State:/Network/Global/IPv4' | scutil | awk -F': ' '/PrimaryService/{print $$2; exit}'); \
	name=$$(echo "show Setup:/Network/Service/$$svc" | scutil | awk -F': ' '/UserDefinedName/{print $$2; exit}'); \
	name=$${name:-Wi-Fi}; \
	echo "==> clearing DNS override on primary service: $$name"; \
	networksetup -setdnsservers "$$name" Empty
	dscacheutil -flushcache
	sudo killall -HUP mDNSResponder

.PHONY: uninstall.privileged
uninstall.privileged: build.release
	@# Unregister the daemon only (bootout + plist/socket removal). Keeps the
	@# binary, wgd group, and logs — see purge.privileged for full teardown.
	@# Prefer the installed binary; if it was already removed, fall back to the
	@# freshly compiled one so `launchd uninstall` still runs.
	bin=$(WGD_BIN); [ -x "$$bin" ] || bin=target/release/wgd; \
	sudo "$$bin" launchd uninstall || true

.PHONY: purge.privileged
purge.privileged: uninstall.privileged
	@# Destructive: after unregistering the daemon, remove the binary, all data,
	@# logs, and the wgd group.
	sudo pkill -f '$(WGD_BIN) launchd agent run' 2>/dev/null || true
	sudo rm -f $(WGD_BIN)
	sudo rm -rf "/Library/Application Support/wgd"
	sudo rm -rf /var/log/wgd
	sudo dseditgroup -o delete wgd 2>/dev/null || true

.PHONY: uninstall
uninstall: uninstall.autostart uninstall.privileged uninstall.dns

.PHONY: purge
purge: uninstall purge.privileged


.PHONY: logs.privileged
logs.privileged:
	sudo find /var/log/wgd/ -type f -name '*.log' -exec sudo tail -n 150 {} +

.PHONY: check.privileged
check.privileged:
	@echo "==> daemon (expect: state = not running, sockets registered)"
	sudo launchctl print system/me.pansen.wgd.privileged | grep -E 'state =|Listeners'
	@echo "==> socket (expect: srw-rw---- root:wgd)"
	stat -f '  %Sp  %Su:%Sg  %N' "/Library/Application Support/wgd/run/ctl.sock"
	@echo "==> socket dir (expect: drwxr-x--- root:wgd)"
	stat -f '  %Sp  %Su:%Sg  %N' "/Library/Application Support/wgd/run"
	@echo "==> group membership (expect: wgd listed)"
	id | tr ',' '\n' | grep wgd || echo "  not in wgd group — re-login required"
	sudo log show --predicate 'sender == "launchd"' --last 10m --info | grep wgd | tail -n30
	ps axu | grep wgd
	ping -c1 -m1 1.1.1.1 || true
	ping -c1 -m1 100.64.1.1 || true
	ping -c1 -m1 10.66.77.2 || true

.PHONY: check
check:
	mkdir -p target
	$(MAKE) logs.privileged check.privileged 2>&1 | tee target/$$(date +%Y-%m-%d%d_%H-%M.%s)_check.log
