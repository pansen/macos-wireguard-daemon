# Path to the WireGuard profile `make install` stores as this user's
# Automatic connection; the session agent itself just reconnects whatever is
# currently stored that way, not this variable.
# Override on other machines/users: make install WGD_PROFILE=/path/to/your.conf
WGD_PROFILE ?= $(HOME)/private/.wireguard/andi_split.conf
CONNECTION_NAME ?= andi_split
WGD_BIN ?= /usr/local/bin/wgd
# The Homebrew cask's `wgd` link and the staged binary it points to. Set only
# when the cask is installed; `make install` then replaces that binary instead
# of putting a second, unmanaged copy next to it.
BREW_WGD ?= /opt/homebrew/bin/wgd
BREW_WGD_STAGED := $(if $(findstring /Caskroom/,$(realpath $(BREW_WGD))),$(realpath $(BREW_WGD)))
# The installed binary, or the freshly compiled one once purge removed it.
WGD ?= $(or $(wildcard $(WGD_BIN)),target/release/wgd)

.PHONY: hooks
hooks:
	git config core.hooksPath scripts/hooks

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: build.release
build.release: fmt
	cargo build --release

.PHONY: install.binary
install.binary:
ifneq ($(BREW_WGD_STAGED),)
	@# Cask installed: overwrite its staged binary, then let `launchd install`
	@# copy it to $(WGD_BIN) exactly as the cask's installer step does, so
	@# Homebrew's link, the trusted copy and the daemon run the same build.
	@# `brew reinstall --cask macos-wireguard-daemon` restores the release.
	install -m 0755 target/release/wgd $(BREW_WGD_STAGED)
	sudo $(BREW_WGD) launchd install
else
	sudo install -m 0755 target/release/wgd $(WGD_BIN)
endif

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
	@# Writes the `# begin: wgd managed` block into ~/.bashrc; see
	@# src/completion.rs for why it uses `eval` and keeps symlinked dotfiles.
	$(WGD) completion install

.PHONY: install
install: build.release install.binary
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
	@# Restore DNS a force-killed helper left behind (escalates on its own).
	@# Needs the helpers stopped first, see `uninstall`.
	$(WGD) dns repair

.PHONY: uninstall.privileged
uninstall.privileged: build.release
	@# Unregister the daemon only (bootout + plist/socket removal). Keeps the
	@# binary, wgd group, and logs; see purge.privileged for full teardown.
	-sudo $(WGD) launchd uninstall

.PHONY: purge.privileged
purge.privileged: build.release
	@# Destructive: `launchd purge` stops everything, restores DNS, and removes
	@# all data, logs, the authorization right and the wgd group. Removing the
	@# binary stays here: it is a dev install, and wgd never deletes itself.
	$(WGD) launchd purge
	sudo rm -f $(WGD_BIN)

.PHONY: uninstall
# Order matters: uninstall.dns needs the helpers stopped (uninstall.privileged
# disconnects everything) and the binary still installed. Run serially.
uninstall: uninstall.autostart uninstall.privileged uninstall.dns

.PHONY: purge
purge: purge.privileged


.PHONY: logs.privileged
logs.privileged:
	$(WGD) logs

.PHONY: check
check:
	@# Same report a Homebrew user attaches to a bug report, redacted.
	mkdir -p target
	$(WGD) doctor --report target/$$(date +%Y-%m-%d_%H-%M.%s)_check.log

.PHONY: bar
bar:
	@# Menu bar app (Swift UI over the Rust core); output target/WgdBar.app.
	$(MAKE) -C macos/WgdBar
