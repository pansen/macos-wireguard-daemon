# Path to the WireGuard profile the login autoconnect agent connects with.
# Override on other machines/users: make install TUNMUX_PROFILE=/path/to/your.conf
TUNMUX_PROFILE ?= $(HOME)/private/.wireguard/andi_split.conf

.PHONY: submodule
submodule:
	git submodule update --init --recursive

.PHONY: hooks
hooks:
	git config core.hooksPath scripts/hooks

.PHONY: build.release
build.release: submodule
	cargo build --release

.PHONY: install/privileged
install/privileged:
	sudo dseditgroup -o read tunmux >/dev/null 2>&1 || sudo dseditgroup -o create tunmux
	sudo dseditgroup -o edit -a $$(id -un) -t user tunmux

	sudo install -m 0755 target/release/tunmux /usr/local/bin/tunmux
	sudo mkdir -p /var/log/tunmux && sudo chmod 755 /var/log/tunmux
	sudo mkdir -p "/Library/Application Support/tunmux/run"
	sudo chgrp tunmux "/Library/Application Support/tunmux/run"
	sudo chmod 0750 "/Library/Application Support/tunmux/run"

	sudo cp etc/me.pansen.tunmux.privileged.plist /Library/LaunchDaemons/
	sudo chown root:wheel /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo chmod 644 /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	GID=$$(dscl . -read /Groups/tunmux PrimaryGroupID | awk '{print $$2}'); \
	sudo /usr/libexec/PlistBuddy -c "Delete :Sockets:Listeners:SockPathGroup" \
		/Library/LaunchDaemons/me.pansen.tunmux.privileged.plist 2>/dev/null || true; \
	sudo /usr/libexec/PlistBuddy -c "Add :Sockets:Listeners:SockPathGroup integer $$GID" \
		/Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo launchctl bootout system/me.pansen.tunmux.privileged 2>/dev/null || true
	@# Clear any stale "disabled" override — bootstrap of a disabled label fails with EIO (5).
	sudo launchctl enable system/me.pansen.tunmux.privileged
	sudo launchctl bootstrap system /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist


.PHONY: install/autostart
install/autostart:
	mkdir -p $$HOME/Library/LaunchAgents
	sed -e "s|__HOME__|$$HOME|g" -e "s|__PROFILE__|$(TUNMUX_PROFILE)|g" etc/me.pansen.tunmux.autoconnect.plist > $$HOME/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist
	launchctl bootout gui/$$(id -u)/me.pansen.tunmux.autoconnect 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) $$HOME/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist
	@# test now
	launchctl kickstart -k gui/$$(id -u)/me.pansen.tunmux.autoconnect
	@# inspect
	launchctl print gui/$$(id -u)/me.pansen.tunmux.autoconnect


.PHONY: install
install: build.release install/privileged install/autostart


.PHONY: reload/privileged
reload/privileged:
	sudo launchctl kickstart -k system/me.pansen.tunmux.privileged

.PHONY: reload/connections
reload/connections:
	/usr/local/bin/tunmux --debug disconnect --provider wgconf --all

.PHONY: reload/autostart
reload/autostart:
	launchctl kickstart -k gui/$$(id -u)/me.pansen.tunmux.autoconnect
	launchctl print gui/$$(id -u)/me.pansen.tunmux.autoconnect

.PHONY: reload
reload: reload/privileged reload/connections reload/autostart


.PHONY: uninstall/autostart
uninstall/autostart:
	launchctl bootout gui/$$(id -u)/me.pansen.tunmux.autoconnect 2>/dev/null || true
	rm -f $$HOME/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist

.PHONY: uninstall/dns
uninstall/dns:
	@# Clear any tunnel DNS override back to DHCP. A graceful daemon teardown
	@# already restores DNS; this is the fallback for a force-killed daemon
	@# (bootout/pkill above) that skipped cleanup. tunmux only ever writes the
	@# primary service's DNS, so clear that one — resolved dynamically instead
	@# of assuming Wi-Fi. Falls back to Wi-Fi if the primary can't be determined.
	@svc=$$(echo 'show State:/Network/Global/IPv4' | scutil | awk -F': ' '/PrimaryService/{print $$2; exit}'); \
	name=$$(echo "show Setup:/Network/Service/$$svc" | scutil | awk -F': ' '/UserDefinedName/{print $$2; exit}'); \
	name=$${name:-Wi-Fi}; \
	echo "==> clearing DNS override on primary service: $$name"; \
	networksetup -setdnsservers "$$name" Empty
	dscacheutil -flushcache
	sudo killall -HUP mDNSResponder

.PHONY: uninstall/privileged
uninstall/privileged:
	sudo launchctl bootout system/me.pansen.tunmux.privileged 2>/dev/null || true
	sudo launchctl disable system/me.pansen.tunmux.privileged 2>/dev/null || true
	sudo pkill -f '/usr/local/bin/tunmux wgconf' 2>/dev/null || true
	sudo rm -f /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo rm -f /usr/local/bin/tunmux
	sudo rm -rf "/Library/Application Support/tunmux"
	sudo rm -rf /var/log/tunmux
	sudo dseditgroup -o delete tunmux 2>/dev/null || true

.PHONY: uninstall
uninstall: uninstall/autostart uninstall/privileged uninstall/dns


.PHONY: check/privileged
check/privileged:
	@echo "==> daemon (expect: state = not running, sockets registered)"
	sudo launchctl print system/me.pansen.tunmux.privileged | grep -E 'state =|Listeners'
	@echo "==> socket (expect: srw-rw---- root:tunmux)"
	stat -f '  %Sp  %Su:%Sg  %N' "/Library/Application Support/tunmux/run/ctl.sock"
	@echo "==> socket dir (expect: drwxr-x--- root:tunmux)"
	stat -f '  %Sp  %Su:%Sg  %N' "/Library/Application Support/tunmux/run"
	@echo "==> group membership (expect: tunmux listed)"
	id | tr ',' '\n' | grep tunmux || echo "  not in tunmux group — re-login required"
	sudo log show --predicate 'sender == "launchd"' --last 10m --info | grep tunmux | tail -n30
	sudo tail -n20  /var/log/tunmux/*
	ps axu | grep tunmux
	ping -c2 55.56.57.2

.PHONY: check
check: check/privileged


# --- Release ---------------------------------------------------------------
# Cut a release from the CLI: push a v-prefixed tag and let the Release
# workflow (.github/workflows/release.yml) build and publish the GitHub
# Release with artifacts. Do NOT create the release in the web UI — a
# published release is immutable and the asset upload would fail.
#
# Version defaults to Cargo.toml; override with:  make release VERSION=1.2.3
VERSION ?= $(shell grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
TAG := v$(VERSION)

.PHONY: release
release:
	@git diff --quiet && git diff --cached --quiet || { echo "==> working tree dirty; commit or stash first"; exit 1; }
	@git rev-parse -q --verify "refs/tags/$(TAG)" >/dev/null && { echo "==> tag $(TAG) already exists"; exit 1; } || true
	@echo "==> tagging $(TAG) at $$(git rev-parse --short HEAD)"
	git tag -a "$(TAG)" -m "Release $(TAG)"
	git push origin "$(TAG)"
	@echo "==> pushed $(TAG) — the Release workflow will build and publish"
