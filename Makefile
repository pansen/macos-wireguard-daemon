# Path to the WireGuard profile the login autoconnect agent connects with.
# Override on other machines/users: make install TUNMUX_PROFILE=/path/to/your.conf
TUNMUX_PROFILE ?= $(HOME)/private/.wireguard/andi_split.conf

.PHONY: hooks
hooks:
	git config core.hooksPath scripts/hooks

.PHONY: build.release
build.release:
	cargo build --release

.PHONY: install/binary
install/binary:
	@# Binary copy is a dev stand-in for the future Homebrew bottle.
	sudo install -m 0755 target/release/tunmux /usr/local/bin/tunmux

.PHONY: install/privileged
install/privileged: install/binary
	sudo /usr/local/bin/tunmux launchd install


.PHONY: install
install: build.release install/binary
	@# `tunmux reload` registers the privileged daemon (escalating on its own)
	@# and the autoconnect agent; --file seeds the agent on a first install.
	/usr/local/bin/tunmux reload --file $(TUNMUX_PROFILE)


.PHONY: reload
reload:
	@# Re-registers both launchd services and reconnects, keeping whatever
	@# profile the installed autoconnect agent was set up with.
	/usr/local/bin/tunmux reload


.PHONY: uninstall/autostart
uninstall/autostart:
	/usr/local/bin/tunmux autoconnect uninstall

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
uninstall/privileged: build.release
	@# Unregister the daemon only (bootout + plist/socket removal). Keeps the
	@# binary, tunmux group, and logs — see purge/privileged for full teardown.
	@# Prefer the installed binary; if it was already removed, fall back to the
	@# freshly compiled one so `launchd uninstall` still runs.
	bin=/usr/local/bin/tunmux; [ -x "$$bin" ] || bin=target/release/tunmux; \
	sudo "$$bin" launchd uninstall || true

.PHONY: purge/privileged
purge/privileged: uninstall/privileged
	@# Destructive: after unregistering the daemon, remove the binary, all data,
	@# logs, and the tunmux group.
	sudo pkill -f '/usr/local/bin/tunmux wgconf' 2>/dev/null || true
	sudo rm -f /usr/local/bin/tunmux
	sudo rm -rf "/Library/Application Support/tunmux"
	sudo rm -rf /var/log/tunmux
	sudo dseditgroup -o delete tunmux 2>/dev/null || true

.PHONY: uninstall
uninstall: uninstall/autostart uninstall/privileged uninstall/dns

.PHONY: purge
purge: uninstall purge/privileged


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
