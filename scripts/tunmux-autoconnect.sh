#!/bin/bash
set -euo pipefail

# Both are parameterized so the LaunchAgent works across machines/users; the
# install step injects TUNMUX_PROFILE into the plist's EnvironmentVariables.
BIN="${TUNMUX_BIN:-/usr/local/bin/tunmux}"
PROFILE="${TUNMUX_PROFILE:?TUNMUX_PROFILE is not set (path to the WireGuard .conf)}"

# Already up? nothing to do. (status always exits 0, so match on output.)
if "$BIN" wgconf status 2>/dev/null | grep -q '^Connected:'; then
    exit 0
fi

exec "$BIN" --debug wgconf connect --file "$PROFILE"
