#!/usr/bin/env bash
# Run as the logged-in user, with the tunnel connected. Does not reboot.
set -uo pipefail
umask 077

if [[ $# -gt 1 || $EUID -eq 0 ]]; then
    echo "Usage (without sudo): bash scripts/shutdown-before.sh [output-directory]" >&2
    exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 1
output_dir="${1:-$script_dir/../target/shutdown-checks}"
mkdir -p -- "$output_dir" || exit 1
output_dir="$(cd -- "$output_dir" && pwd)" || exit 1
report="$(mktemp "$output_dir/before-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")" || exit 1

run_check() {
    printf '\n==>'
    printf ' %q' "$@"
    printf '\n'
    if "$@"; then
        return 0
    else
        local status=$?
        failures=$((failures + 1))
        printf '\n[check failed: exit %s; continuing]\n' "$status"
    fi
}

capture() {
    local failures=0
    printf 'Shutdown verification: BEFORE reboot\n'
    printf 'Raw output; review endpoints, IP addresses and names before sharing.\n'
    run_check date -u
    run_check wgd --version
    run_check /usr/local/bin/wgd --version
    # Observe launchd before a status request can socket-activate the daemon.
    run_check wgd launchd status
    run_check /usr/sbin/networksetup -getdnsservers Wi-Fi
    run_check /usr/sbin/networksetup -getsearchdomains Wi-Fi
    run_check wgd status --dns
    printf '\nFailed checks: %s\n' "$failures"
    printf 'No reboot or disconnect performed. Verify the tunnel and DNS state before rebooting.\n'
    [[ $failures -eq 0 ]]
}

capture 2>&1 | tee "$report"
status=$?
printf '\nReport path: %s\n' "$report"
exit "$status"
