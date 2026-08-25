#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install_root=${FLUXGATE_INSTALL_ROOT:-/opt/fluxgate}
bin_path=${FLUXGATE_BIN_PATH:-/usr/local/bin/fluxgate}
python_bin=${FLUXGATE_PYTHON:-python3}

fail() {
    printf 'FluxGate install error: %s\n' "$1" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run this installer as root"
[ -f "$project_root/pyproject.toml" ] || fail "run the installer from a FluxGate source tree"

case "$install_root" in
    /*) ;;
    *) fail "FLUXGATE_INSTALL_ROOT must be absolute" ;;
esac
case "$bin_path" in
    /*) ;;
    *) fail "FLUXGATE_BIN_PATH must be absolute" ;;
esac
[ "$install_root" != / ] || fail "refusing to use / as the install root"

[ -r /etc/os-release ] || fail "cannot identify the operating system"
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|debian:12) ;;
    *) fail "supported systems are Ubuntu 22.04/24.04 and Debian 12" ;;
esac

command -v "$python_bin" >/dev/null 2>&1 || fail "$python_bin is not installed"
"$python_bin" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' || \
    fail "Python 3.10 or newer is required"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3-venv

mkdir -p "$install_root/releases"
release="$install_root/releases/$(date -u +%Y%m%d%H%M%S)-$$"
mkdir "$release"
complete=false
created_bin=false
next_link="$install_root/current.new.$$"
cleanup() {
    if [ "$complete" != true ]; then
        if [ -L "$install_root/current" ] && \
            [ "$(readlink "$install_root/current")" = "$release" ]; then
            complete=true
            return
        fi
        rm -rf "$release"
        rm -f "$next_link"
        if [ "$created_bin" = true ]; then
            rm -f "$bin_path"
        fi
    fi
}
trap cleanup EXIT HUP INT TERM

"$python_bin" -m venv "$release"
"$release/bin/python" -m pip install --disable-pip-version-check --no-cache-dir "$project_root"
"$release/bin/fluxgate" version >/dev/null

expected_link="$install_root/current/bin/fluxgate"
if [ -e "$bin_path" ] || [ -L "$bin_path" ]; then
    [ -L "$bin_path" ] || fail "refusing to replace non-symlink command at $bin_path"
    [ "$(readlink "$bin_path")" = "$expected_link" ] || \
        fail "refusing to replace command not owned by FluxGate: $bin_path"
else
    mkdir -p "$(dirname "$bin_path")"
    ln -s "$expected_link" "$bin_path"
    created_bin=true
fi

ln -s "$release" "$next_link"
mv -Tf "$next_link" "$install_root/current"
complete=true
trap - EXIT HUP INT TERM

printf 'FluxGate installed: %s\n' "$("$bin_path" version)"
printf 'Command: %s\n' "$bin_path"
