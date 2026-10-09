#!/bin/sh
# ts-sshd.sh - a real login shell on a sealed host, over the tailnet.
#
# Tailscale's own SSH server cannot do this here. The daemon is static Go, so
# its pty.Open() cannot be interposed, /dev/ptmx does not exist and /dev is not
# writable; it *errors* on a pty request instead of degrading. A dynamic sshd
# can be interposed, refuses the kernel pty and carries on over pipes, and the
# login shell then runs under sandhome's userspace pty (fakepty) and its line
# discipline (errandsh).
#
# OpenSSH will not listen on a unix socket, so shim/unixsockd.c is the missing
# listener: it accepts on a unix socket and hands each connection to `sshd -i`.
# `tailscale serve --tcp` then exposes that socket on the tailnet, which is
# stock Tailscale.
#
# Requires a shims directory from `cfrs net ts-shims` (passwd/group/getent/id/
# fakepwd), a running tailscaled, and sandhome's shell files (fetched pinned
# below unless --sandhome names a checkout).
#
# Usage:
#   tools/ts-sshd.sh --shims DIR [--dir DIR] [--port N]
#                    [--sandhome DIR] [--tailscale BIN] [--socket SOCK] [--serve]
set -eu

SANDHOME_COMMIT=5792a3e731573662492d22cd23a6ca7dcd7bc536
ERRANDSH_SHA=5f34a881cbc26eb5d68ec7adbc271627bdf0d4908c8d86858f05dc29fcf4a3ba
FAKETTY_SHA=09f20fbd0f218da8ae792877aab18b49c5b360b4484706014ba45f30ce67ce1d
FAKEPTY_SHA=c6450a66dad007944b0d7cb5439e83fe9a1164631a969d3f8486c360a3e00d34

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

shims=
dir=
port=2222
sandhome=
tsbin=
socket=
serve=0

while [ $# -gt 0 ]; do
    case "$1" in
        --shims) shims=${2:-}; shift 2 ;;
        --dir) dir=${2:-}; shift 2 ;;
        --port) port=${2:-}; shift 2 ;;
        --sandhome) sandhome=${2:-}; shift 2 ;;
        --tailscale) tsbin=${2:-}; shift 2 ;;
        --socket) socket=${2:-}; shift 2 ;;
        --serve) serve=1; shift ;;
        -h|--help) usage ;;
        *) echo "ts-sshd: unknown option $1" >&2; usage ;;
    esac
done

[ -n "$shims" ] || usage
[ -n "$dir" ] || dir="$shims/sshd"
[ -f "$shims/fakepwd.so" ] || { echo "ts-sshd: $shims/fakepwd.so missing; run 'cfrs net ts-shims --out $shims'" >&2; exit 1; }
mkdir -p "$dir"

verify() {
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] || { echo "ts-sshd: sha256 of $1 is $got, expected $2" >&2; exit 1; }
}

take() {
    # take NAME SHA
    if [ -n "$sandhome" ]; then
        cp "$sandhome/shell/$1" "$dir/$1" 2>/dev/null || cp "$sandhome/shims/$1" "$dir/$1"
    else
        case "$1" in
            errandsh) fetch_url="https://raw.githubusercontent.com/talaria0101/sandhome/$SANDHOME_COMMIT/shell/errandsh" ;;
            faketty)  fetch_url="https://raw.githubusercontent.com/talaria0101/sandhome/$SANDHOME_COMMIT/shell/faketty" ;;
            fakepty.c) fetch_url="https://raw.githubusercontent.com/talaria0101/sandhome/$SANDHOME_COMMIT/shims/fakepty.c" ;;
        esac
        curl -fsSL --max-time 60 "$fetch_url" -o "$dir/$1"
    fi
    verify "$dir/$1" "$2"
}

take errandsh "$ERRANDSH_SHA"
take faketty "$FAKETTY_SHA"
take fakepty.c "$FAKEPTY_SHA"
chmod 755 "$dir/errandsh" "$dir/faketty"

cc -O2 -shared -fPIC -o "$dir/fakepty.so" "$dir/fakepty.c" -ldl
cc -O2 -o "$dir/unixsockd" "$here/../shim/unixsockd.c"

sed -e "s|@DIR@|$dir|g" \
    -e "s|@FAKEPWD@|$shims/fakepwd.so|g" \
    -e "s|@PASSWD@|$shims/passwd|g" \
    "$here/../shim/loginshell" > "$dir/loginshell"
chmod 755 "$dir/loginshell"

# Point the synthetic users at that login shell.
awk -F: -v OFS=: -v s="$dir/loginshell" '{ $7 = s; print }' "$shims/passwd" > "$shims/passwd.tmp"
mv "$shims/passwd.tmp" "$shims/passwd"

cat > "$dir/sshd_config" <<EOF
HostKey $dir/ssh_host_ed25519_key
PidFile none
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $dir/authorized_keys
PermitRootLogin yes
PrintMotd no
UseDNS no
AcceptEnv TERM LANG LC_*
StrictModes no
Subsystem sftp internal-sftp
EOF

# ssh-keygen calls getpwuid; the shim answers it.
if [ ! -f "$dir/ssh_host_ed25519_key" ]; then
    SANDHOME_PASSWD="$shims/passwd" LD_PRELOAD="$shims/fakepwd.so" \
        ssh-keygen -q -t ed25519 -f "$dir/ssh_host_ed25519_key" -N ''
fi
if [ ! -f "$dir/id_ed25519" ]; then
    SANDHOME_PASSWD="$shims/passwd" LD_PRELOAD="$shims/fakepwd.so" \
        ssh-keygen -q -t ed25519 -f "$dir/id_ed25519" -N ''
    cp "$dir/id_ed25519.pub" "$dir/authorized_keys"
    chmod 600 "$dir/authorized_keys"
fi

PATH="$shims:/usr/local/bin:/usr/bin:/bin" \
SANDHOME_PASSWD="$shims/passwd" \
LD_PRELOAD="$shims/fakepwd.so" \
UNIXSOCKD_LOG="$dir/sshd.log" \
nohup "$dir/unixsockd" "$dir/sshd.sock" /usr/sbin/sshd -i -e -f "$dir/sshd_config" \
    >"$dir/bridge.log" 2>&1 &
sleep 1

echo "ts-sshd: socket  $dir/sshd.sock"
echo "ts-sshd: log     $dir/sshd.log"
echo "ts-sshd: shell   $dir/loginshell (faketty + errandsh)"
echo "ts-sshd: key     $dir/id_ed25519"
echo "ts-sshd: put your own public key in $dir/authorized_keys, then:"
if [ "$serve" = 1 ] && [ -n "$tsbin" ] && [ -n "$socket" ]; then
    "$tsbin" --socket="$socket" serve --bg --tcp "$port" "unix:$dir/sshd.sock"
fi
echo "  tailscale serve --bg --tcp $port unix:$dir/sshd.sock"
echo "  ssh -p $port root@<this-node>"
