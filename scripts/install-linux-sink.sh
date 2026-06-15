#!/usr/bin/env bash
#
# install-linux-sink.sh — install the agentcookie sink as a systemd service on
# a Linux VPS, with ~/.agentcookie mounted on tmpfs so the plaintext cookie
# sidecar lives only in RAM. Run on the VPS, as root (sudo).
#
# Prereqs (this script checks, does not install them):
#   - the Linux agentcookie binary (build with `make build-linux`, scp it over)
#   - Tailscale up on the host (`tailscale ip -4` returns a 100.x address)
#   - a ~/.config/agentcookie/sink.yaml (start from examples/sink-linux.yaml)
#   - pairing done: `agentcookie pair --as sink ...` (writes the peer key)
#
# It does NOT create 1Password service accounts or the vault — see
# docs/runbook-linux-vps-sink.md for that. Idempotent: safe to re-run.
#
# Usage:
#   sudo AGENTCOOKIE_USER=brien BINARY=./agentcookie-linux-amd64 \
#     scripts/install-linux-sink.sh
#
set -euo pipefail

USER_NAME="${AGENTCOOKIE_USER:?set AGENTCOOKIE_USER to the account that runs the sink}"
BINARY="${BINARY:-./agentcookie-linux-amd64}"
TMPFS_SIZE="${TMPFS_SIZE:-64m}"

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (sudo)" >&2
  exit 1
fi
if ! id "$USER_NAME" >/dev/null 2>&1; then
  echo "user '$USER_NAME' does not exist" >&2
  exit 1
fi
if [[ ! -f "$BINARY" ]]; then
  echo "binary '$BINARY' not found (build with 'make build-linux' and copy it here)" >&2
  exit 1
fi

home="$(getent passwd "$USER_NAME" | cut -d: -f6)"
uid="$(id -u "$USER_NAME")"
gid="$(id -g "$USER_NAME")"
ac_dir="$home/.agentcookie"

echo "==> Installing binary to /usr/local/bin/agentcookie"
install -m755 "$BINARY" /usr/local/bin/agentcookie

echo "==> Ensuring $ac_dir exists and is owned by $USER_NAME"
install -d -o "$USER_NAME" -g "$gid" -m700 "$ac_dir"

echo "==> Mounting $ac_dir on tmpfs (RAM-only cookie sidecar)"
fstab_line="tmpfs $ac_dir tmpfs rw,nosuid,nodev,uid=$uid,gid=$gid,mode=0700,size=$TMPFS_SIZE 0 0"
if ! grep -qF " $ac_dir tmpfs " /etc/fstab; then
  echo "$fstab_line" >> /etc/fstab
  echo "    added to /etc/fstab"
fi
# (Re)mount now. mountpoint check keeps this idempotent.
if ! mountpoint -q "$ac_dir"; then
  mount "$ac_dir"
  echo "    mounted"
else
  echo "    already a tmpfs mount"
fi

echo "==> Installing systemd unit"
unit_src="$(dirname "$0")/../examples/agentcookie-sink.service"
sed "s|AGENTCOOKIE_USER|$USER_NAME|g" "$unit_src" > /etc/systemd/system/agentcookie-sink.service

echo "==> Preparing /etc/agentcookie/sink.env (0600) for OP_SERVICE_ACCOUNT_TOKEN"
install -d -m700 /etc/agentcookie
if [[ ! -f /etc/agentcookie/sink.env ]]; then
  install -m600 /dev/null /etc/agentcookie/sink.env
  echo "# OP_SERVICE_ACCOUNT_TOKEN=ops_...   # write-scoped 1Password token" > /etc/agentcookie/sink.env
  echo "    created (add your write-scoped OP_SERVICE_ACCOUNT_TOKEN here)"
fi

echo "==> Enabling + starting the service"
systemctl daemon-reload
systemctl enable --now agentcookie-sink.service

echo
echo "Done. Check status with:  systemctl status agentcookie-sink.service"
echo "Tail logs with:           journalctl -u agentcookie-sink.service -f"
