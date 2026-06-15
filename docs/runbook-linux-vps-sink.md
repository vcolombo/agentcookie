# Runbook: Linux VPS sink → Hermes Docker container

Run the agentcookie **sink** on a Linux VPS (e.g. Hostinger) instead of a second
Mac, and feed a **Hermes** agent running in Docker on that box. The **source
stays your Mac**. Cookies arrive as a RAM-only plaintext sidecar the Hermes
container reads; secrets are pushed into 1Password and read back by Hermes's
1Password skill, so secret values never touch the VPS disk.

This is the headless "degraded mode" (`skip_chrome_sqlite`) — no macOS Keychain,
no Chrome on the sink. See [architecture.md](architecture.md) for the base model
and [threat-model.md](threat-model.md) for the security posture (read the
"Linux VPS sink + 1Password" section — the trust model differs from the all-Mac
default).

## What does and doesn't transfer

- **Cookies** for non-device-bound sites: yes, as `~/.agentcookie/cookies-plain.db`.
- **Secrets** (bearer tokens, API keys): yes, into a 1Password vault.
- **DBSC / device-bound cookies** (mainly Google/Workspace): no — same limit as the Mac sink. Sign Hermes's browser into those accounts once, locally.

## 1. Build the Linux binary

The cookie sidecar uses a CGO sqlite driver, so the binary must be built **on
Linux with CGO**, not cross-compiled from your Mac. From the repo on your Mac:

```bash
make build-linux                 # linux/amd64 → bin/agentcookie-linux-amd64
make build-linux ARCH=arm64      # for an ARM VPS
```

(Or, on the VPS itself, which has Go + gcc: `CGO_ENABLED=1 go build -o agentcookie ./cmd/agentcookie`.)

Copy it to the VPS:

```bash
scp bin/agentcookie-linux-amd64 vps:/tmp/agentcookie
```

## 2. Tailscale on the VPS

Install Tailscale and join the same tailnet as your Mac. The sink binds the
host's tailnet IP (the binding policy rejects public/0.0.0.0 addresses), and the
WireGuard channel is the transport encryption — no public port, no TLS to manage.

```bash
tailscale up
tailscale ip -4        # note the 100.x.y.z address for sink.yaml
```

Lock it down with a tailnet ACL so only your Mac can reach the sink's `:9999`.

## 3. Config + pairing

```bash
ssh vps
mkdir -p ~/.config/agentcookie
# Start from the example; set listen.addr to the 100.x from step 2, peer.hostname
# to your Mac, and the onepassword block (vault name).
curl -o ~/.config/agentcookie/sink.yaml \
  https://raw.githubusercontent.com/mvanhorn/agentcookie/main/examples/sink-linux.yaml
$EDITOR ~/.config/agentcookie/sink.yaml
```

Pair the two machines (does not need the macOS wizard — pairing is plain HTTP +
X25519 and works on Linux):

```bash
# On the Mac (source):
agentcookie pair --as source            # prints a code + the sink command

# On the VPS (sink):
/tmp/agentcookie pair --as sink --peer <mac-host> \
  --pair-url http://<mac-host>:9998/pair --code <CODE>
```

Point the Mac's `source.yaml` at the VPS: `sink.url: http://<vps-tailnet-host>:9999/sync`.

## 4. 1Password: two service accounts + a vault

The 1Password skill is **read-only** and **agent-runtime** (the Hermes agent
calls `op read`/`op run` on demand; nothing is cached to disk). agentcookie is
the **writer**. Set up least privilege:

1. Create a vault, e.g. `AgentCookie`.
2. Create **two** service accounts (1Password → Settings → Service Accounts):
   - **sink** — *write* access to `AgentCookie`. Its token goes on the VPS sink.
   - **hermes** — *read* access to `AgentCookie`. Its token goes to Hermes.
   Each token starts with `ops_` and is shown once — copy it.

The sink upserts **one item per CLI** (item title = the CLI name) with **one
concealed field per key** (label = the env-var key). A Hermes agent reads a
value back with `op read "op://AgentCookie/<cli>/<KEY>"`.

> The exact `op item create/edit` invocation the sink uses targets `op` v2
> (category "API Credential"). If your `op` version rejects it, the sink logs a
> non-fatal error (the cookie sync still succeeds) — adjust and re-sync. Verify
> with step 6.

## 5. Install the sink as a systemd service (tmpfs-backed)

```bash
# As root on the VPS, with the binary present:
sudo AGENTCOOKIE_USER=<user> BINARY=/tmp/agentcookie \
  bash install-linux-sink.sh        # from scripts/ in this repo
# Then add the write-scoped token the sink uses:
sudo sh -c 'echo "OP_SERVICE_ACCOUNT_TOKEN=ops_<sink-write-token>" >> /etc/agentcookie/sink.env'
sudo systemctl restart agentcookie-sink.service
```

The installer mounts `~/.agentcookie/` on **tmpfs** (RAM-only), installs the
systemd unit (`examples/agentcookie-sink.service`), and enables it. Check it:

```bash
systemctl status agentcookie-sink.service
journalctl -u agentcookie-sink.service -f
findmnt ~/.agentcookie            # confirm it's tmpfs
```

## 6. Verify the sync

```bash
# On the Mac:
agentcookie source --once

# On the VPS:
sqlite3 ~/.agentcookie/cookies-plain.db 'select count(*) from cookies;'   # > 0
ls ~/.agentcookie/secrets 2>/dev/null && echo "UNEXPECTED: secrets on disk" || echo "good: no plaintext secrets on disk"
# With the read-scoped hermes token exported:
OP_SERVICE_ACCOUNT_TOKEN=ops_<hermes-read-token> op item list --vault AgentCookie
OP_SERVICE_ACCOUNT_TOKEN=ops_<hermes-read-token> op read "op://AgentCookie/<cli>/<KEY>"
```

## 7. Wire up Hermes (Docker)

**Cookies** — bind-mount the RAM-only sidecar read-only and point Hermes at it:

```bash
docker run \
  -v /home/<user>/.agentcookie/cookies-plain.db:/data/cookies-plain.db:ro \
  -e AGENTCOOKIE_PLAIN_COOKIES=/data/cookies-plain.db \
  ... hermes-image
```

Inside Hermes, load them into the browser context at session start — Go consumers
use `pkg/sidecar.ReadSidecar`; others read the SQLite directly:
`SELECT host_key,name,value,path,is_secure,is_httponly FROM cookies`.

**Secrets** — enable Hermes's optional 1Password skill and give it the
**read-scoped** token:

```bash
# In the Hermes container's ~/.hermes/.env:
OP_SERVICE_ACCOUNT_TOKEN=ops_<hermes-read-token>
```

The agent now fetches credentials on demand (`op read`/`op run`), in memory.

## Keeping it in sync

The source watches Chrome via fsnotify and pushes on change, so a new login on
your Mac lands on the VPS within seconds; rotating a token on the Mac updates the
1Password item on the next sync. On VPS reboot the tmpfs cookie DB is empty until
the next push (re-run `agentcookie source --once` or just log in once); secrets
remain in 1Password (the vault is the source of truth).
