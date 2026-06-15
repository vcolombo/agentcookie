# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

agentcookie does one-way, continuous, unattended replication of a "source" Mac's
session state (Chrome cookies + per-CLI secrets) to a "sink" Mac where AI agents
act on the user's behalf. The sink wakes up authenticated on the web and in the
terminal with zero per-site auth ceremony. Transport is AES-256-GCM over the
Tailscale tailnet; keys are pairing-derived per peer.

**macOS-only on both ends.** The code relies on Chrome's macOS Keychain Safe
Storage decrypt path, macOS LaunchAgents, and `security`/`codesign`. Do not
assume changes can be tested or run on Linux.

## Build / test / lint

```bash
make build        # go build -> bin/agentcookie (no Apple cert needed)
make test         # go test -race ./...   (this is what CI runs)
make vet          # go vet ./...
make install      # go install + sign in place (needs Developer ID cert)

go test ./internal/sinkpush/...                    # one package
go test -run TestAdapterInstacart ./internal/sinkpush/   # one test
golangci-lint run                                  # lint (config: .golangci.yml, v2)
```

- **CGO is required for the SQLite-backed Chrome cookie path** (`github.com/mattn/go-sqlite3`). Release builds set `CGO_ENABLED=1` (see `.goreleaser.yaml`). `make test`/`go test` work because CGO defaults on for native builds.
- CI (`.github/workflows/ci.yml`) runs `go vet`, `go test -race`, `go build` on `macos-latest`. Lint runs golangci-lint v2 separately. PR titles are checked (conventional-commit style — see recent git log).
- The lint config enables `modernize`; prefer `any` over `interface{}`, `slices.Contains`, `min`/`max` builtins, etc.

### Signing (release path)

`make sign` / `make notarize` / `make release` need an Apple Developer ID. Reading Chrome Safe Storage is granted **per signed binary** — running an unsigned/`go run` build prompts the Keychain on every invocation. The installed signed binary gets a one-time grant. Override identity via `AGENTCOOKIE_SIGN_IDENTITY`. See `docs/runbook-v0.12-codesign.md`.

## Web app

`web/` is a separate Next.js 15 / React 19 / Tailwind v4 marketing site using **pnpm** (not the Go module). It deploys to agentcookie.dev via Vercel. `cd web && pnpm test` (vitest), `pnpm build`, `pnpm typecheck`. Unrelated to the Go CLI build.

## Architecture

Single cobra binary (`cmd/agentcookie` → `internal/cli`) that is both the source and sink depending on subcommand. Config lives under `~/.config/agentcookie/` (`source.yaml`, `sink.yaml`, `blocklist.yaml`); runtime state and synced secrets under `~/.agentcookie/`.

**One sync, end to end:** source reads Chrome's Cookies SQLite read-only → decrypts each value with the local Keychain Safe Storage key → drops blocklisted hosts → folds in the secrets-bus payload → wraps in a versioned `SyncEnvelope` with a monotonic sequence → AES-GCM-seals with the paired key → POSTs to the sink. The sink opens the seal, checks protocol version + sequence (replay defense), re-filters against its own blocklist, then fans the result out across **delivery surfaces** (below). `internal/watcher` drives the source side continuously via fsnotify on the Cookies file, debounced.

### Cookie delivery surfaces (the sink fan-out)

Different agents read cookies differently, so the sink writes several surfaces after every sync (`internal/sinkpush`):

1. **Universal** — the real Default Chrome profile, re-encrypted for the sink's Keychain; one login-password Safe Storage open at install makes any unmodified cookie tool (yt-dlp, gallery-dl, browser agents) work. Degrades gracefully when no password is available.
2. **Plaintext sidecar** — `~/.agentcookie/cookies-plain.db` (`pkg/sidecar` reader, env `AGENTCOOKIE_PLAIN_COOKIES`).
3. **Per-CLI adapters** — `internal/sinkpush/adapter_*.go`, registered via `Register()` in a `registry`. Each maps cookies into a specific CLI's session file (instacart, airbnb, ebay, pagliacci, table-reservation-goat). A new adapter is ~50 lines + a `Register()` call.
4. **cmux** (opt-in) and **agent-sync** — live CDP injection into running browsers (see below).

### Live CDP injection (not on-disk copying)

`internal/livecdp` + `internal/cdp` inject **plaintext cookies into a running browser over the DevTools Protocol** (`Storage.setCookies`), bypassing Chrome 127+ App-Bound Encryption that makes cold-profile cookies undecryptable. This powers `agentcookie agent-sync` (owns a Chrome on a loopback debug port for browser-use / vercel agent-browser) and the cmux surface. Device-bound (DBSC) cookies cannot transfer across machines and are flagged, not faked.

### Secrets bus (non-cookie auth)

Bearer tokens / API keys / `KEY=VALUE` blobs ride the same encrypted push to `~/.agentcookie/secrets/<cli>/secrets.env` (mode 0600). `internal/secretsbus` is the engine; `agentcookie secret …` manages it; consumers read via env vars, the in-process `pkg/agentcookiesecret` Go library, or a v2 `agentcookie.toml` manifest auto-detected by `agentcookie discover` (`pkg/agentcookieadoption` is the author-side helper).

### Package map (internal/)

| Package | Role |
|---|---|
| `cli` | All cobra subcommands. New commands wire into `root.go`'s `AddCommand`. |
| `chrome`, `chromepaths`, `chromectl`, `chromedirsync` | Read/write/decrypt Chrome cookies on macOS; Chrome lifecycle; profile dir packing. |
| `sinkpush` | Sink-side delivery surfaces + adapter registry. |
| `livecdp`, `cdp` | Live cookie injection over CDP. |
| `secretsbus` | Per-CLI secrets engine (+ v2 manifest discovery). |
| `pairing`, `keystore` | X25519+HKDF handshake; per-peer key files (`~/.config/agentcookie/keys/<peer>.json`, 0600). |
| `transport`, `protocol` | AES-GCM seal/open; `SyncEnvelope`, sequence/replay defense, blocklist matcher. |
| `config` | YAML loaders + allowlist/blocklist. |
| `watcher`, `state` | Source fsnotify loop; shared state-file format. |
| `tsclient`, `launchd`, `cmuxconfig` | Tailscale probing; LaunchAgent plist gen; comment-preserving cmux config edits. |

`cookiesource/` (repo root) and `pkg/` (`agentcookiesecret`, `agentcookieadoption`, `sidecar`) are the **public, importable** integration points for third-party CLIs — keep their APIs stable. `cmd/spike-source` and `cmd/spike-sink` are experimental spikes, not the shipping binary.

## Conventions

- **Adding a CLI subcommand:** create `internal/cli/<name>.go` with a `cobra.Command`, add it to the `AddCommand(...)` call in `root.go`. Persistent flags `--config-dir` and `--json` are already wired.
- **Adding a cookie adapter:** new `internal/sinkpush/adapter_<cli>.go`, implement the adapter interface, call `Register()`. There are consistency/registry tests that enumerate adapters — keep them green.
- Tests live next to code (`*_test.go`); 520+ unit tests across 26 packages. Adapters and the keychain/converge paths have dedicated tests — run the package's tests after touching them.
- The architecture doc (`docs/architecture.md`) describes the original v1 spike and is partially dated (protocol/surface details have grown); trust the code and `README.md` over it. Long-form runbooks for each subsystem live in `docs/runbook-*.md`.
