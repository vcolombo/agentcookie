package secretsbus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// OnePasswordConfig is the minimal 1Password push configuration the sink
// passes in. Kept independent of internal/config so secretsbus carries no
// dependency on the config package.
type OnePasswordConfig struct {
	// Vault is the target 1Password vault name or ID. Required.
	Vault string
	// ServiceAccountToken is a write-scoped 1Password service-account token.
	// Optional: when empty the pusher relies on OP_SERVICE_ACCOUNT_TOKEN
	// already present in the process environment (which `op` reads natively).
	ServiceAccountToken string
	// OpPath overrides the `op` binary location. Empty resolves "op" on PATH.
	OpPath string
}

// OnePasswordResult is the per-push outcome the sink uses for logging and
// sink-state reporting.
type OnePasswordResult struct {
	// ItemsCreated is the number of vault items created (one per CLI that
	// had no existing item).
	ItemsCreated int
	// ItemsUpdated is the number of existing vault items edited in place.
	ItemsUpdated int
	// KeysWritten is the total count of secret fields set across all items.
	KeysWritten int
	// SkippedKeys lists "<cli>/<key>" entries dropped before reaching `op`
	// because the CLI or key name was not a safe 1Password field label /
	// env-var name. A whole CLI dropped for an invalid name appears as
	// "<cli>/*".
	SkippedKeys []string
}

// opRunner runs the `op` CLI. Injected so tests can assert the exact argv we
// generate, capture stdin, and simulate create/edit/not-found without a real
// binary. stdin is nil for commands that take no piped input.
type opRunner func(ctx context.Context, opPath string, args []string, stdin []byte, env []string) (stdout, stderr []byte, err error)

func execOpRunner(ctx context.Context, opPath string, args []string, stdin []byte, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, opPath, args...)
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// opField / opTemplate model the JSON item template `op` reads on stdin. Using
// a piped template (rather than `KEY[password]=VALUE` argv assignments) keeps
// secret VALUES out of /proc/<pid>/cmdline — the approach 1Password documents
// for sensitive values.
type opField struct {
	Label string `json:"label"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type opTemplate struct {
	Fields []opField `json:"fields"`
}

// PushPayload upserts the source-shipped secrets into the configured
// 1Password vault: one item per CLI (title = the CLI name), one concealed
// field per key (label = the env-var KEY, value = the secret). Field values
// travel on the `op` process's STDIN as a JSON template, never on argv.
// Re-runs edit existing items in place, so a steady sync loop is idempotent.
//
// payload is the map carried in the wire envelope (envelope.Secrets). A nil
// or empty payload is a no-op. Errors are NON-FATAL and returned for the sink
// to log: a failure pushing one CLI does not stop the others, and the caller
// must keep the cookie sync alive regardless.
//
// Consumers (e.g. a Hermes agent via its 1Password skill) read a value back
// with `op read "op://<vault>/<cli>/<KEY>"`.
//
// Rotation contract / known limitation: PushPayload UPSERTS — it adds and
// overwrites fields/items, but does NOT delete fields for keys that have
// disappeared from the bus, nor items for CLIs that are gone. A secret removed
// on the source therefore lingers in the vault until removed there (manually
// or by a future reconciliation pass). Reliable orphan deletion needs `op`'s
// field-delete syntax plus tracking which fields are agentcookie-owned vs
// 1Password built-ins; that is deliberately deferred rather than risk mangling
// hand-edited items. Treat the vault as add/update-only for now.
func PushPayload(ctx context.Context, cfg OnePasswordConfig, payload map[string]map[string]string) (OnePasswordResult, []error) {
	return pushPayload(ctx, cfg, payload, execOpRunner)
}

func pushPayload(ctx context.Context, cfg OnePasswordConfig, payload map[string]map[string]string, run opRunner) (OnePasswordResult, []error) {
	var result OnePasswordResult
	var errs []error
	if len(payload) == 0 {
		return result, nil
	}

	opPath := cfg.OpPath
	if opPath == "" {
		opPath = "op"
	}
	env := os.Environ()
	if cfg.ServiceAccountToken != "" {
		env = append(env, "OP_SERVICE_ACCOUNT_TOKEN="+cfg.ServiceAccountToken)
	}

	for _, cli := range sortedMapKeys(payload) {
		kv := payload[cli]
		if !validCLIName(cli) {
			result.SkippedKeys = append(result.SkippedKeys, cli+"/*")
			errs = append(errs, fmt.Errorf("onepassword: skipping CLI %q: invalid name (1Password item title)", cli))
			continue
		}

		// One concealed field per valid env-var key. Values go on stdin, never
		// argv, so the field label is the only key-derived data on the command
		// line (and labels are validated env-var names).
		var fields []opField
		for _, k := range sortedStringKeys(kv) {
			if !validKeyName(k) {
				result.SkippedKeys = append(result.SkippedKeys, cli+"/"+k)
				continue
			}
			fields = append(fields, opField{Label: k, Type: "CONCEALED", Value: kv[k]})
		}
		if len(fields) == 0 {
			continue
		}

		// Decide create vs edit by probing the item. CRITICAL: only treat a
		// genuine "not found" as "create". Any other failure (auth, network,
		// rate-limit) is ambiguous — creating then would risk a duplicate item
		// and would silently mask the real error — so skip this CLI instead.
		_, getStderr, getErr := run(ctx, opPath, []string{"item", "get", cli, "--vault", cfg.Vault, "--format", "json"}, nil, env)
		var create bool
		switch {
		case getErr == nil:
			create = false
		case isOpNotFound(getStderr):
			create = true
		default:
			errs = append(errs, fmt.Errorf("onepassword: probing item %q failed; skipping (not creating, to avoid a duplicate / mask the error): %w", cli, getErr))
			continue
		}

		tmpl, err := json.Marshal(opTemplate{Fields: fields})
		if err != nil { // unreachable for string maps, but be explicit
			errs = append(errs, fmt.Errorf("onepassword: marshal template for %q: %w", cli, err))
			continue
		}

		var args []string
		if create {
			args = []string{"item", "create", "--category", "API Credential", "--title", cli, "--vault", cfg.Vault, "-"}
		} else {
			args = []string{"item", "edit", cli, "--vault", cfg.Vault, "-"}
		}

		// NOTE: deliberately do NOT interpolate op's stderr into the error —
		// it can echo back field labels/values. The exit error is enough to
		// signal failure; reproduce with `op` manually for diagnosis.
		if _, _, err := run(ctx, opPath, args, tmpl, env); err != nil {
			verb := "edit"
			if create {
				verb = "create"
			}
			errs = append(errs, fmt.Errorf("onepassword: %s item %q failed: %w", verb, cli, err))
			continue
		}

		if create {
			result.ItemsCreated++
		} else {
			result.ItemsUpdated++
		}
		result.KeysWritten += len(fields)
	}

	return result, errs
}

// isOpNotFound reports whether op's stderr indicates the probed item simply
// doesn't exist (vs an auth/network/other failure). op does not expose a
// granular exit code for this, so we match its stable human-readable markers.
func isOpNotFound(stderr []byte) bool {
	s := strings.ToLower(string(stderr))
	for _, marker := range []string{"isn't an item", "not found", "no item", "doesn't exist", "could not find"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func sortedMapKeys(m map[string]map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
