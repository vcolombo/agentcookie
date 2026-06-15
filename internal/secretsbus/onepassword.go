package secretsbus

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
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
// generate and simulate create-vs-edit without a real binary.
type opRunner func(ctx context.Context, opPath string, args, env []string) (stdout, stderr []byte, err error)

func execOpRunner(ctx context.Context, opPath string, args, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, opPath, args...)
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// PushPayload upserts the source-shipped secrets into the configured
// 1Password vault: one item per CLI (title = the CLI name), one concealed
// field per key (label = the env-var KEY, value = the secret). Re-runs edit
// existing items in place, so a steady sync loop is idempotent.
//
// payload is the map carried in the wire envelope (envelope.Secrets). A nil
// or empty payload is a no-op. Errors are NON-FATAL and returned for the sink
// to log: a failure pushing one CLI does not stop the others, and the caller
// must keep the cookie sync alive regardless.
//
// Consumers (e.g. a Hermes agent via its 1Password skill) read a value back
// with `op read "op://<vault>/<cli>/<KEY>"`.
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

		// Build one concealed-field assignment per valid env-var key. The
		// label part is "<KEY>[password]"; since KEY is a validated env-var
		// name (no '[', ']' or '='), op parses the assignment unambiguously.
		var assignments []string
		for _, k := range sortedStringKeys(kv) {
			if !validKeyName(k) {
				result.SkippedKeys = append(result.SkippedKeys, cli+"/"+k)
				continue
			}
			assignments = append(assignments, k+"[password]="+kv[k])
		}
		if len(assignments) == 0 {
			continue
		}

		// `op item get` exit code decides create vs edit. We only care
		// whether the item exists, not its contents.
		_, _, getErr := run(ctx, opPath, []string{"item", "get", cli, "--vault", cfg.Vault}, env)
		create := getErr != nil

		var args []string
		if create {
			args = append([]string{"item", "create", "--category", "API Credential", "--title", cli, "--vault", cfg.Vault}, assignments...)
		} else {
			args = append([]string{"item", "edit", cli, "--vault", cfg.Vault}, assignments...)
		}

		if _, stderr, err := run(ctx, opPath, args, env); err != nil {
			verb := "edit"
			if create {
				verb = "create"
			}
			errs = append(errs, fmt.Errorf("onepassword: %s item %q: %w: %s", verb, cli, err, bytes.TrimSpace(stderr)))
			continue
		}

		if create {
			result.ItemsCreated++
		} else {
			result.ItemsUpdated++
		}
		result.KeysWritten += len(assignments)
	}

	return result, errs
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
