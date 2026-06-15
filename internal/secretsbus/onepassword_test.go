package secretsbus

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// opCall records one invocation of the fake op runner.
type opCall struct {
	args  []string
	stdin []byte
	env   []string
}

// fakeOp is a programmable op runner.
//   - notFound titles make `op item get` report a genuine "not found" (→ create).
//   - otherErr titles make `op item get` fail with an ambiguous error (→ skip).
//   - everything else: `op item get` succeeds (→ edit).
//   - failWrite titles make the create/edit call fail.
type fakeOp struct {
	calls     []opCall
	notFound  map[string]bool
	otherErr  map[string]bool
	failWrite map[string]bool
}

func (f *fakeOp) run(_ context.Context, _ string, args []string, stdin []byte, env []string) ([]byte, []byte, error) {
	f.calls = append(f.calls, opCall{args: slices.Clone(args), stdin: slices.Clone(stdin), env: env})

	// `op item get <title> ...`
	if len(args) >= 3 && args[0] == "item" && args[1] == "get" {
		title := args[2]
		if f.notFound[title] {
			return nil, []byte(`"` + title + `" isn't an item.`), errors.New("exit 1")
		}
		if f.otherErr[title] {
			return nil, []byte("error initializing client: rate limited"), errors.New("exit 1")
		}
		return []byte("{}"), nil, nil
	}
	// `op item create|edit <...>`
	if len(args) >= 2 && args[0] == "item" && (args[1] == "create" || args[1] == "edit") {
		title := args[2] // edit: title is positional
		if args[1] == "create" {
			if i := slices.Index(args, "--title"); i >= 0 && i+1 < len(args) {
				title = args[i+1]
			}
		}
		if f.failWrite[title] {
			return nil, []byte("write failed"), errors.New("exit 1")
		}
	}
	return []byte("{}"), nil, nil
}

func (f *fakeOp) lastWrite() opCall {
	for i := len(f.calls) - 1; i >= 0; i-- {
		if len(f.calls[i].args) >= 2 && f.calls[i].args[0] == "item" &&
			(f.calls[i].args[1] == "create" || f.calls[i].args[1] == "edit") {
			return f.calls[i]
		}
	}
	return opCall{}
}

// assertNoSecretInArgv is the security regression guard for the /proc argv
// leak: no secret VALUE may appear in any op argument, ever.
func assertNoSecretInArgv(t *testing.T, f *fakeOp, secrets ...string) {
	t.Helper()
	for _, c := range f.calls {
		for _, a := range c.args {
			for _, s := range secrets {
				if strings.Contains(a, s) {
					t.Errorf("secret %q leaked into argv %q (call %v)", s, a, c.args)
				}
			}
		}
	}
}

func TestPushPayload_CreatesNewItem(t *testing.T) {
	f := &fakeOp{notFound: map[string]bool{"github-cli": true}}
	cfg := OnePasswordConfig{Vault: "AgentCookie", ServiceAccountToken: "ops_tok"}
	payload := map[string]map[string]string{
		"github-cli": {"GITHUB_TOKEN": "ghp_xyz", "GH_HOST": "github.com"},
	}

	res, errs := pushPayload(context.Background(), cfg, payload, f.run)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if res.ItemsCreated != 1 || res.ItemsUpdated != 0 || res.KeysWritten != 2 {
		t.Errorf("got created=%d updated=%d keys=%d, want 1/0/2", res.ItemsCreated, res.ItemsUpdated, res.KeysWritten)
	}

	w := f.lastWrite()
	want := []string{"item", "create", "--category", "API Credential", "--title", "github-cli", "--vault", "AgentCookie", "-"}
	if !slices.Equal(w.args, want) {
		t.Errorf("create argv = %v, want %v", w.args, want)
	}
	// Values ride stdin as a JSON template, sorted by label.
	var tmpl opTemplate
	if err := json.Unmarshal(w.stdin, &tmpl); err != nil {
		t.Fatalf("stdin is not valid JSON: %v (%s)", err, w.stdin)
	}
	wantFields := []opField{
		{Label: "GH_HOST", Type: "CONCEALED", Value: "github.com"},
		{Label: "GITHUB_TOKEN", Type: "CONCEALED", Value: "ghp_xyz"},
	}
	if !slices.Equal(tmpl.Fields, wantFields) {
		t.Errorf("stdin fields = %v, want %v", tmpl.Fields, wantFields)
	}
	// The security guard: the secret never appears on argv.
	assertNoSecretInArgv(t, f, "ghp_xyz", "github.com")
	if !slices.Contains(w.env, "OP_SERVICE_ACCOUNT_TOKEN=ops_tok") {
		t.Errorf("env missing OP_SERVICE_ACCOUNT_TOKEN")
	}
}

func TestPushPayload_EditsExistingItem(t *testing.T) {
	f := &fakeOp{} // get succeeds → item exists → edit
	cfg := OnePasswordConfig{Vault: "AgentCookie"}
	payload := map[string]map[string]string{"slack-cli": {"SLACK_TOKEN": "xoxb-secret"}}

	res, errs := pushPayload(context.Background(), cfg, payload, f.run)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if res.ItemsUpdated != 1 || res.ItemsCreated != 0 {
		t.Errorf("got created=%d updated=%d, want 0/1", res.ItemsCreated, res.ItemsUpdated)
	}
	w := f.lastWrite()
	want := []string{"item", "edit", "slack-cli", "--vault", "AgentCookie", "-"}
	if !slices.Equal(w.args, want) {
		t.Errorf("edit argv = %v, want %v", w.args, want)
	}
	assertNoSecretInArgv(t, f, "xoxb-secret")
}

func TestPushPayload_SkipsInvalidNames(t *testing.T) {
	f := &fakeOp{notFound: map[string]bool{"good-cli": true}}
	cfg := OnePasswordConfig{Vault: "V"}
	payload := map[string]map[string]string{
		"good-cli":     {"OK_KEY": "v1", "bad key": "v2", "1BAD": "v3"},
		"Bad_CLI_Name": {"WHATEVER": "v"}, // invalid CLI name
	}

	res, errs := pushPayload(context.Background(), cfg, payload, f.run)
	if res.KeysWritten != 1 || res.ItemsCreated != 1 {
		t.Errorf("got keys=%d created=%d, want 1/1", res.KeysWritten, res.ItemsCreated)
	}
	if !slices.Contains(res.SkippedKeys, "Bad_CLI_Name/*") {
		t.Errorf("SkippedKeys missing Bad_CLI_Name/*: %v", res.SkippedKeys)
	}
	if !slices.Contains(res.SkippedKeys, "good-cli/bad key") || !slices.Contains(res.SkippedKeys, "good-cli/1BAD") {
		t.Errorf("SkippedKeys missing invalid keys: %v", res.SkippedKeys)
	}
	if len(errs) != 1 {
		t.Errorf("want 1 non-fatal error (invalid CLI), got %d: %v", len(errs), errs)
	}
	// Only the one valid field is in the create template.
	var tmpl opTemplate
	_ = json.Unmarshal(f.lastWrite().stdin, &tmpl)
	if len(tmpl.Fields) != 1 || tmpl.Fields[0].Label != "OK_KEY" {
		t.Errorf("template fields = %v, want only OK_KEY", tmpl.Fields)
	}
}

// TestPushPayload_FailOpenOnAmbiguousGet covers the security finding: a non-
// "not found" probe error (auth/network/rate-limit) must NOT trigger create
// (which would duplicate the item and mask the real error) — it skips.
func TestPushPayload_FailOpenOnAmbiguousGet(t *testing.T) {
	f := &fakeOp{otherErr: map[string]bool{"flaky-cli": true}}
	cfg := OnePasswordConfig{Vault: "V"}
	payload := map[string]map[string]string{"flaky-cli": {"A_KEY": "1"}}

	res, errs := pushPayload(context.Background(), cfg, payload, f.run)
	if res.ItemsCreated != 0 || res.ItemsUpdated != 0 {
		t.Errorf("ambiguous get must not create/edit; got created=%d updated=%d", res.ItemsCreated, res.ItemsUpdated)
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 error for the ambiguous probe, got %d: %v", len(errs), errs)
	}
	// No create/edit call should have been issued.
	for _, c := range f.calls {
		if len(c.args) >= 2 && (c.args[1] == "create" || c.args[1] == "edit") {
			t.Errorf("unexpected write call after ambiguous get: %v", c.args)
		}
	}
}

func TestPushPayload_WriteFailureIsNonFatalAndContinues(t *testing.T) {
	f := &fakeOp{
		notFound:  map[string]bool{"aaa-cli": true, "bbb-cli": true},
		failWrite: map[string]bool{"aaa-cli": true},
	}
	cfg := OnePasswordConfig{Vault: "V"}
	payload := map[string]map[string]string{
		"aaa-cli": {"A_KEY": "1"},
		"bbb-cli": {"B_KEY": "2"},
	}

	res, errs := pushPayload(context.Background(), cfg, payload, f.run)
	if len(errs) != 1 {
		t.Fatalf("want 1 error for the failed CLI, got %d: %v", len(errs), errs)
	}
	if res.ItemsCreated != 1 {
		t.Errorf("ItemsCreated=%d, want 1 (bbb-cli still created)", res.ItemsCreated)
	}
	// The error must not echo op's stderr (which could carry secret material).
	if strings.Contains(errs[0].Error(), "write failed") {
		t.Errorf("error leaked op stderr: %v", errs[0])
	}
}

func TestPushPayload_EmptyIsNoop(t *testing.T) {
	f := &fakeOp{}
	res, errs := pushPayload(context.Background(), OnePasswordConfig{Vault: "V"}, nil, f.run)
	if len(errs) != 0 || res.KeysWritten != 0 || len(f.calls) != 0 {
		t.Errorf("empty payload should be a no-op; calls=%d res=%+v errs=%v", len(f.calls), res, errs)
	}
}
