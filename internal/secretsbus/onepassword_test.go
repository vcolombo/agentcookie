package secretsbus

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// opCall records one invocation of the fake op runner.
type opCall struct {
	args []string
	env  []string
}

// fakeOp is a programmable op runner. notFound holds item titles for which
// `op item get` should report "not found" (exit error → create path);
// everything else is treated as an existing item (edit path). failArgs maps a
// substring of the joined argv to an error the runner should return.
type fakeOp struct {
	calls    []opCall
	notFound map[string]bool
	failOn   string // if non-empty, any call whose argv contains this substring fails
}

func (f *fakeOp) run(_ context.Context, _ string, args, env []string) ([]byte, []byte, error) {
	f.calls = append(f.calls, opCall{args: slices.Clone(args), env: env})
	joined := strings.Join(args, " ")
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return nil, []byte("boom"), errors.New("op failed")
	}
	// `op item get <title> ...`: error when the title is in notFound.
	if len(args) >= 3 && args[0] == "item" && args[1] == "get" {
		if f.notFound[args[2]] {
			return nil, []byte("not found"), errors.New("exit 1")
		}
	}
	return []byte("{}"), nil, nil
}

func (f *fakeOp) lastWrite() opCall {
	// The write (create/edit) is the call following the matching get.
	for i := len(f.calls) - 1; i >= 0; i-- {
		if len(f.calls[i].args) >= 2 && f.calls[i].args[0] == "item" &&
			(f.calls[i].args[1] == "create" || f.calls[i].args[1] == "edit") {
			return f.calls[i]
		}
	}
	return opCall{}
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
	if res.ItemsCreated != 1 || res.ItemsUpdated != 0 {
		t.Errorf("got created=%d updated=%d, want 1/0", res.ItemsCreated, res.ItemsUpdated)
	}
	if res.KeysWritten != 2 {
		t.Errorf("KeysWritten=%d, want 2", res.KeysWritten)
	}

	w := f.lastWrite()
	wantPrefix := []string{"item", "create", "--category", "API Credential", "--title", "github-cli", "--vault", "AgentCookie"}
	if !slices.Equal(w.args[:len(wantPrefix)], wantPrefix) {
		t.Errorf("create argv prefix = %v, want %v", w.args[:len(wantPrefix)], wantPrefix)
	}
	// Field assignments are sorted; GH_HOST before GITHUB_TOKEN.
	wantFields := []string{"GH_HOST[password]=github.com", "GITHUB_TOKEN[password]=ghp_xyz"}
	if !slices.Equal(w.args[len(wantPrefix):], wantFields) {
		t.Errorf("create field assignments = %v, want %v", w.args[len(wantPrefix):], wantFields)
	}
	// Service-account token is injected into the subprocess env.
	if !slices.Contains(w.env, "OP_SERVICE_ACCOUNT_TOKEN=ops_tok") {
		t.Errorf("env missing OP_SERVICE_ACCOUNT_TOKEN")
	}
}

func TestPushPayload_EditsExistingItem(t *testing.T) {
	f := &fakeOp{notFound: map[string]bool{}} // get succeeds → item exists → edit
	cfg := OnePasswordConfig{Vault: "AgentCookie"}
	payload := map[string]map[string]string{"slack-cli": {"SLACK_TOKEN": "xoxb"}}

	res, errs := pushPayload(context.Background(), cfg, payload, f.run)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if res.ItemsUpdated != 1 || res.ItemsCreated != 0 {
		t.Errorf("got created=%d updated=%d, want 0/1", res.ItemsCreated, res.ItemsUpdated)
	}
	w := f.lastWrite()
	want := []string{"item", "edit", "slack-cli", "--vault", "AgentCookie", "SLACK_TOKEN[password]=xoxb"}
	if !slices.Equal(w.args, want) {
		t.Errorf("edit argv = %v, want %v", w.args, want)
	}
}

func TestPushPayload_SkipsInvalidNames(t *testing.T) {
	f := &fakeOp{notFound: map[string]bool{"good-cli": true}}
	cfg := OnePasswordConfig{Vault: "V"}
	payload := map[string]map[string]string{
		"good-cli":     {"OK_KEY": "v1", "bad key": "v2", "1BAD": "v3"},
		"Bad_CLI_Name": {"WHATEVER": "v"}, // invalid CLI name (uppercase/underscore)
	}

	res, errs := pushPayload(context.Background(), cfg, payload, f.run)

	// Only the one valid field on the valid CLI is written.
	if res.KeysWritten != 1 {
		t.Errorf("KeysWritten=%d, want 1", res.KeysWritten)
	}
	if res.ItemsCreated != 1 {
		t.Errorf("ItemsCreated=%d, want 1", res.ItemsCreated)
	}
	// The invalid CLI produces a non-fatal error and a "<cli>/*" skip entry.
	if !slices.Contains(res.SkippedKeys, "Bad_CLI_Name/*") {
		t.Errorf("SkippedKeys missing Bad_CLI_Name/*: %v", res.SkippedKeys)
	}
	if !slices.Contains(res.SkippedKeys, "good-cli/bad key") || !slices.Contains(res.SkippedKeys, "good-cli/1BAD") {
		t.Errorf("SkippedKeys missing invalid keys: %v", res.SkippedKeys)
	}
	if len(errs) != 1 {
		t.Errorf("want 1 non-fatal error (invalid CLI), got %d: %v", len(errs), errs)
	}
	w := f.lastWrite()
	want := []string{"item", "create", "--category", "API Credential", "--title", "good-cli", "--vault", "V", "OK_KEY[password]=v1"}
	if !slices.Equal(w.args, want) {
		t.Errorf("create argv = %v, want %v", w.args, want)
	}
}

func TestPushPayload_PushFailureIsNonFatalAndContinues(t *testing.T) {
	// First CLI's create fails; second CLI must still be processed.
	f := &fakeOp{notFound: map[string]bool{"aaa-cli": true, "bbb-cli": true}, failOn: "--title aaa-cli"}
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
}

func TestPushPayload_EmptyIsNoop(t *testing.T) {
	f := &fakeOp{}
	res, errs := pushPayload(context.Background(), OnePasswordConfig{Vault: "V"}, nil, f.run)
	if len(errs) != 0 || res.KeysWritten != 0 || len(f.calls) != 0 {
		t.Errorf("empty payload should be a no-op; calls=%d res=%+v errs=%v", len(f.calls), res, errs)
	}
}
