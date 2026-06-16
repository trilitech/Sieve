package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ScriptConfig holds configuration for the script evaluator.
type ScriptConfig struct {
	Command string        `json:"command"` // e.g. "python3"
	Script  string        `json:"script"`  // path to script file
	Timeout time.Duration `json:"timeout"` // default 5s
}

// ScriptEvaluator runs an external process to decide policy.
type ScriptEvaluator struct {
	config ScriptConfig
}

// NewScriptEvaluator creates a ScriptEvaluator from a generic config map.
func NewScriptEvaluator(config map[string]any) (*ScriptEvaluator, error) {
	var sc ScriptConfig

	if v, ok := config["command"]; ok {
		if s, ok := v.(string); ok {
			sc.Command = s
		}
	}
	if v, ok := config["script"]; ok {
		if s, ok := v.(string); ok {
			sc.Script = s
		}
	}

	sc.Timeout = parseTimeout(config["timeout"], 5*time.Second)

	if sc.Command == "" {
		return nil, fmt.Errorf("script evaluator: command is required")
	}
	if sc.Script == "" {
		return nil, fmt.Errorf("script evaluator: script path is required")
	}

	// Command allowlist enforcement. Stored policies that pre-date the
	// allowlist and reference a disallowed interpreter (anything not in
	// CurrentCommandAllowlist) MUST fail at evaluation time with the
	// documented error rather than being silently downgraded — operators
	// are expected to fix the policy by hand, so this is a hard break.
	if err := ValidateCommand(sc.Command, CurrentCommandAllowlist()); err != nil {
		return nil, fmt.Errorf("script evaluator: %w", err)
	}

	// Resolve symlinks so we can reason about what the interpreter will
	// actually open. EvalSymlinks also turns a relative path into an
	// absolute one, which protects against a later `os.Chdir` racing the
	// exec. We refuse non-regular files (devices, FIFOs, sockets) — the
	// interpreter would block or read garbage from those — and surface
	// the resolved path back into the stored config so subsequent
	// re-runs of this evaluator see the same file even if a symlink
	// further up the chain is replaced.
	resolved, err := filepath.EvalSymlinks(sc.Script)
	if err != nil {
		return nil, fmt.Errorf("script evaluator: script not found: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("script evaluator: script not readable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("script evaluator: script must be a regular file (got %s)", info.Mode().Type())
	}
	sc.Script = resolved

	return &ScriptEvaluator{config: sc}, nil
}

// Type returns the evaluator type identifier.
func (s *ScriptEvaluator) Type() string {
	return "script"
}

// Evaluate runs the configured script and returns its decision.
func (s *ScriptEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	timeout := s.config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Derive scriptCtx from the caller ctx when it is still live so that a
	// client disconnect cancels the script process (saving resources).
	// When the caller ctx is already done (e.g., already-cancelled context),
	// fall back to context.Background so the timeout is honoured in full.
	baseCtx := ctx
	if ctx.Err() != nil {
		baseCtx = context.Background()
	}
	scriptCtx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scriptCtx, s.config.Command, s.config.Script)

	// Sandbox: don't leak parent-process environment variables to the
	// policy script. PATH is whitelisted so the interpreter (python3, node,
	// etc.) can still be located on disk.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

	inputData, err := json.Marshal(req)
	if err != nil {
		return denyDecision("script evaluator: failed to marshal request: " + err.Error()), nil
	}

	cmd.Stdin = bytes.NewReader(inputData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		reason := fmt.Sprintf("script evaluator: process failed: %v", err)
		if stderr.Len() > 0 {
			stderrText := stderr.String()
			const maxStderr = 500
			if len(stderrText) > maxStderr {
				stderrText = stderrText[:maxStderr] + "... (truncated)"
			}
			reason += "; stderr: " + stderrText
		}
		return denyDecision(reason), nil
	}

	var decision PolicyDecision
	if err := json.Unmarshal(stdout.Bytes(), &decision); err != nil {
		return denyDecision("script evaluator: failed to parse output: " + err.Error()), nil
	}

	// Validate the action is one of the known values to prevent script injection.
	switch decision.Action {
	case "allow", "deny", "approval_required":
		// valid
	default:
		return denyDecision(fmt.Sprintf("script evaluator: invalid action %q; treating as deny", decision.Action)), nil
	}

	return &decision, nil
}

// denyDecision is a helper that returns a deny PolicyDecision.
func denyDecision(reason string) *PolicyDecision {
	return &PolicyDecision{
		Action: "deny",
		Reason: reason,
	}
}

// parseTimeout handles both string ("5s") and numeric (5, interpreted as seconds) timeout values.
func parseTimeout(v any, defaultVal time.Duration) time.Duration {
	if v == nil {
		return defaultVal
	}
	switch t := v.(type) {
	case string:
		if d, err := time.ParseDuration(t); err == nil {
			return d
		}
		return defaultVal
	case float64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
		return defaultVal
	case int:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
		return defaultVal
	case json.Number:
		if f, err := t.Float64(); err == nil && f > 0 {
			return time.Duration(f) * time.Second
		}
		return defaultVal
	default:
		return defaultVal
	}
}
