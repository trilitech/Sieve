package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

	if _, err := os.Stat(sc.Script); err != nil {
		return nil, fmt.Errorf("script evaluator: script not found: %w", err)
	}

	return &ScriptEvaluator{config: sc}, nil
}

// Type returns the evaluator type identifier.
func (s *ScriptEvaluator) Type() string {
	return "script"
}

// Evaluate runs the configured script and returns its decision.
func (s *ScriptEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	_ = ctx // script timeout is independent of the caller's context
	timeout := s.config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Independent timeout — not derived from the caller's context, because
	// an already-cancelled caller ctx would make cmd.Run return instantly
	// without honoring the intended timeout.
	scriptCtx, cancel := context.WithTimeout(context.Background(), timeout)
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
