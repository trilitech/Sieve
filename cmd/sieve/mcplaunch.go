package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// runMCPLaunch is the entry point for `sieve mcp-launch`. It is a thin stdio
// → HTTP bridge: it reads newline-delimited JSON-RPC messages from stdin,
// POSTs each one to the Sieve MCP endpoint with a Bearer token sourced from
// the macOS Keychain (or a token file), and writes the response back to
// stdout. This lets Claude Desktop — which only supports stdio MCP servers —
// talk to Sieve without putting the bearer token in plaintext in
// claude_desktop_config.json.
//
// Token sources are tried in order: macOS Keychain, --token-file. There is
// deliberately no env-var fallback (consistent with secrets.Acquire).
func runMCPLaunch(args []string) error {
	// ContinueOnError so a bad flag returns up to the caller (which
	// log.Fatalf's) instead of os.Exit'ing inside the parser. Keeps the
	// error format consistent with the rest of `sieve mcp-launch: …`.
	fs := flag.NewFlagSet("mcp-launch", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:19817/mcp", "Sieve MCP endpoint")
	keychainService := fs.String("keychain", "sieve-token",
		"macOS Keychain generic-password service name to read the token from")
	tokenFile := fs.String("token-file", "",
		"file containing the Sieve bearer token (used only if Keychain lookup fails or on non-macOS hosts)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	token, err := loadToken(*keychainService, *tokenFile)
	if err != nil {
		return err
	}
	return bridge(*url, token, os.Stdin, os.Stdout, os.Stderr)
}

// loadToken returns the Sieve bearer token, trying macOS Keychain first
// (when applicable) and falling back to a file path.
func loadToken(keychainService, tokenFile string) (string, error) {
	if runtime.GOOS == "darwin" && keychainService != "" {
		// user.Current() works under LaunchAgent / non-interactive contexts
		// where $USER may be empty; falls back to $USER if it errors.
		username := os.Getenv("USER")
		if u, err := user.Current(); err == nil && u.Username != "" {
			username = u.Username
		}
		out, err := exec.Command("security", "find-generic-password",
			"-a", username, "-s", keychainService, "-w").Output()
		if err == nil {
			tok := strings.TrimSpace(string(out))
			if tok != "" {
				return tok, nil
			}
		}
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file %q: %w", tokenFile, err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("token file %q is empty", tokenFile)
		}
		return tok, nil
	}
	return "", errors.New("no token: store one in macOS Keychain (`security add-generic-password -s sieve-token -a $USER -w sieve_tok_…`) or pass --token-file")
}

// bridge forwards newline-delimited JSON-RPC messages from in to the MCP
// endpoint and writes responses back to out. It returns when in is closed
// or an unrecoverable error occurs. Notifications (requests with no `id`
// field) are forwarded but their responses are suppressed, per JSON-RPC.
//
// If the upstream returns a non-2xx response, the body is unlikely to be
// valid JSON-RPC (e.g. the auth middleware returns plain-text 401). In that
// case the raw body is logged to errOut for diagnostics and a synthesized
// JSON-RPC error response is written to out so Claude Desktop's protocol
// stream stays in sync.
func bridge(url, token string, in io.Reader, out, errOut io.Writer) error {
	client := &http.Client{Timeout: 60 * time.Second}

	scanner := bufio.NewScanner(in)
	// MCP messages can be larger than the default 64 KiB, e.g. when
	// tools/list returns dozens of tools with full JSON Schemas, or when
	// a tool returns a long email body. Allow up to 16 MiB per line.
	scanner.Buffer(make([]byte, 1<<20), 16<<20)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		// Detect notifications (no `id`) so we can drop their responses.
		// We only peek at id; we forward the original bytes verbatim.
		var probe struct {
			ID *json.RawMessage `json:"id"`
		}
		isNotification := json.Unmarshal(line, &probe) == nil && probe.ID == nil

		req, err := http.NewRequest("POST", url, bytes.NewReader(line))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("post to %s: %w", url, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read response: %w", readErr)
		}

		if resp.StatusCode >= 400 {
			fmt.Fprintf(errOut, "sieve mcp-launch: upstream %d: %s\n",
				resp.StatusCode, truncate(strings.TrimSpace(string(body)), 500))
			if !isNotification {
				body = jsonrpcError(probe.ID, fmt.Sprintf("sieve upstream %d: %s",
					resp.StatusCode, truncate(strings.TrimSpace(string(body)), 200)))
			}
		}

		if isNotification {
			continue
		}

		if _, err := out.Write(bytes.TrimRight(body, "\n")); err != nil {
			return err
		}
		if _, err := out.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// jsonrpcError builds a JSON-RPC 2.0 error response. id is forwarded
// verbatim from the originating request (pass nil to emit "id":null).
// Code -32000 is JSON-RPC's "implementation-defined server error" range.
func jsonrpcError(id *json.RawMessage, message string) []byte {
	resp := struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      *json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	resp.Error.Code = -32000
	resp.Error.Message = message
	b, _ := json.Marshal(resp)
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
