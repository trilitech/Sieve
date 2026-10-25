// Package gmail implements the Google connector for Sieve. It wraps Google
// service APIs (Gmail, Drive, Calendar, Contacts, Sheets, and Docs) behind
// the connector.Connector interface so that the MCP server and REST API can
// invoke Google operations uniformly through the policy pipeline.
// The connector uses a Factory pattern: Factory(config) returns a ready-to-use
// GoogleConnector. The factory handles two OAuth token scenarios:
// 1. If client_id and client_secret are present in the config, it builds a
// refreshing TokenSource via oauth2.Config.TokenSource. This means expired
// access tokens are automatically refreshed using the refresh_token, which
// is the normal production path after the web UI OAuth flow.
// 2. If client credentials are missing (e.g., CLI setup before OAuth), it
// falls back to a StaticTokenSource that uses the access token as-is.
// This won't refresh, so it will stop working once the token expires —
// but it allows basic validation and testing.
// Token expiry handling: if the stored expiry is zero/missing, it is set to
// time.Now so the oauth2 library treats the token as expired and immediately
// attempts a refresh. This ensures stale tokens from a database restore or
// manual config don't silently fail.
package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
	gmailclient "github.com/trilitech/Sieve/internal/gmail"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	calendarapi "google.golang.org/api/calendar/v3"
	docsapi "google.golang.org/api/docs/v1"
	driveapi "google.golang.org/api/drive/v3"
	googleapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
	peopleapi "google.golang.org/api/people/v1"
	sheetsapi "google.golang.org/api/sheets/v4"
)

// Meta describes the Google Account connector for the UI catalog.
//
// The OAuth-managed fields (oauth_token, client_id, client_secret) are
// written by the bespoke OAuth flow in internal/web/server.go (handleAddConnection,
// handleOAuthCallback). They're declared here with Editable=false +
// EditOnly=true so the cmd/sieve/registry_arch_test.go invariant holds —
// every persisted config key MUST appear on Meta() — while the generic
// forms continue to not render them.
var Meta = connector.ConnectorMeta{
	Type:        "google",
	Name:        "Google Account",
	Description: "Gmail, Drive, Calendar, Contacts, and Sheets via Google APIs",
	Category:    "Google",
	SetupFields: []connector.Field{
		{Name: "email", Label: "Google Account Email", Type: "text", Required: true, Placeholder: "you@gmail.com"},
		{Name: "oauth_token", Label: "OAuth Token", Type: "oauth", Required: true, Editable: false, EditOnly: true, Secret: true,
			HelpText: "Authenticate via Google OAuth. Stored as a token blob — set by the OAuth callback handler, not directly editable."},
		{Name: "client_id", Label: "OAuth client_id", Type: "text", Editable: false, EditOnly: true,
			HelpText: "Google OAuth client_id used to refresh the access token. Copied from the application's client_secret*.json at connection-creation time; declared here for the architecture test."},
		{Name: "client_secret", Label: "OAuth client_secret", Type: "password", Editable: false, EditOnly: true, Secret: true,
			HelpText: "Google OAuth client_secret used to refresh the access token. Same source as client_id."},
	},
	Operations: operations,
	// recipient_domains is populated by GoogleConnector.EnrichContext for the
	// send/draft/reply ops (see EnrichContext below). The domain_allowlist
	// condition lets operators permit a send only when every recipient domain
	// is in the configured set.
	RuleConditions: []connector.RuleCondition{
		{
			Key:     "recipient_domain",
			Label:   "Recipient domains (allowlist)",
			Kind:    "domain_allowlist",
			CtxPath: "context.recipient_domains",
			Help:    "Sends allowed only if every recipient domain is in this list",
			Ops:     []string{"send_email", "create_draft", "update_draft", "reply", "forward_draft", "forward_email"},
		},
		{
			Key:     "recipient_count",
			Label:   "Recipient count",
			Kind:    "number",
			CtxPath: "context.recipient_count",
			Help:    "Cap how many distinct recipients (To+Cc) a send may have",
			Ops:     []string{"send_email", "create_draft", "update_draft", "reply", "forward_draft", "forward_email"},
		},
	},
	// ContentFields are the response text fields safe for content filtering.
	// Redact/exclude apply ONLY within these — NOT id/thread_id/labels/date or
	// attachment data (a 16-digit run in a base64 MIME part is never redacted).
	ContentFields: []connector.ContentField{
		{Key: "subject", Label: "Subject"},
		{Key: "body", Label: "Body"},
		{Key: "body_html", Label: "Body (HTML)"},
		{Key: "snippet", Label: "Snippet"},
		{Key: "from", Label: "From"},
		{Key: "to", Label: "To"},
		{Key: "cc", Label: "Cc"},
	},
	// Bridge the pure EnrichContext method to the Meta func field the PDP calls
	// (no configured instance / keyring needed — the method ignores its
	// receiver). Populates context.recipient_domains for the domain_allowlist
	// condition above.
	EnrichContext: (&GoogleConnector{}).EnrichContext,
}

// GoogleConnector implements the connector.Connector interface for Google services.
type GoogleConnector struct {
	client         *gmailclient.Client
	driveClient    *gmailclient.DriveClient
	calendarClient *gmailclient.CalendarClient
	peopleClient   *gmailclient.PeopleClient
	sheetsClient   *gmailclient.SheetsClient
	docsClient     *gmailclient.DocsClient
	email          string
}

// persistingTokenSource wraps an oauth2.TokenSource and calls callbacks for
// the two outcomes that matter to Sieve's persistence layer:
// - onRefresh: a refresh succeeded. Persist the new token to the DB so
// server restarts don't burn a fresh refresh on every startup.
// - onRefreshFailure: a refresh failed irrecoverably (invalid_grant et al.).
// Mark the connection needs_reauth so the UI surfaces it and future
// calls return a structured error instead of opaque 500s.
type persistingTokenSource struct {
	base             oauth2.TokenSource
	lastHash         string // last seen access_token, to detect actual refreshes
	onRefresh        func(token *oauth2.Token)
	onRefreshFailure func(reason string)
}

// reauthErrorCodes lists the OAuth2 RetrieveError.ErrorCode values that
// indicate the refresh token itself is dead — re-authentication is the only
// fix. Other errors (network blips, 5xx upstream, malformed responses) are
// transient and shouldn't flip the needs_reauth flag.
var reauthErrorCodes = map[string]bool{
	"invalid_grant":       true, // user revoked, refresh expired/rotated, or password change
	"unauthorized_client": true, // client config changed after the token was issued
	"invalid_client":      true, // client_id/secret no longer valid for this token
}

func (p *persistingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := p.base.Token()
	if err != nil {
		// Inspect the error: if it's an OAuth refresh failure with a code
		// that means "the refresh token is dead", flip needs_reauth and
		// return the wrapped sentinel so callers (router, sweeper, MCP)
		// can map it to a structured "please re-authenticate" response.
		var rerr *oauth2.RetrieveError
		if errors.As(err, &rerr) && reauthErrorCodes[rerr.ErrorCode] {
			if p.onRefreshFailure != nil {
				reason := rerr.ErrorCode
				if rerr.ErrorDescription != "" {
					reason = rerr.ErrorCode + ": " + rerr.ErrorDescription
				}
				p.onRefreshFailure(reason)
			}
			return nil, fmt.Errorf("%w: %s", connector.ErrNeedsReauth, rerr.ErrorCode)
		}
		return nil, err
	}
	// Detect if the token changed (refresh happened).
	if tok.AccessToken != p.lastHash {
		if p.lastHash != "" && p.onRefresh != nil {
			// Not the first call — a real refresh happened.
			p.onRefresh(tok)
		}
		p.lastHash = tok.AccessToken
	}
	return tok, nil
}

// Factory creates a new GoogleConnector from the provided config.
// Expected config keys:
// - "email": string - the user's email address
// - "oauth_token": map[string]any - OAuth2 token with keys: access_token, token_type, refresh_token, expiry
// - "client_id", "client_secret": for token refresh
// - "_on_token_refresh": func(*oauth2.Token) - optional callback for persisting refreshed tokens
func Factory(config map[string]any) (connector.Connector, error) {
	email, ok := config["email"].(string)
	if !ok || email == "" {
		return nil, fmt.Errorf("gmail connector: missing or invalid 'email' in config")
	}

	tokenMap, ok := config["oauth_token"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("gmail connector: missing or invalid 'oauth_token' in config")
	}

	token, err := tokenFromMap(tokenMap)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: parsing oauth_token: %w", err)
	}

	// Build a refreshing token source using client credentials if available,
	// otherwise fall back to a static (non-refreshing) token source.
	var tokenSource oauth2.TokenSource
	clientID, _ := config["client_id"].(string)
	clientSecret, _ := config["client_secret"].(string)
	if clientID != "" && clientSecret != "" {
		oauthConf := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
		}
		base := oauthConf.TokenSource(context.Background(), token)

		// Wrap with persistence callbacks if provided. The connections
		// service registers both: onRefresh persists rotated tokens,
		// onRefreshFailure flips the needs_reauth flag.
		onRefresh, _ := config["_on_token_refresh"].(func(*oauth2.Token))
		onRefreshFailure, _ := config["_on_token_refresh_failure"].(func(string))
		tokenSource = &persistingTokenSource{
			base:             base,
			lastHash:         token.AccessToken,
			onRefresh:        onRefresh,
			onRefreshFailure: onRefreshFailure,
		}
	} else {
		tokenSource = oauth2.StaticTokenSource(token)
	}

	tsOpt := option.WithTokenSource(tokenSource)

	svc, err := googleapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating gmail service: %w", err)
	}

	driveSvc, err := driveapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating drive service: %w", err)
	}

	calendarSvc, err := calendarapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating calendar service: %w", err)
	}

	peopleSvc, err := peopleapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating people service: %w", err)
	}

	sheetsSvc, err := sheetsapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating sheets service: %w", err)
	}

	docsSvc, err := docsapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating docs service: %w", err)
	}

	client := gmailclient.NewClient(svc, email)

	return &GoogleConnector{
		client:         client,
		driveClient:    gmailclient.NewDriveClient(driveSvc),
		calendarClient: gmailclient.NewCalendarClient(calendarSvc),
		peopleClient:   gmailclient.NewPeopleClient(peopleSvc),
		sheetsClient:   gmailclient.NewSheetsClient(sheetsSvc),
		docsClient:     gmailclient.NewDocsClient(docsSvc, driveSvc),
		email:          email,
	}, nil
}

// tokenFromMap reconstructs an *oauth2.Token from a map[string]any.
func tokenFromMap(m map[string]any) (*oauth2.Token, error) {
	accessToken, _ := m["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("missing access_token")
	}

	token := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    getStringFromMap(m, "token_type"),
		RefreshToken: getStringFromMap(m, "refresh_token"),
	}

	if expiryStr, ok := m["expiry"].(string); ok && expiryStr != "" {
		t, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			return nil, fmt.Errorf("parsing expiry: %w", err)
		}
		token.Expiry = t
	}

	// If expiry is zero (missing or unparseable), set it to now. The oauth2
	// library checks token.Valid which returns false when Expiry <= now,
	// triggering an automatic refresh via the refresh_token. Without this,
	// a missing expiry would make the token appear perpetually valid even
	// after the access token actually expires on Google's side.
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().UTC()
	}

	return token, nil
}

func getStringFromMap(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// Type returns "google".
func (g *GoogleConnector) Type() string {
	return "google"
}

// ConfigSchemaKeys implements connector.ConfigSchemaProvider. The Google
// connector stores its config as a free-form map (no typed Config struct);
// the persisted-key list is maintained here and the architecture test
// verifies these are covered by Meta().SetupFields. Internal injection
// keys prefixed with "_" (_on_token_refresh, _on_token_refresh_failure)
// are NOT persisted — they're function-typed callbacks set at runtime by
// connections.Service and round-tripped via separate plumbing.
func (g *GoogleConnector) ConfigSchemaKeys() []string {
	return []string{"email", "oauth_token", "client_id", "client_secret"}
}

// Operations returns the list of supported Gmail operations.
func (g *GoogleConnector) Operations() []connector.OperationDef {
	return operations
}

// recipientParamsByOp lists, per outbound op, the params that carry actual
// recipient email addresses. Drawn from the Gmail OperationDefs: only "to" and
// "cc" hold addresses ([]string). "reply_to" is deliberately excluded — in this
// connector it is a Gmail message ID to reply to, not an address. There is no
// "bcc" param in the catalog. Read-only ops are absent (no recipients to gate).
var recipientParamsByOp = map[string][]string{
	"create_draft":  {"to", "cc"},
	"update_draft":  {"to", "cc"},
	"send_email":    {"to", "cc"},
	"reply":         {"to", "cc"},
	"forward_draft": {"to", "cc"},
	"forward_email": {"to", "cc"},
}

// EnrichContext implements connector.ContextEnricher. For the send/draft/reply
// ops it collects every recipient address, extracts the domain after '@'
// (lowercased), and returns {"recipient_domains": [...]} with duplicates
// removed. The domain_allowlist rule condition (CtxPath
// "context.recipient_domains", declared in Meta) reads this attribute. Returns
// nil for ops with no recipient params or when no usable address is present.
// Pure: no I/O, no mutation of params.
func (g *GoogleConnector) EnrichContext(op string, params map[string]any) map[string]any {
	keys, ok := recipientParamsByOp[op]
	if !ok {
		return nil
	}

	addrSeen := make(map[string]struct{})
	domSeen := make(map[string]struct{})
	domains := make([]string, 0)
	for _, key := range keys {
		for _, addr := range recipientAddresses(params, key) {
			a := strings.ToLower(strings.TrimSpace(addr))
			if a == "" {
				continue
			}
			if _, dup := addrSeen[a]; dup {
				continue
			}
			addrSeen[a] = struct{}{}
			d := domainOf(addr)
			if d == "" {
				continue
			}
			if _, dup := domSeen[d]; dup {
				continue
			}
			domSeen[d] = struct{}{}
			domains = append(domains, d)
		}
	}
	if len(addrSeen) == 0 {
		return nil
	}
	// recipient_count = distinct recipient addresses (the "blast radius" of a
	// send); recipient_domains = the distinct domains among them.
	out := map[string]any{"recipient_count": len(addrSeen)}
	if len(domains) > 0 {
		out["recipient_domains"] = domains
	}
	return out
}

// recipientAddresses reads a recipient param that may arrive as []string,
// []any (JSON-decoded), or a single string, returning the addresses as a
// slice. getStringSliceParam already covers the slice shapes; the plain-string
// fallback handles callers that pass a single address as a bare string.
func recipientAddresses(params map[string]any, key string) []string {
	if vals := getStringSliceParam(params, key); len(vals) > 0 {
		return vals
	}
	if s, ok := params[key].(string); ok && s != "" {
		return []string{s}
	}
	return nil
}

// domainOf extracts the lowercased domain from an email address (the part
// after the last '@'). Returns "" when there is no '@' or the domain part is
// empty, so malformed entries are skipped rather than producing junk domains.
func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	domain := strings.TrimSpace(addr[at+1:])
	return strings.ToLower(domain)
}

// operations is the static catalog of supported Google operations. It is the
// single source of truth shared by the runtime Operations() method and the
// Meta.Operations field consumed by IAM taxonomy/schema generation.
var operations = []connector.OperationDef{
	{
		Name:        "list_emails",
		Description: "Search and list emails using Gmail query syntax. Returns lightweight stubs (id, thread_id, snippet, labels, and the From/To/Cc/Subject/Date/Message-ID headers) — no body, no attachments. Call read_email to fetch the full content of a specific message. This keeps list responses small enough to fit in agent context windows even with max_results=100.",
		Params: map[string]connector.ParamDef{
			"query":              {Type: "string", Description: "Gmail search query string (same syntax as the Gmail web UI search box)", Required: false},
			"max_results":        {Type: "int", Description: "Maximum number of results to return (default 100, max 500)", Required: false},
			"page_token":         {Type: "string", Description: "Page token for pagination", Required: false},
			"label_ids":          {Type: "[]string", Description: "Restrict results to messages carrying ALL of these label ids", Required: false},
			"include_spam_trash": {Type: "bool", Description: "Include messages in SPAM and TRASH (default false)", Required: false},
		},
		ReadOnly: true,
	},
	{
		Name:        "read_email",
		Description: "Read a single email by message ID, returning full headers, plain-text body, HTML body, and attachment metadata",
		Params: map[string]connector.ParamDef{
			"message_id": {Type: "string", Description: "The ID of the message to read", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "read_email_raw",
		Description: "Read a single email by message ID, returning the byte-faithful RFC822 message (full headers, all MIME parts, attachments inline) base64url-encoded in `raw`. Response shape matches Google's users.messages.get?format=RAW. Use for archival pipelines that need .eml-grade fidelity; response bodies are large, so this is not suitable for context-window-bound interactive use — prefer read_email for that.",
		Params: map[string]connector.ParamDef{
			"message_id": {Type: "string", Description: "The ID of the message to read", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "read_thread",
		Description: "Read all messages in a thread",
		Params: map[string]connector.ParamDef{
			"thread_id": {Type: "string", Description: "The ID of the thread to read", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "create_draft",
		Description: "Create a new email draft. To draft a reply INTO an existing conversation, set in_reply_to_message_id to the parent message's id — the connector looks up the thread and Message-ID/References headers so the draft threads correctly. (thread_id / in_reply_to / references may be set explicitly instead.)",
		Params: map[string]connector.ParamDef{
			"to":                     {Type: "[]string", Description: "Recipient email addresses", Required: false},
			"cc":                     {Type: "[]string", Description: "CC email addresses", Required: false},
			"bcc":                    {Type: "[]string", Description: "BCC email addresses", Required: false},
			"subject":                {Type: "string", Description: "Email subject (defaults to Re: parent subject when in_reply_to_message_id is set)", Required: false},
			"body":                   {Type: "string", Description: "Email body text", Required: false},
			"in_reply_to_message_id": {Type: "string", Description: "Gmail message id of the parent to reply into; the connector derives thread_id, In-Reply-To and References", Required: false},
			"thread_id":              {Type: "string", Description: "Gmail thread id to attach the draft to (advanced; prefer in_reply_to_message_id)", Required: false},
			"in_reply_to":            {Type: "string", Description: "Parent RFC5322 Message-ID for the In-Reply-To header (advanced)", Required: false},
			"references":             {Type: "string", Description: "RFC5322 References chain (advanced)", Required: false},
			"reply_to":               {Type: "string", Description: "DEPRECATED legacy alias; use in_reply_to_message_id", Required: false},
			"attachments":            {Type: "[]object", Description: "Files to attach, each {filename, mime_type, content} where content is base64-encoded bytes", Required: false},
			"reply_to_address":       {Type: "[]string", Description: "Reply-To header: addresses replies should go to. Unrelated to the deprecated reply_to threading alias.", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "update_draft",
		Description: "Update an existing email draft",
		Params: map[string]connector.ParamDef{
			"draft_id":               {Type: "string", Description: "The ID of the draft to update", Required: true},
			"to":                     {Type: "[]string", Description: "Recipient email addresses", Required: false},
			"cc":                     {Type: "[]string", Description: "CC email addresses", Required: false},
			"bcc":                    {Type: "[]string", Description: "BCC email addresses", Required: false},
			"subject":                {Type: "string", Description: "Email subject", Required: false},
			"body":                   {Type: "string", Description: "Email body text", Required: false},
			"in_reply_to_message_id": {Type: "string", Description: "Gmail message id of the parent to reply into; derives thread_id, In-Reply-To and References", Required: false},
			"thread_id":              {Type: "string", Description: "Gmail thread id to attach the draft to (advanced)", Required: false},
			"in_reply_to":            {Type: "string", Description: "Parent RFC5322 Message-ID for the In-Reply-To header (advanced)", Required: false},
			"references":             {Type: "string", Description: "RFC5322 References chain (advanced)", Required: false},
			"attachments":            {Type: "[]object", Description: "Files to attach, each {filename, mime_type, content} where content is base64-encoded bytes", Required: false},
			"reply_to_address":       {Type: "[]string", Description: "Reply-To header: addresses replies should go to. Unrelated to the deprecated reply_to threading alias.", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "send_email",
		Description: "Send an email directly. Set in_reply_to_message_id to send a reply INTO an existing conversation (derives thread_id and threading headers).",
		Params: map[string]connector.ParamDef{
			"to":                     {Type: "[]string", Description: "Recipient email addresses", Required: false},
			"cc":                     {Type: "[]string", Description: "CC email addresses", Required: false},
			"bcc":                    {Type: "[]string", Description: "BCC email addresses", Required: false},
			"subject":                {Type: "string", Description: "Email subject", Required: false},
			"body":                   {Type: "string", Description: "Email body text", Required: false},
			"in_reply_to_message_id": {Type: "string", Description: "Gmail message id of the parent to reply into; derives thread_id, In-Reply-To and References", Required: false},
			"thread_id":              {Type: "string", Description: "Gmail thread id to attach the message to (advanced)", Required: false},
			"in_reply_to":            {Type: "string", Description: "Parent RFC5322 Message-ID for the In-Reply-To header (advanced)", Required: false},
			"references":             {Type: "string", Description: "RFC5322 References chain (advanced)", Required: false},
			"reply_to":               {Type: "string", Description: "DEPRECATED legacy alias; use in_reply_to_message_id", Required: false},
			"attachments":            {Type: "[]object", Description: "Files to attach, each {filename, mime_type, content} where content is base64-encoded bytes", Required: false},
			"reply_to_address":       {Type: "[]string", Description: "Reply-To header: addresses replies should go to. Unrelated to the deprecated reply_to threading alias.", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "forward_draft",
		Description: "Draft a forward of an existing message. Sieve looks up the source message and assembles a faithful forwarded copy — the original From/Date/Subject/To, the original body in BOTH plain text and HTML (so links survive), and the original attachments — beneath your own note. This is a separate privilege from create_draft: forwarding existing mail to new recipients is an exfiltration primitive and is granted independently of composing/replying.",
		Params: map[string]connector.ParamDef{
			"message_id":       {Type: "string", Description: "Gmail message id of the source message to forward", Required: true},
			"to":               {Type: "[]string", Description: "Recipient email addresses", Required: false},
			"cc":               {Type: "[]string", Description: "CC email addresses", Required: false},
			"bcc":              {Type: "[]string", Description: "BCC email addresses", Required: false},
			"subject":          {Type: "string", Description: "Subject (defaults to Fwd: <source subject>)", Required: false},
			"body":             {Type: "string", Description: "Your note, placed above the forwarded content", Required: false},
			"attachments":      {Type: "[]object", Description: "Additional files to attach beyond the source's own attachments, each {filename, mime_type, content} (base64)", Required: false},
			"reply_to_address": {Type: "[]string", Description: "Reply-To header: addresses replies should go to.", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "forward_email",
		Description: "Send a forward of an existing message directly. Identical assembly to forward_draft (real headers, text + HTML body, original attachments) but sends instead of drafting; gated separately from send_email.",
		Params: map[string]connector.ParamDef{
			"message_id":       {Type: "string", Description: "Gmail message id of the source message to forward", Required: true},
			"to":               {Type: "[]string", Description: "Recipient email addresses", Required: false},
			"cc":               {Type: "[]string", Description: "CC email addresses", Required: false},
			"bcc":              {Type: "[]string", Description: "BCC email addresses", Required: false},
			"subject":          {Type: "string", Description: "Subject (defaults to Fwd: <source subject>)", Required: false},
			"body":             {Type: "string", Description: "Your note, placed above the forwarded content", Required: false},
			"attachments":      {Type: "[]object", Description: "Additional files to attach beyond the source's own attachments, each {filename, mime_type, content} (base64)", Required: false},
			"reply_to_address": {Type: "[]string", Description: "Reply-To header: addresses replies should go to.", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "send_draft",
		Description: "Send an existing draft",
		Params: map[string]connector.ParamDef{
			"draft_id": {Type: "string", Description: "The ID of the draft to send", Required: true},
		},
		ReadOnly: false,
	},
	{
		Name:        "list_drafts",
		Description: "List existing drafts as lightweight stubs (draft id + message id/thread_id/to/subject/snippet; no body). Use to find or verify drafts you created.",
		Params: map[string]connector.ParamDef{
			"max_results": {Type: "int", Description: "Maximum drafts to return (default 100, max 500)", Required: false},
		},
		ReadOnly: true,
	},
	{
		Name:        "delete_draft",
		Description: "Permanently delete a draft by id",
		Params: map[string]connector.ParamDef{
			"draft_id": {Type: "string", Description: "The ID of the draft to delete", Required: true},
		},
		ReadOnly: false,
	},
	{
		Name:        "reply",
		Description: "Reply to an existing email",
		Params: map[string]connector.ParamDef{
			"message_id":       {Type: "string", Description: "The ID of the message to reply to", Required: true},
			"to":               {Type: "[]string", Description: "Recipient email addresses (defaults to original sender)", Required: false},
			"cc":               {Type: "[]string", Description: "CC email addresses", Required: false},
			"bcc":              {Type: "[]string", Description: "BCC email addresses", Required: false},
			"subject":          {Type: "string", Description: "Email subject (defaults to Re: original subject)", Required: false},
			"body":             {Type: "string", Description: "Reply body text", Required: true},
			"attachments":      {Type: "[]object", Description: "Files to attach, each {filename, mime_type, content} where content is base64-encoded bytes", Required: false},
			"reply_to_address": {Type: "[]string", Description: "Reply-To header: addresses replies should go to. Unrelated to the deprecated reply_to threading alias.", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "add_label",
		Description: "Add a label to a message",
		Params: map[string]connector.ParamDef{
			"message_id": {Type: "string", Description: "The ID of the message", Required: true},
			"label_id":   {Type: "string", Description: "The ID of the label to add", Required: true},
		},
		ReadOnly: false,
	},
	{
		Name:        "remove_label",
		Description: "Remove a label from a message",
		Params: map[string]connector.ParamDef{
			"message_id": {Type: "string", Description: "The ID of the message", Required: true},
			"label_id":   {Type: "string", Description: "The ID of the label to remove", Required: true},
		},
		ReadOnly: false,
	},
	{
		Name:        "archive",
		Description: "Archive a message by removing the INBOX label",
		Params: map[string]connector.ParamDef{
			"message_id": {Type: "string", Description: "The ID of the message to archive", Required: true},
		},
		ReadOnly: false,
	},
	{
		Name:        "list_labels",
		Description: "List all labels for the account",
		Params:      map[string]connector.ParamDef{},
		ReadOnly:    true,
	},
	{
		Name:        "get_attachment",
		Description: "Download an email attachment",
		Params: map[string]connector.ParamDef{
			"message_id":    {Type: "string", Description: "The ID of the message containing the attachment", Required: true},
			"attachment_id": {Type: "string", Description: "The ID of the attachment", Required: true},
		},
		ReadOnly: true,
	},

	// --- Google Drive ---
	{
		Name:        "drive.list_files",
		Description: "List files in Google Drive with optional search query",
		Params: map[string]connector.ParamDef{
			"query":      {Type: "string", Description: "Drive search query (e.g. \"name contains 'report'\")", Required: false},
			"page_size":  {Type: "int", Description: "Maximum number of results (default 100)", Required: false},
			"page_token": {Type: "string", Description: "Page token for pagination", Required: false},
		},
		ReadOnly: true,
	},
	{
		Name:        "drive.get_file",
		Description: "Get metadata for a single file in Google Drive",
		Params: map[string]connector.ParamDef{
			"file_id": {Type: "string", Description: "The ID of the file", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "drive.download_file",
		Description: "Download a file's content from Google Drive (returned as base64)",
		Params: map[string]connector.ParamDef{
			"file_id": {Type: "string", Description: "The ID of the file to download", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "drive.upload_file",
		Description: "Upload a file to Google Drive",
		Params: map[string]connector.ParamDef{
			"name":             {Type: "string", Description: "Filename", Required: true},
			"content":          {Type: "string", Description: "File content as base64", Required: true},
			"mime_type":        {Type: "string", Description: "MIME type of the file", Required: true},
			"parent_folder_id": {Type: "string", Description: "Parent folder ID (optional)", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "drive.share_file",
		Description: "Share a file. Defaults to sharing with a user by email and sending a notification; set type/domain/send_notification for other grants.",
		Params: map[string]connector.ParamDef{
			"file_id":           {Type: "string", Description: "The ID of the file to share", Required: true},
			"email":             {Type: "string", Description: "Email to share with (required for type user/group)", Required: false},
			"role":              {Type: "string", Description: "Permission role: reader, writer, commenter (default: reader)", Required: false},
			"type":              {Type: "string", Description: "Grantee type: user, group, domain, anyone (default: user)", Required: false},
			"domain":            {Type: "string", Description: "Domain to share with (required for type domain)", Required: false},
			"send_notification": {Type: "bool", Description: "Send the 'shared with you' email (default true)", Required: false},
		},
		ReadOnly: false,
	},

	// --- Google Calendar ---
	{
		Name:        "calendar.list_events",
		Description: "List events from a Google Calendar",
		Params: map[string]connector.ParamDef{
			"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
			"time_min":    {Type: "string", Description: "Start time filter (RFC3339, e.g. 2024-01-01T00:00:00Z)", Required: false},
			"time_max":    {Type: "string", Description: "End time filter (RFC3339)", Required: false},
			"max_results": {Type: "int", Description: "Maximum number of events (default 100)", Required: false},
			"page_token":  {Type: "string", Description: "Page token for pagination", Required: false},
		},
		ReadOnly: true,
	},
	{
		Name:        "calendar.get_event",
		Description: "Get a single calendar event by ID",
		Params: map[string]connector.ParamDef{
			"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
			"event_id":    {Type: "string", Description: "The event ID", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "calendar.create_event",
		Description: "Create a new calendar event",
		Params: map[string]connector.ParamDef{
			"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
			"summary":     {Type: "string", Description: "Event title", Required: true},
			"start":       {Type: "string", Description: "Start time (RFC3339)", Required: true},
			"end":         {Type: "string", Description: "End time (RFC3339)", Required: true},
			"location":    {Type: "string", Description: "Event location", Required: false},
			"description": {Type: "string", Description: "Event description", Required: false},
			"attendees":   {Type: "[]string", Description: "Attendee email addresses", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "calendar.update_event",
		Description: "Update an existing calendar event",
		Params: map[string]connector.ParamDef{
			"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
			"event_id":    {Type: "string", Description: "The event ID", Required: true},
			"summary":     {Type: "string", Description: "Event title (omit to leave unchanged; empty string to clear)", Required: false},
			"start":       {Type: "string", Description: "Start time (RFC3339)", Required: false},
			"end":         {Type: "string", Description: "End time (RFC3339)", Required: false},
			"location":    {Type: "string", Description: "Event location (omit to leave unchanged; empty string to clear)", Required: false},
			"description": {Type: "string", Description: "Event description (omit to leave unchanged; empty string to clear)", Required: false},
			"attendees":   {Type: "[]string", Description: "REPLACES the whole attendee list (include existing addresses when adding; empty clears all)", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "calendar.delete_event",
		Description: "Delete a calendar event",
		Params: map[string]connector.ParamDef{
			"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
			"event_id":    {Type: "string", Description: "The event ID to delete", Required: true},
		},
		ReadOnly: false,
	},

	// --- Google People/Contacts ---
	{
		Name:        "people.list_contacts",
		Description: "List the user's Google contacts",
		Params: map[string]connector.ParamDef{
			"page_size":  {Type: "int", Description: "Maximum number of contacts (default 100)", Required: false},
			"page_token": {Type: "string", Description: "Page token for pagination", Required: false},
		},
		ReadOnly: true,
	},
	{
		Name:        "people.get_contact",
		Description: "Get a single contact by resource name",
		Params: map[string]connector.ParamDef{
			"resource_name": {Type: "string", Description: "Resource name (e.g. people/c12345)", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "people.create_contact",
		Description: "Create a new contact. Use given_name/family_name for precise name parts, or name for a full name (split on whitespace).",
		Params: map[string]connector.ParamDef{
			"name":        {Type: "string", Description: "Full name; split into given/family on whitespace (ignored if given_name/family_name set)", Required: false},
			"given_name":  {Type: "string", Description: "Given (first) name", Required: false},
			"family_name": {Type: "string", Description: "Family (last) name", Required: false},
			"email":       {Type: "string", Description: "Contact email address", Required: false},
			"phone":       {Type: "string", Description: "Contact phone number", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "people.update_contact",
		Description: "Update an existing contact. Use given_name/family_name for precise name parts, or name for a full name (split on whitespace).",
		Params: map[string]connector.ParamDef{
			"resource_name": {Type: "string", Description: "Resource name (e.g. people/c12345)", Required: true},
			"name":          {Type: "string", Description: "Full name; split into given/family on whitespace (ignored if given_name/family_name set)", Required: false},
			"given_name":    {Type: "string", Description: "Given (first) name", Required: false},
			"family_name":   {Type: "string", Description: "Family (last) name", Required: false},
			"email":         {Type: "string", Description: "Contact email address", Required: false},
			"phone":         {Type: "string", Description: "Contact phone number", Required: false},
		},
		ReadOnly: false,
	},
	{
		Name:        "people.delete_contact",
		Description: "Delete a contact",
		Params: map[string]connector.ParamDef{
			"resource_name": {Type: "string", Description: "Resource name (e.g. people/c12345)", Required: true},
		},
		ReadOnly: false,
	},

	// --- Google Sheets ---
	{
		Name:        "sheets.get_spreadsheet",
		Description: "Get metadata about a spreadsheet (sheets, titles)",
		Params: map[string]connector.ParamDef{
			"spreadsheet_id": {Type: "string", Description: "The spreadsheet ID", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "sheets.read_range",
		Description: "Read values from a spreadsheet range",
		Params: map[string]connector.ParamDef{
			"spreadsheet_id": {Type: "string", Description: "The spreadsheet ID", Required: true},
			"range":          {Type: "string", Description: "A1 notation range (e.g. Sheet1!A1:D10)", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "sheets.write_range",
		Description: "Write values to a spreadsheet range",
		Params: map[string]connector.ParamDef{
			"spreadsheet_id": {Type: "string", Description: "The spreadsheet ID", Required: true},
			"range":          {Type: "string", Description: "A1 notation range (e.g. Sheet1!A1:D10)", Required: true},
			"values":         {Type: "string", Description: "JSON array of rows, e.g. [[\"a\",\"b\"],[\"c\",\"d\"]]", Required: true},
		},
		ReadOnly: false,
	},
	{
		Name:        "sheets.create_spreadsheet",
		Description: "Create a new Google Sheets spreadsheet",
		Params: map[string]connector.ParamDef{
			"title": {Type: "string", Description: "Spreadsheet title", Required: true},
		},
		ReadOnly: false,
	},

	// --- Google Docs ---
	{
		Name:        "docs.get_document",
		Description: "Get a Google Doc with its plain text content",
		Params: map[string]connector.ParamDef{
			"document_id": {Type: "string", Description: "The document ID", Required: true},
		},
		ReadOnly: true,
	},
	{
		Name:        "docs.list_documents",
		Description: "List Google Docs from Drive",
		Params: map[string]connector.ParamDef{
			"page_size":  {Type: "int", Description: "Maximum number of results (default 100)", Required: false},
			"page_token": {Type: "string", Description: "Page token for pagination", Required: false},
		},
		ReadOnly: true,
	},
	{
		Name:        "docs.create_document",
		Description: "Create a new Google Doc",
		Params: map[string]connector.ParamDef{
			"title": {Type: "string", Description: "Document title", Required: true},
		},
		ReadOnly: false,
	},
	{
		Name:        "docs.update_document",
		Description: "Update a Google Doc using batch update requests",
		Params: map[string]connector.ParamDef{
			"document_id": {Type: "string", Description: "The document ID", Required: true},
			"requests":    {Type: "string", Description: "JSON array of Docs API request objects", Required: true},
		},
		ReadOnly: false,
	},
}

// Execute routes an operation to the appropriate gmail.Client method.
func (g *GoogleConnector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	// Guard the deprecated reply_to alias before dispatch, so the check applies
	// identically on the REST, MCP and generic-ops surfaces.
	if err := checkLegacyReplyTo(params); err != nil {
		return nil, err
	}
	switch op {
	case "list_emails":
		query := gmailclient.SearchQuery{
			Query:            getStringParam(params, "query"),
			MaxResults:       int64(getIntParam(params, "max_results")),
			PageToken:        getStringParam(params, "page_token"),
			LabelIds:         getStringSliceParam(params, "label_ids"),
			IncludeSpamTrash: getBoolParam(params, "include_spam_trash"),
		}
		return g.client.ListEmails(ctx, query)

	case "read_email":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetEmail(ctx, messageID)

	case "read_email_raw":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetEmailRaw(ctx, messageID)

	case "read_thread":
		threadID, err := requireStringParam(params, "thread_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetThread(ctx, threadID)

	case "create_draft":
		req := gmailclient.DraftRequest{
			To:               getStringSliceParam(params, "to"),
			Cc:               getStringSliceParam(params, "cc"),
			Bcc:              getStringSliceParam(params, "bcc"),
			Subject:          getStringParam(params, "subject"),
			Body:             getStringParam(params, "body"),
			ReplyToAddresses: getStringSliceParam(params, "reply_to_address"),
			ReplyTo:          getStringParam(params, "reply_to"),
		}
		atts, err := getAttachmentsParam(params)
		if err != nil {
			return nil, err
		}
		req.Attachments = atts
		if err := g.applyThreading(ctx, params, &req); err != nil {
			return nil, err
		}
		return g.client.CreateDraft(ctx, req)

	case "update_draft":
		draftID, err := requireStringParam(params, "draft_id")
		if err != nil {
			return nil, err
		}
		req := gmailclient.DraftRequest{
			To:               getStringSliceParam(params, "to"),
			Cc:               getStringSliceParam(params, "cc"),
			Bcc:              getStringSliceParam(params, "bcc"),
			Subject:          getStringParam(params, "subject"),
			Body:             getStringParam(params, "body"),
			ReplyToAddresses: getStringSliceParam(params, "reply_to_address"),
		}
		atts, err := getAttachmentsParam(params)
		if err != nil {
			return nil, err
		}
		req.Attachments = atts
		if err := g.applyThreading(ctx, params, &req); err != nil {
			return nil, err
		}
		return g.client.UpdateDraft(ctx, draftID, req)

	case "send_email":
		req := gmailclient.DraftRequest{
			To:               getStringSliceParam(params, "to"),
			Cc:               getStringSliceParam(params, "cc"),
			Bcc:              getStringSliceParam(params, "bcc"),
			Subject:          getStringParam(params, "subject"),
			Body:             getStringParam(params, "body"),
			ReplyToAddresses: getStringSliceParam(params, "reply_to_address"),
			ReplyTo:          getStringParam(params, "reply_to"),
		}
		atts, err := getAttachmentsParam(params)
		if err != nil {
			return nil, err
		}
		req.Attachments = atts
		if err := g.applyThreading(ctx, params, &req); err != nil {
			return nil, err
		}
		return g.client.SendEmail(ctx, req)

	case "forward_draft", "forward_email":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		req := gmailclient.DraftRequest{
			To:               getStringSliceParam(params, "to"),
			Cc:               getStringSliceParam(params, "cc"),
			Bcc:              getStringSliceParam(params, "bcc"),
			Subject:          getStringParam(params, "subject"),
			Body:             getStringParam(params, "body"),
			ReplyToAddresses: getStringSliceParam(params, "reply_to_address"),
		}
		extra, err := getAttachmentsParam(params)
		if err != nil {
			return nil, err
		}
		if err := g.buildForward(ctx, messageID, &req, extra); err != nil {
			return nil, err
		}
		if op == "forward_draft" {
			return g.client.CreateDraft(ctx, req)
		}
		return g.client.SendEmail(ctx, req)

	case "send_draft":
		draftID, err := requireStringParam(params, "draft_id")
		if err != nil {
			return nil, err
		}
		return g.client.SendDraft(ctx, draftID)

	case "list_drafts":
		return g.client.ListDrafts(ctx, int64(getIntParam(params, "max_results")))

	case "delete_draft":
		draftID, err := requireStringParam(params, "draft_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.DeleteDraft(ctx, draftID)

	case "add_label":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		labelID, err := requireStringParam(params, "label_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.AddLabel(ctx, messageID, labelID)

	case "remove_label":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		labelID, err := requireStringParam(params, "label_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.RemoveLabel(ctx, messageID, labelID)

	case "archive":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.Archive(ctx, messageID)

	case "list_labels":
		return g.client.ListLabels(ctx)

	case "reply":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		req := gmailclient.DraftRequest{
			To:               getStringSliceParam(params, "to"),
			Cc:               getStringSliceParam(params, "cc"),
			Bcc:              getStringSliceParam(params, "bcc"),
			Subject:          getStringParam(params, "subject"),
			Body:             getStringParam(params, "body"),
			ReplyToAddresses: getStringSliceParam(params, "reply_to_address"),
		}
		atts, err := getAttachmentsParam(params)
		if err != nil {
			return nil, err
		}
		req.Attachments = atts
		// Reply threads into message_id's conversation with correct thread_id +
		// In-Reply-To/References headers (derived from the parent), instead of the
		// old behavior that mis-used the message id as both threadId and Message-ID.
		if err := g.applyThreadingFromParent(ctx, messageID, &req); err != nil {
			return nil, err
		}
		return g.client.SendEmail(ctx, req)

	case "get_attachment":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		attachmentID, err := requireStringParam(params, "attachment_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetAttachment(ctx, messageID, attachmentID)

	// --- Google Drive ---
	case "drive.list_files":
		return g.driveClient.ListFiles(ctx,
			getStringParam(params, "query"),
			int64(getIntParam(params, "page_size")),
			getStringParam(params, "page_token"),
		)

	case "drive.get_file":
		fileID, err := requireStringParam(params, "file_id")
		if err != nil {
			return nil, err
		}
		return g.driveClient.GetFile(ctx, fileID)

	case "drive.download_file":
		fileID, err := requireStringParam(params, "file_id")
		if err != nil {
			return nil, err
		}
		return g.driveClient.DownloadFile(ctx, fileID)

	case "drive.upload_file":
		name, err := requireStringParam(params, "name")
		if err != nil {
			return nil, err
		}
		content, err := requireStringParam(params, "content")
		if err != nil {
			return nil, err
		}
		mimeType, err := requireStringParam(params, "mime_type")
		if err != nil {
			return nil, err
		}
		parentFolderID := getStringParam(params, "parent_folder_id")
		return g.driveClient.UploadFile(ctx, name, content, mimeType, parentFolderID)

	case "drive.share_file":
		fileID, err := requireStringParam(params, "file_id")
		if err != nil {
			return nil, err
		}
		shareType := getStringParam(params, "type")
		spec := gmailclient.ShareSpec{
			Email:            getStringParam(params, "email"),
			Role:             getStringParam(params, "role"),
			Type:             shareType,
			Domain:           getStringParam(params, "domain"),
			SendNotification: true, // Drive default; overridable below.
		}
		if hasParam(params, "send_notification") {
			spec.SendNotification = getBoolParam(params, "send_notification")
		}
		// email is required for the user/group grant types (the common case).
		if (shareType == "" || shareType == "user" || shareType == "group") && spec.Email == "" {
			return nil, fmt.Errorf("gmail connector: missing required parameter %q", "email")
		}
		if shareType == "domain" && spec.Domain == "" {
			return nil, fmt.Errorf("gmail connector: share type \"domain\" requires %q", "domain")
		}
		return g.driveClient.ShareFile(ctx, fileID, spec)

	// --- Google Calendar ---
	case "calendar.list_events":
		return g.calendarClient.ListEvents(ctx,
			getStringParam(params, "calendar_id"),
			getStringParam(params, "time_min"),
			getStringParam(params, "time_max"),
			int64(getIntParam(params, "max_results")),
			getStringParam(params, "page_token"),
		)

	case "calendar.get_event":
		eventID, err := requireStringParam(params, "event_id")
		if err != nil {
			return nil, err
		}
		return g.calendarClient.GetEvent(ctx, getStringParam(params, "calendar_id"), eventID)

	case "calendar.create_event":
		summary, err := requireStringParam(params, "summary")
		if err != nil {
			return nil, err
		}
		startTime, err := requireStringParam(params, "start")
		if err != nil {
			return nil, err
		}
		endTime, err := requireStringParam(params, "end")
		if err != nil {
			return nil, err
		}
		return g.calendarClient.CreateEvent(ctx,
			getStringParam(params, "calendar_id"),
			summary,
			getStringParam(params, "location"),
			getStringParam(params, "description"),
			startTime,
			endTime,
			getStringSliceParam(params, "attendees"),
		)

	case "calendar.update_event":
		eventID, err := requireStringParam(params, "event_id")
		if err != nil {
			return nil, err
		}
		// Presence-aware: a field only changes when the caller included it, and
		// an explicit "" clears it (see EventPatch). attendees, when present,
		// replaces the whole list.
		patch := gmailclient.EventPatch{
			Summary:     getStringPtrParam(params, "summary"),
			Location:    getStringPtrParam(params, "location"),
			Description: getStringPtrParam(params, "description"),
			StartTime:   getStringPtrParam(params, "start"),
			EndTime:     getStringPtrParam(params, "end"),
		}
		if hasParam(params, "attendees") {
			a := getStringSliceParam(params, "attendees")
			if a == nil {
				a = []string{}
			}
			patch.Attendees = &a
		}
		return g.calendarClient.UpdateEvent(ctx, getStringParam(params, "calendar_id"), eventID, patch)

	case "calendar.delete_event":
		eventID, err := requireStringParam(params, "event_id")
		if err != nil {
			return nil, err
		}
		return nil, g.calendarClient.DeleteEvent(ctx, getStringParam(params, "calendar_id"), eventID)

	// --- Google People/Contacts ---
	case "people.list_contacts":
		return g.peopleClient.ListContacts(ctx,
			int64(getIntParam(params, "page_size")),
			getStringParam(params, "page_token"),
		)

	case "people.get_contact":
		resourceName, err := requireStringParam(params, "resource_name")
		if err != nil {
			return nil, err
		}
		return g.peopleClient.GetContact(ctx, resourceName)

	case "people.create_contact":
		given, family := contactName(params)
		return g.peopleClient.CreateContact(ctx,
			given, family,
			getStringParam(params, "email"),
			getStringParam(params, "phone"),
		)

	case "people.update_contact":
		resourceName, err := requireStringParam(params, "resource_name")
		if err != nil {
			return nil, err
		}
		given, family := contactName(params)
		return g.peopleClient.UpdateContact(ctx,
			resourceName,
			given, family,
			getStringParam(params, "email"),
			getStringParam(params, "phone"),
		)

	case "people.delete_contact":
		resourceName, err := requireStringParam(params, "resource_name")
		if err != nil {
			return nil, err
		}
		return nil, g.peopleClient.DeleteContact(ctx, resourceName)

	// --- Google Sheets ---
	case "sheets.get_spreadsheet":
		spreadsheetID, err := requireStringParam(params, "spreadsheet_id")
		if err != nil {
			return nil, err
		}
		return g.sheetsClient.GetSpreadsheet(ctx, spreadsheetID)

	case "sheets.read_range":
		spreadsheetID, err := requireStringParam(params, "spreadsheet_id")
		if err != nil {
			return nil, err
		}
		readRange, err := requireStringParam(params, "range")
		if err != nil {
			return nil, err
		}
		return g.sheetsClient.ReadRange(ctx, spreadsheetID, readRange)

	case "sheets.write_range":
		spreadsheetID, err := requireStringParam(params, "spreadsheet_id")
		if err != nil {
			return nil, err
		}
		writeRange, err := requireStringParam(params, "range")
		if err != nil {
			return nil, err
		}
		valuesJSON, err := requireStringParam(params, "values")
		if err != nil {
			return nil, err
		}
		var values [][]interface{}
		if err := json.Unmarshal([]byte(valuesJSON), &values); err != nil {
			return nil, fmt.Errorf("google connector: parsing values JSON: %w", err)
		}
		return g.sheetsClient.WriteRange(ctx, spreadsheetID, writeRange, values)

	case "sheets.create_spreadsheet":
		title, err := requireStringParam(params, "title")
		if err != nil {
			return nil, err
		}
		return g.sheetsClient.CreateSpreadsheet(ctx, title)

	// --- Google Docs ---
	case "docs.get_document":
		documentID, err := requireStringParam(params, "document_id")
		if err != nil {
			return nil, err
		}
		return g.docsClient.GetDocument(ctx, documentID)

	case "docs.list_documents":
		return g.docsClient.ListDocuments(ctx,
			int64(getIntParam(params, "page_size")),
			getStringParam(params, "page_token"),
		)

	case "docs.create_document":
		title, err := requireStringParam(params, "title")
		if err != nil {
			return nil, err
		}
		return g.docsClient.CreateDocument(ctx, title)

	case "docs.update_document":
		documentID, err := requireStringParam(params, "document_id")
		if err != nil {
			return nil, err
		}
		requestsJSON, err := requireStringParam(params, "requests")
		if err != nil {
			return nil, err
		}
		return g.docsClient.UpdateDocument(ctx, documentID, requestsJSON)

	default:
		return nil, fmt.Errorf("google connector: unknown operation %q", op)
	}
}

// applyThreading populates the threading fields of req from params. Explicit
// advanced fields (thread_id / in_reply_to / references) win; otherwise, if
// in_reply_to_message_id is set, the parent message is looked up and its
// thread_id, Message-ID, References and (when subject is empty) a "Re:" subject
// are filled in. Returns an error only when the parent lookup fails.
func (g *GoogleConnector) applyThreading(ctx context.Context, params map[string]any, req *gmailclient.DraftRequest) error {
	req.ThreadID = getStringParam(params, "thread_id")
	req.InReplyTo = getStringParam(params, "in_reply_to")
	req.References = getStringParam(params, "references")

	parentID := getStringParam(params, "in_reply_to_message_id")
	if parentID == "" {
		return nil
	}
	return g.applyThreadingFromParent(ctx, parentID, req)
}

// applyThreadingFromParent looks up parentID and fills any threading field of
// req not already set: thread_id, In-Reply-To (parent Message-ID), References,
// and a "Re:" subject when none was supplied.
func (g *GoogleConnector) applyThreadingFromParent(ctx context.Context, parentID string, req *gmailclient.DraftRequest) error {
	rc, err := g.client.GetReplyContext(ctx, parentID)
	if err != nil {
		return err
	}
	if req.ThreadID == "" {
		req.ThreadID = rc.ThreadID
	}
	if req.InReplyTo == "" {
		req.InReplyTo = rc.MessageID
	}
	if req.References == "" {
		req.References = rc.References
	}
	if req.Subject == "" && rc.Subject != "" {
		req.Subject = ensureRePrefix(rc.Subject)
	}
	return nil
}

// ensureRePrefix prepends "Re: " unless the subject already starts with a
// case-insensitive "Re:" (with or without trailing space), so replies don't
// accumulate "Re: Re: ...".
func ensureRePrefix(subject string) string {
	trimmed := strings.TrimSpace(subject)
	if len(trimmed) >= 3 && strings.EqualFold(trimmed[:3], "re:") {
		return subject
	}
	return "Re: " + subject
}

// ensureFwdPrefix prepends "Fwd: " unless the subject already carries a
// case-insensitive "Fwd:" or "Fw:" prefix, so forwards don't accumulate one.
func ensureFwdPrefix(subject string) string {
	low := strings.ToLower(strings.TrimSpace(subject))
	if strings.HasPrefix(low, "fwd:") || strings.HasPrefix(low, "fw:") {
		return subject
	}
	return "Fwd: " + subject
}

// checkLegacyReplyTo rejects a `reply_to` that is plainly an email address.
//
// `reply_to` is the DEPRECATED threading alias: a Gmail message id. Feeding it
// an address does not set a Reply-To header — it is written into In-Reply-To /
// References AND used as the Gmail threadId, so the draft silently carries a
// fabricated threading header while the header the caller wanted is absent.
// A 200 in that situation makes an agent report a Reply-To that isn't there,
// so fail loudly and name both of the fields the caller might have meant.
//
// A value in angle brackets is left alone: that is a legacy RFC 5322
// Message-ID, which legitimately contains "@".
func checkLegacyReplyTo(params map[string]any) error {
	v := strings.TrimSpace(getStringParam(params, "reply_to"))
	if v == "" || !strings.Contains(v, "@") || strings.HasPrefix(v, "<") {
		return nil
	}
	return fmt.Errorf("gmail connector: %q is the deprecated threading alias (a Gmail message id), "+
		"not a Reply-To header, and %q looks like an email address. "+
		"To set the Reply-To header use %q; to reply into a thread use %q",
		"reply_to", v, "reply_to_address", "in_reply_to_message_id")
}

// getAttachmentsParam parses the "attachments" op param — an array of
// {filename, mime_type, content} objects, where content is base64-encoded
// bytes — into decoded gmail.Attachment values. Returns (nil, nil) when the
// param is absent. Errors (rather than silently dropping) on a malformed shape
// or undecodable content, so a caller learns its attachment didn't ride along.
func getAttachmentsParam(params map[string]any) ([]gmailclient.Attachment, error) {
	raw, ok := params["attachments"]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("gmail connector: %q must be an array of {filename, mime_type, content} objects", "attachments")
	}
	out := make([]gmailclient.Attachment, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("gmail connector: attachments[%d] must be an object with filename, mime_type, content", i)
		}
		filename, _ := m["filename"].(string)
		mimeType, _ := m["mime_type"].(string)
		contentStr, _ := m["content"].(string)
		if filename == "" {
			return nil, fmt.Errorf("gmail connector: attachments[%d] missing required %q", i, "filename")
		}
		if contentStr == "" {
			return nil, fmt.Errorf("gmail connector: attachments[%d] missing required %q (base64 bytes)", i, "content")
		}
		data, err := decodeBase64(contentStr)
		if err != nil {
			return nil, fmt.Errorf("gmail connector: attachments[%d] content is not valid base64: %w", i, err)
		}
		out = append(out, gmailclient.Attachment{Filename: filename, MimeType: mimeType, Data: data})
	}
	return out, nil
}

// decodeBase64 decodes s tolerantly across the four base64 alphabets/paddings
// callers commonly emit (std/url, padded/raw), since JSON has no canonical
// base64 and clients differ.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}

// buildForward populates req to forward the message sourceID. It looks up the
// source, derives a "Fwd:" subject when the caller gave none, and appends the
// standard forwarded block (the real From/Date/Subject/To plus the original
// body) beneath the caller's note in BOTH plain text and — when the source had
// an HTML part — HTML, so the original's links and formatting survive. The
// source's own attachments are fetched in full and carried, followed by any
// caller-supplied extras. Everything is server-assembled from a message the
// token was already permitted to read, so it stays fully policy-inspectable —
// this is not the opaque-raw-MIME path.
func (g *GoogleConnector) buildForward(ctx context.Context, sourceID string, req *gmailclient.DraftRequest, extra []gmailclient.Attachment) error {
	src, err := g.client.GetEmail(ctx, sourceID)
	if err != nil {
		return err
	}
	if req.Subject == "" {
		req.Subject = ensureFwdPrefix(src.Subject)
	}
	note := req.Body
	req.Body = forwardTextBody(note, src)
	if src.BodyHTML != "" {
		req.BodyHTML = forwardHTMLBody(note, src)
	}
	atts := make([]gmailclient.Attachment, 0, len(src.Attachments)+len(extra))
	for _, meta := range src.Attachments {
		full, err := g.client.GetAttachment(ctx, sourceID, meta.ID)
		if err != nil {
			return fmt.Errorf("gmail connector: fetching attachment %q to forward: %w", meta.Filename, err)
		}
		atts = append(atts, *full)
	}
	atts = append(atts, extra...)
	req.Attachments = atts
	return nil
}

// forwardTextBody renders the plain-text body of a forward: the caller's note
// (if any), the "---------- Forwarded message ----------" separator with the
// source's genuine headers, then the source's plain-text body.
func forwardTextBody(note string, src *gmailclient.Email) string {
	var b strings.Builder
	if note != "" {
		b.WriteString(note)
		b.WriteString("\n\n")
	}
	b.WriteString("---------- Forwarded message ----------\n")
	b.WriteString("From: " + src.From + "\n")
	if !src.Date.IsZero() {
		b.WriteString("Date: " + src.Date.Format(time.RFC1123Z) + "\n")
	}
	b.WriteString("Subject: " + src.Subject + "\n")
	if len(src.To) > 0 {
		b.WriteString("To: " + strings.Join(src.To, ", ") + "\n")
	}
	if len(src.Cc) > 0 {
		b.WriteString("Cc: " + strings.Join(src.Cc, ", ") + "\n")
	}
	b.WriteString("\n")
	b.WriteString(src.Body)
	return b.String()
}

// forwardHTMLBody renders the HTML body of a forward. The caller's note and the
// forwarded header lines are HTML-escaped (they are attacker-influenced text);
// the source's HTML body is included verbatim so its links/markup — the whole
// point of preserving HTML — survive intact.
func forwardHTMLBody(note string, src *gmailclient.Email) string {
	var b strings.Builder
	if note != "" {
		b.WriteString("<div>")
		b.WriteString(strings.ReplaceAll(html.EscapeString(note), "\n", "<br>\n"))
		b.WriteString("</div><br>\n")
	}
	b.WriteString(`<div class="gmail_quote">`)
	b.WriteString("---------- Forwarded message ----------<br>\n")
	b.WriteString("From: " + html.EscapeString(src.From) + "<br>\n")
	if !src.Date.IsZero() {
		b.WriteString("Date: " + html.EscapeString(src.Date.Format(time.RFC1123Z)) + "<br>\n")
	}
	b.WriteString("Subject: " + html.EscapeString(src.Subject) + "<br>\n")
	if len(src.To) > 0 {
		b.WriteString("To: " + html.EscapeString(strings.Join(src.To, ", ")) + "<br>\n")
	}
	if len(src.Cc) > 0 {
		b.WriteString("Cc: " + html.EscapeString(strings.Join(src.Cc, ", ")) + "<br>\n")
	}
	b.WriteString("</div>\n")
	b.WriteString(src.BodyHTML)
	return b.String()
}

// Validate checks that the credentials are valid by listing 1 email.
func (g *GoogleConnector) Validate(ctx context.Context) error {
	_, err := g.client.ListEmails(ctx, gmailclient.SearchQuery{MaxResults: 1})
	if err != nil {
		return fmt.Errorf("gmail connector: validation failed: %w", err)
	}
	return nil
}

// --- param helper functions ---

func getStringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	v, _ := params[key].(string)
	return v
}

func requireStringParam(params map[string]any, key string) (string, error) {
	v := getStringParam(params, key)
	if v == "" {
		return "", fmt.Errorf("gmail connector: missing required parameter %q", key)
	}
	return v, nil
}

// contactName resolves a contact's given/family name from params. Explicit
// given_name/family_name win; otherwise a single `name` is split on the last
// run of whitespace (first token → given, remainder → family) so "Jane Doe"
// stores as given "Jane", family "Doe" instead of the whole string in given.
func contactName(params map[string]any) (given, family string) {
	given = getStringParam(params, "given_name")
	family = getStringParam(params, "family_name")
	if given != "" || family != "" {
		return given, family
	}
	fields := strings.Fields(getStringParam(params, "name"))
	switch len(fields) {
	case 0:
		return "", ""
	case 1:
		return fields[0], ""
	default:
		return fields[0], strings.Join(fields[1:], " ")
	}
}

// hasParam reports whether key is present in params at all (even if empty/null),
// used to distinguish "field omitted" from "field set to empty" on PATCH-style
// updates.
func hasParam(params map[string]any, key string) bool {
	_, ok := params[key]
	return ok
}

// getStringPtrParam returns a pointer to the string value when key is present
// (empty string included), or nil when the key is absent. Lets a caller send an
// explicit "" to clear a field vs omit it to leave it unchanged.
func getStringPtrParam(params map[string]any, key string) *string {
	if v, ok := params[key]; ok {
		s, _ := v.(string)
		return &s
	}
	return nil
}

func getIntParam(params map[string]any, key string) int {
	if params == nil {
		return 0
	}
	switch v := params[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func getStringSliceParam(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	// Direct []string assertion
	if v, ok := params[key].([]string); ok {
		return v
	}
	// Handle []any (common when decoded from JSON)
	if v, ok := params[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// getBoolParam reads a boolean param, accepting a JSON bool or the string
// "true"/"1" (query params and form values arrive as strings).
func getBoolParam(params map[string]any, key string) bool {
	switch v := params[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	default:
		return false
	}
}
