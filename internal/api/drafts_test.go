package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// newDraftBodyReq builds a POST with the given JSON body for parseMailBody.
func parseBody(t *testing.T, jsonBody string) (map[string]any, int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/gmail/v1/users/me/drafts", strings.NewReader(jsonBody))
	rec := httptest.NewRecorder()
	rt := &Router{}
	params, ok := rt.parseMailBody(rec, req)
	if !ok {
		return nil, rec.Code, rec.Body.String()
	}
	return params, 200, ""
}

func TestParseDraftBody_RejectsUnknownField(t *testing.T) {
	// The reported footgun: a mistyped/unsupported threading field must 400,
	// not be silently dropped so the caller thinks it threaded a reply.
	_, code, body := parseBody(t, `{"to":["x@y.com"],"subject":"s","body":"b","in_reply_to_message":"m1"}`)
	if code != 400 {
		t.Fatalf("code = %d, want 400 for unknown field", code)
	}
	if !strings.Contains(body, "in_reply_to_message") {
		t.Errorf("error should name the offending field; got %q", body)
	}
}

func TestParseDraftBody_RejectsRaw(t *testing.T) {
	_, code, body := parseBody(t, `{"raw":"AAAA","thread_id":"t1"}`)
	if code != 400 {
		t.Fatalf("code = %d, want 400 for raw", code)
	}
	if !strings.Contains(body, "raw") || !strings.Contains(body, "in_reply_to_message_id") {
		t.Errorf("error should explain raw is unsupported and point at structured fields; got %q", body)
	}
}

func TestParseDraftBody_NormalizesCamelCase(t *testing.T) {
	params, code, _ := parseBody(t, `{"to":["x@y.com"],"threadId":"t1","inReplyToMessageId":"m1"}`)
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	if params["thread_id"] != "t1" {
		t.Errorf("threadId not normalized to thread_id: %v", params)
	}
	if params["in_reply_to_message_id"] != "m1" {
		t.Errorf("inReplyToMessageId not normalized: %v", params)
	}
	if _, present := params["threadId"]; present {
		t.Errorf("camelCase key should not survive into op params: %v", params)
	}
}

// modifyReq drives gmailModifyMessage directly (bare Router), exercising the
// fail-loud branches that run before any auth/policy stack.
func modifyReq(t *testing.T, jsonBody string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/gmail/v1/users/me/messages/m1/modify", strings.NewReader(jsonBody))
	rec := httptest.NewRecorder()
	(&Router{}).gmailModifyMessage(rec, req)
	return rec.Code, rec.Body.String()
}

func TestModify_RejectsMultipleLabelOps(t *testing.T) {
	// Two label changes in one call would silently apply only the first under
	// the old code; now it fails loud rather than doing a partial write.
	code, body := modifyReq(t, `{"addLabelIds":["A","B"]}`)
	if code != 400 {
		t.Fatalf("code = %d, want 400 for a multi-label modify", code)
	}
	if !strings.Contains(body, "one label change per call") {
		t.Errorf("error should explain the one-op limit; got %q", body)
	}
	code, _ = modifyReq(t, `{"addLabelIds":["A"],"removeLabelIds":["INBOX"]}`)
	if code != 400 {
		t.Errorf("add+remove in one call should 400, got %d", code)
	}
}

func TestModify_RejectsEmpty(t *testing.T) {
	code, body := modifyReq(t, `{}`)
	if code != 400 || !strings.Contains(body, "addLabelIds or removeLabelIds") {
		t.Errorf("empty modify: code=%d body=%q", code, body)
	}
}

func TestParseDraftBody_AcceptsKnownFields(t *testing.T) {
	params, code, _ := parseBody(t, `{"to":["x@y.com"],"cc":["c@y.com"],"bcc":["b@y.com"],"subject":"s","body":"b","in_reply_to_message_id":"m1","references":"<r@x>"}`)
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	for _, k := range []string{"to", "cc", "bcc", "subject", "body", "in_reply_to_message_id", "references"} {
		if _, ok := params[k]; !ok {
			t.Errorf("param %q missing after parse: %v", k, params)
		}
	}
}

func TestParseDraftBody_AcceptsAttachments(t *testing.T) {
	// The mirabello P1: attachments must be an accepted structured field, not a
	// rejected unknown one.
	params, code, body := parseBody(t, `{"to":["x@y.com"],"attachments":[{"filename":"a.pdf","mime_type":"application/pdf","content":"AAAA"}]}`)
	if code != 200 {
		t.Fatalf("code = %d (%s), want 200 — attachments should be accepted", code, body)
	}
	if _, ok := params["attachments"]; !ok {
		t.Errorf("attachments missing after parse: %v", params)
	}
}

func TestParseDraftBody_NormalizesForwardMessageId(t *testing.T) {
	// forward_message_id (and its camelCase alias) normalize to the op's
	// message_id param, which is how the handlers detect a forward.
	for _, in := range []string{
		`{"to":["x@y.com"],"forward_message_id":"src1"}`,
		`{"to":["x@y.com"],"forwardMessageId":"src1"}`,
	} {
		params, code, body := parseBody(t, in)
		if code != 200 {
			t.Fatalf("code = %d (%s), want 200 for %s", code, body, in)
		}
		if params["message_id"] != "src1" {
			t.Errorf("forward id not normalized to message_id for %s: %v", in, params)
		}
	}
}

// TestMailOpFor verifies drafts/send dispatch selects the dedicated forward op
// exactly when a forward id (already normalized to message_id) is present.
func TestMailOpFor(t *testing.T) {
	if got := mailOpFor(map[string]any{"message_id": "src1"}, "create_draft", "forward_draft"); got != "forward_draft" {
		t.Errorf("with forward id: got %q, want forward_draft", got)
	}
	if got := mailOpFor(map[string]any{"body": "b"}, "create_draft", "forward_draft"); got != "create_draft" {
		t.Errorf("without forward id: got %q, want create_draft", got)
	}
	if got := mailOpFor(map[string]any{"message_id": "src1"}, "send_email", "forward_email"); got != "forward_email" {
		t.Errorf("send with forward id: got %q, want forward_email", got)
	}
	if got := mailOpFor(map[string]any{"body": "b"}, "send_email", "forward_email"); got != "send_email" {
		t.Errorf("send without forward id: got %q, want send_email", got)
	}
}

// TestParseDraftBody_AcceptsReplyToAddress: the Reply-To header field must be
// an accepted structured field, not a rejected unknown one.
func TestParseDraftBody_AcceptsReplyToAddress(t *testing.T) {
	for _, in := range []string{
		`{"to":["x@y.com"],"reply_to_address":["replies@y.com"]}`,
		`{"to":["x@y.com"],"replyToAddress":["replies@y.com"]}`,
	} {
		params, code, body := parseBody(t, in)
		if code != 200 {
			t.Fatalf("code = %d (%s) for %s", code, body, in)
		}
		if _, ok := params["reply_to_address"]; !ok {
			t.Errorf("reply_to_address missing after parse of %s: %v", in, params)
		}
	}
}

// TestDraftUpdateRoute_Exists is the reported gap: PUT (and PATCH)
// /gmail/v1/users/{u}/drafts/{id} returned 405, so update_draft was reachable
// only via the generic ops surface. Asserted against the real mux so a
// registration regression is caught.
func TestDraftUpdateRoute_Exists(t *testing.T) {
	// Assert against the bare mux: authMiddleware runs before routing, so a
	// request through Handler() 401s whether or not the route exists.
	mux := (&Router{}).mux()
	for _, method := range []string{"PUT", "PATCH", "DELETE"} {
		req := httptest.NewRequest(method, "/gmail/v1/users/me/drafts/d1", strings.NewReader(`{}`))
		if _, pattern := mux.Handler(req); !strings.Contains(pattern, "/drafts/{id}") {
			t.Errorf("%s /gmail/v1/users/{userId}/drafts/{id} is not registered (resolved %q)", method, pattern)
		}
	}
	// Control: a method with genuinely no route resolves to the 405 fallback,
	// proving the assertion above can actually fail.
	req := httptest.NewRequest("TRACE", "/gmail/v1/users/me/drafts/d1", nil)
	if _, pattern := mux.Handler(req); strings.Contains(pattern, "/drafts/{id}") {
		t.Errorf("control: TRACE resolved to %q — the check above proves nothing", pattern)
	}
}

// TestGmailUpdateDraft_RejectsForward: parseMailBody maps forward_message_id
// to message_id, which update_draft has no parameter for — it would be
// silently dropped, editing the draft without the forward.
func TestGmailUpdateDraft_RejectsForward(t *testing.T) {
	req := httptest.NewRequest("PUT", "/gmail/v1/users/me/drafts/d1",
		strings.NewReader(`{"to":["x@y.com"],"forward_message_id":"src1"}`))
	rec := httptest.NewRecorder()
	(&Router{}).gmailUpdateDraft(rec, req)
	if rec.Code != 400 {
		t.Fatalf("code = %d, want 400 for forward_message_id on draft update", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "forward_message_id") {
		t.Errorf("error should name the offending field; got %q", rec.Body.String())
	}
}
