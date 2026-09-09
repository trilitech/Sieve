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
