// Package mockconnector fixtures provide realistic API response data modeled
// after real vendor APIs (Gmail, AWS, etc.) for use in end-to-end policy tests.
package mockconnector

// GmailListEmails returns a realistic Gmail list_emails response matching the
// SearchResult/EmailStub format from internal/gmail/client.go. Stubs only —
// no body, no attachments, no body_html. Mirrors what real Gmail-MCP servers
// return from search/list operations. Tests that need to filter on body
// content should use GmailReadEmail and the read_email operation instead.
func GmailListEmails() map[string]any {
	return map[string]any{
		"emails": []any{
			map[string]any{
				"id":        "msg-001",
				"thread_id": "thread-001",
				"from":      "alice@company.com",
				"to":        []string{"me@company.com"},
				"subject":   "Q3 Revenue Report",
				"labels":    []string{"INBOX", "project-x"},
				"snippet":   "Revenue for Q3 was $4.2M...",
				"date":      "2026-03-15T10:30:00Z",
			},
			map[string]any{
				"id":        "msg-002",
				"thread_id": "thread-002",
				"from":      "bob@external.com",
				"to":        []string{"me@company.com"},
				"subject":   "CONFIDENTIAL: Merger Details",
				"labels":    []string{"INBOX"},
				"snippet":   "CONFIDENTIAL: The merger with Acme...",
				"date":      "2026-03-14T09:00:00Z",
			},
			map[string]any{
				"id":        "msg-003",
				"thread_id": "thread-003",
				"from":      "newsletter@spam.com",
				"to":        []string{"me@company.com"},
				"subject":   "You won a prize!",
				"labels":    []string{"SPAM"},
				"snippet":   "Click here to claim...",
				"date":      "2026-03-13T15:00:00Z",
			},
			map[string]any{
				"id":        "msg-004",
				"thread_id": "thread-004",
				"from":      "cfo@company.com",
				"to":        []string{"me@company.com"},
				"subject":   "Salary Adjustments - PRIVATE",
				"labels":    []string{"INBOX", "finance"},
				"snippet":   "Employee salaries...",
				"date":      "2026-03-12T11:00:00Z",
			},
			map[string]any{
				"id":        "msg-005",
				"thread_id": "thread-005",
				"from":      "devops@company.com",
				"to":        []string{"me@company.com"},
				"subject":   "Deployment complete",
				"labels":    []string{"INBOX", "project-x"},
				"snippet":   "Deployed v2.1.0 to production...",
				"date":      "2026-03-11T16:00:00Z",
			},
		},
		"total":           float64(5),
		"next_page_token": "token123",
	}
}

// GmailReadEmail returns a realistic single email response matching the
// Email struct from internal/gmail/client.go.
func GmailReadEmail(messageID string) map[string]any {
	return map[string]any{
		"id":             messageID,
		"thread_id":      "thread-001",
		"from":           "alice@company.com",
		"to":             []string{"me@company.com"},
		"subject":        "Q3 Revenue Report",
		"body":           "Revenue for Q3 was $4.2M.\n\nEmployee SSN: 123-45-6789\nCredit card: 4532-1234-5678-9012\n\nRegards,\nAlice",
		"body_html":      "<p>Revenue for Q3 was $4.2M.</p>",
		"labels":         []string{"INBOX", "project-x"},
		"snippet":        "Revenue for Q3 was $4.2M...",
		"date":           "2026-03-15T10:30:00Z",
		"has_attachment":  false,
	}
}

// LLMChatCompletion returns a realistic LLM chat completion response modeled
// after the OpenAI/Anthropic response format as it would appear proxied
// through Sieve's HTTP proxy.
func LLMChatCompletion() map[string]any {
	return map[string]any{
		"id":      "chatcmpl-abc123",
		"object":  "chat.completion",
		"created": float64(1710000000),
		"model":   "claude-sonnet-4-20250514",
		"choices": []any{
			map[string]any{
				"index": float64(0),
				"message": map[string]any{
					"role":    "assistant",
					"content": "The capital of France is Paris. Here is some sensitive data: SSN 555-12-3456.",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     float64(10),
			"completion_tokens": float64(25),
			"total_tokens":      float64(35),
		},
	}
}

// AWSEC2DescribeInstances returns a realistic AWS EC2 DescribeInstances
// response. Note: AWS APIs use PascalCase field names.
func AWSEC2DescribeInstances() map[string]any {
	return map[string]any{
		"Reservations": []any{
			map[string]any{
				"ReservationId": "r-0123456789abcdef0",
				"Instances": []any{
					map[string]any{
						"InstanceId":   "i-0123456789abcdef0",
						"InstanceType": "t3.micro",
						"State": map[string]any{
							"Name": "running",
							"Code": float64(16),
						},
						"PrivateIpAddress": "10.0.1.100",
						"PublicIpAddress":  "54.123.45.67",
						"Tags": []any{
							map[string]any{"Key": "Name", "Value": "web-server-1"},
							map[string]any{"Key": "env", "Value": "production"},
						},
						"LaunchTime": "2026-03-10T08:00:00Z",
					},
					map[string]any{
						"InstanceId":   "i-0abcdef1234567890",
						"InstanceType": "c5.xlarge",
						"State": map[string]any{
							"Name": "running",
							"Code": float64(16),
						},
						"PrivateIpAddress": "10.0.1.101",
						"Tags": []any{
							map[string]any{"Key": "Name", "Value": "gpu-worker"},
							map[string]any{"Key": "env", "Value": "staging"},
						},
						"LaunchTime": "2026-03-11T12:00:00Z",
					},
				},
			},
		},
	}
}

// AWSS3ListObjects returns a realistic AWS S3 ListObjectsV2 response.
func AWSS3ListObjects() map[string]any {
	return map[string]any{
		"items": []any{
			map[string]any{
				"Key":          "public/report-2026-q1.pdf",
				"Size":         float64(1048576),
				"LastModified": "2026-03-15T10:00:00Z",
				"StorageClass": "STANDARD",
			},
			map[string]any{
				"Key":          "private/credentials.json",
				"Size":         float64(2048),
				"LastModified": "2026-03-14T08:00:00Z",
				"StorageClass": "STANDARD",
			},
			map[string]any{
				"Key":          "public/readme.txt",
				"Size":         float64(512),
				"LastModified": "2026-03-13T16:00:00Z",
				"StorageClass": "STANDARD",
			},
		},
		"total": float64(3),
	}
}
