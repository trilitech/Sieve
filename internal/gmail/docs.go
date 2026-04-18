package gmail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/api/docs/v1"
	"google.golang.org/api/drive/v3"
)

// DocsClient wraps the Google Docs API.
type DocsClient struct {
	service      *docs.Service
	driveService *drive.Service
}

// NewDocsClient creates a DocsClient from existing Docs and Drive API services.
// The Drive service is needed for listing documents (Docs API has no list endpoint).
func NewDocsClient(service *docs.Service, driveService *drive.Service) *DocsClient {
	return &DocsClient{service: service, driveService: driveService}
}

// DocInfo represents a Google Doc.
type DocInfo struct {
	DocumentID string `json:"document_id"`
	Title      string `json:"title"`
	Body       string `json:"body,omitempty"`
}

// DocListResult contains the results of a document listing.
type DocListResult struct {
	Documents     []DocListItem `json:"documents"`
	NextPageToken string        `json:"next_page_token,omitempty"`
}

// DocListItem is a lightweight representation for document listings.
type DocListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CreatedTime string `json:"created_time,omitempty"`
}

// GetDocument returns a document with its plain text body content.
func (c *DocsClient) GetDocument(ctx context.Context, documentID string) (*DocInfo, error) {
	doc, err := c.service.Documents.Get(documentID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("docs: getting document %s: %w", documentID, err)
	}

	body := extractPlainText(doc.Body)

	return &DocInfo{
		DocumentID: doc.DocumentId,
		Title:      doc.Title,
		Body:       body,
	}, nil
}

// ListDocuments lists Google Docs using the Drive API with a mimeType filter.
func (c *DocsClient) ListDocuments(ctx context.Context, pageSize int64, pageToken string) (*DocListResult, error) {
	if pageSize == 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	call := c.driveService.Files.List().Context(ctx).
		Q("mimeType='application/vnd.google-apps.document'").
		PageSize(pageSize).
		Fields("nextPageToken, files(id, name, createdTime)")

	if pageToken != "" {
		call = call.PageToken(pageToken)
	}

	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("docs: listing documents: %w", err)
	}

	result := &DocListResult{
		NextPageToken: resp.NextPageToken,
	}
	for _, f := range resp.Files {
		result.Documents = append(result.Documents, DocListItem{
			ID:          f.Id,
			Name:        f.Name,
			CreatedTime: f.CreatedTime,
		})
	}
	return result, nil
}

// CreateDocument creates a new Google Doc.
func (c *DocsClient) CreateDocument(ctx context.Context, title string) (*DocInfo, error) {
	doc := &docs.Document{
		Title: title,
	}

	created, err := c.service.Documents.Create(doc).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("docs: creating document: %w", err)
	}

	return &DocInfo{
		DocumentID: created.DocumentId,
		Title:      created.Title,
	}, nil
}

// UpdateDocument performs a batch update on a document.
// The requestsJSON should be a JSON array of Docs API request objects.
func (c *DocsClient) UpdateDocument(ctx context.Context, documentID string, requestsJSON string) (map[string]any, error) {
	var requests []*docs.Request
	if err := json.Unmarshal([]byte(requestsJSON), &requests); err != nil {
		return nil, fmt.Errorf("docs: parsing update requests: %w", err)
	}

	batchReq := &docs.BatchUpdateDocumentRequest{
		Requests: requests,
	}

	resp, err := c.service.Documents.BatchUpdate(documentID, batchReq).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("docs: updating document %s: %w", documentID, err)
	}

	return map[string]any{
		"document_id": resp.DocumentId,
		"replies":     len(resp.Replies),
	}, nil
}

// extractPlainText walks a Docs document body and concatenates all text runs.
func extractPlainText(body *docs.Body) string {
	if body == nil {
		return ""
	}

	var sb strings.Builder
	for _, elem := range body.Content {
		if elem.Paragraph != nil {
			for _, pe := range elem.Paragraph.Elements {
				if pe.TextRun != nil {
					sb.WriteString(pe.TextRun.Content)
				}
			}
		}
		if elem.Table != nil {
			for _, row := range elem.Table.TableRows {
				for _, cell := range row.TableCells {
					for _, ce := range cell.Content {
						if ce.Paragraph != nil {
							for _, pe := range ce.Paragraph.Elements {
								if pe.TextRun != nil {
									sb.WriteString(pe.TextRun.Content)
								}
							}
						}
					}
					sb.WriteString("\t")
				}
				sb.WriteString("\n")
			}
		}
	}
	return sb.String()
}
