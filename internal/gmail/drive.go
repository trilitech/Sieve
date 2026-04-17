package gmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"google.golang.org/api/drive/v3"
)

// DriveClient wraps the Google Drive API.
type DriveClient struct {
	service *drive.Service
}

// NewDriveClient creates a DriveClient from an existing Drive API service.
func NewDriveClient(service *drive.Service) *DriveClient {
	return &DriveClient{service: service}
}

// DriveFile represents a file in Google Drive.
type DriveFile struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	MimeType     string   `json:"mime_type"`
	Size         int64    `json:"size"`
	CreatedTime  string   `json:"created_time,omitempty"`
	ModifiedTime string   `json:"modified_time,omitempty"`
	Owners       []string `json:"owners,omitempty"`
}

// DriveListResult contains the results of a Drive file listing.
type DriveListResult struct {
	Files         []DriveFile `json:"files"`
	NextPageToken string      `json:"next_page_token,omitempty"`
}

// DriveDownloadResult contains the content of a downloaded file.
type DriveDownloadResult struct {
	Content  string `json:"content"`
	Filename string `json:"filename"`
	MimeType string `json:"mime_type"`
	Size     int64  `json:"size"`
}

// ListFiles lists files in Google Drive.
func (c *DriveClient) ListFiles(ctx context.Context, query string, pageSize int64, pageToken string) (*DriveListResult, error) {
	if pageSize == 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	call := c.service.Files.List().Context(ctx).
		PageSize(pageSize).
		Fields("nextPageToken, files(id, name, mimeType, size, createdTime, modifiedTime, owners)")

	if query != "" {
		call = call.Q(query)
	}
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}

	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("drive: listing files: %w", err)
	}

	result := &DriveListResult{
		NextPageToken: resp.NextPageToken,
	}
	for _, f := range resp.Files {
		df := DriveFile{
			ID:           f.Id,
			Name:         f.Name,
			MimeType:     f.MimeType,
			Size:         f.Size,
			CreatedTime:  f.CreatedTime,
			ModifiedTime: f.ModifiedTime,
		}
		for _, o := range f.Owners {
			df.Owners = append(df.Owners, o.EmailAddress)
		}
		result.Files = append(result.Files, df)
	}
	return result, nil
}

// GetFile returns metadata for a single file.
func (c *DriveClient) GetFile(ctx context.Context, fileID string) (*DriveFile, error) {
	f, err := c.service.Files.Get(fileID).Context(ctx).
		Fields("id, name, mimeType, size, createdTime, modifiedTime, owners").Do()
	if err != nil {
		return nil, fmt.Errorf("drive: getting file %s: %w", fileID, err)
	}

	df := &DriveFile{
		ID:           f.Id,
		Name:         f.Name,
		MimeType:     f.MimeType,
		Size:         f.Size,
		CreatedTime:  f.CreatedTime,
		ModifiedTime: f.ModifiedTime,
	}
	for _, o := range f.Owners {
		df.Owners = append(df.Owners, o.EmailAddress)
	}
	return df, nil
}

// DownloadFile downloads a file's content and returns it as base64.
func (c *DriveClient) DownloadFile(ctx context.Context, fileID string) (*DriveDownloadResult, error) {
	// First get metadata for filename and mime type.
	meta, err := c.service.Files.Get(fileID).Context(ctx).
		Fields("id, name, mimeType, size").Do()
	if err != nil {
		return nil, fmt.Errorf("drive: getting file metadata %s: %w", fileID, err)
	}

	resp, err := c.service.Files.Get(fileID).Context(ctx).Download()
	if err != nil {
		return nil, fmt.Errorf("drive: downloading file %s: %w", fileID, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("drive: reading file content %s: %w", fileID, err)
	}

	return &DriveDownloadResult{
		Content:  base64.StdEncoding.EncodeToString(data),
		Filename: meta.Name,
		MimeType: meta.MimeType,
		Size:     int64(len(data)),
	}, nil
}

// UploadFile uploads a file to Google Drive.
func (c *DriveClient) UploadFile(ctx context.Context, name string, content string, mimeType string, parentFolderID string) (*DriveFile, error) {
	data, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, fmt.Errorf("drive: decoding base64 content: %w", err)
	}

	fileMetadata := &drive.File{
		Name:     name,
		MimeType: mimeType,
	}
	if parentFolderID != "" {
		fileMetadata.Parents = []string{parentFolderID}
	}

	f, err := c.service.Files.Create(fileMetadata).
		Context(ctx).
		Media(bytes.NewReader(data)).
		Fields("id, name, mimeType, size, createdTime, modifiedTime").
		Do()
	if err != nil {
		return nil, fmt.Errorf("drive: uploading file: %w", err)
	}

	return &DriveFile{
		ID:           f.Id,
		Name:         f.Name,
		MimeType:     f.MimeType,
		Size:         f.Size,
		CreatedTime:  f.CreatedTime,
		ModifiedTime: f.ModifiedTime,
	}, nil
}

// ShareFile shares a file with a user by email.
func (c *DriveClient) ShareFile(ctx context.Context, fileID string, email string, role string) (map[string]any, error) {
	if role == "" {
		role = "reader"
	}

	perm := &drive.Permission{
		Type:         "user",
		Role:         role,
		EmailAddress: email,
	}

	created, err := c.service.Permissions.Create(fileID, perm).
		Context(ctx).
		SendNotificationEmail(true).
		Do()
	if err != nil {
		return nil, fmt.Errorf("drive: sharing file %s: %w", fileID, err)
	}

	return map[string]any{
		"permission_id": created.Id,
		"role":          created.Role,
		"type":          created.Type,
		"email":         email,
	}, nil
}
