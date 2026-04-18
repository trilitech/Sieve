package gmail

import (
	"context"
	"fmt"

	"google.golang.org/api/sheets/v4"
)

// SheetsClient wraps the Google Sheets API.
type SheetsClient struct {
	service *sheets.Service
}

// NewSheetsClient creates a SheetsClient from an existing Sheets API service.
func NewSheetsClient(service *sheets.Service) *SheetsClient {
	return &SheetsClient{service: service}
}

// SpreadsheetInfo represents basic spreadsheet metadata.
type SpreadsheetInfo struct {
	ID     string      `json:"id"`
	Title  string      `json:"title"`
	Sheets []SheetInfo `json:"sheets"`
}

// SheetInfo represents a single sheet tab within a spreadsheet.
type SheetInfo struct {
	Title string `json:"title"`
	Index int64  `json:"index"`
}

// RangeResult contains the values read from a spreadsheet range.
type RangeResult struct {
	Range  string          `json:"range"`
	Values [][]interface{} `json:"values"`
}

// GetSpreadsheet returns metadata about a spreadsheet.
func (c *SheetsClient) GetSpreadsheet(ctx context.Context, spreadsheetID string) (*SpreadsheetInfo, error) {
	ss, err := c.service.Spreadsheets.Get(spreadsheetID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("sheets: getting spreadsheet %s: %w", spreadsheetID, err)
	}

	info := &SpreadsheetInfo{
		ID:    ss.SpreadsheetId,
		Title: ss.Properties.Title,
	}
	for _, s := range ss.Sheets {
		info.Sheets = append(info.Sheets, SheetInfo{
			Title: s.Properties.Title,
			Index: s.Properties.Index,
		})
	}
	return info, nil
}

// ReadRange reads values from a spreadsheet range.
func (c *SheetsClient) ReadRange(ctx context.Context, spreadsheetID, readRange string) (*RangeResult, error) {
	resp, err := c.service.Spreadsheets.Values.Get(spreadsheetID, readRange).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("sheets: reading range %s from %s: %w", readRange, spreadsheetID, err)
	}

	return &RangeResult{
		Range:  resp.Range,
		Values: resp.Values,
	}, nil
}

// WriteRange writes values to a spreadsheet range.
func (c *SheetsClient) WriteRange(ctx context.Context, spreadsheetID, writeRange string, values [][]interface{}) (map[string]any, error) {
	vr := &sheets.ValueRange{
		Values: values,
	}

	resp, err := c.service.Spreadsheets.Values.Update(spreadsheetID, writeRange, vr).
		Context(ctx).
		ValueInputOption("USER_ENTERED").
		Do()
	if err != nil {
		return nil, fmt.Errorf("sheets: writing range %s to %s: %w", writeRange, spreadsheetID, err)
	}

	return map[string]any{
		"spreadsheet_id": resp.SpreadsheetId,
		"updated_range":  resp.UpdatedRange,
		"updated_rows":   resp.UpdatedRows,
		"updated_columns": resp.UpdatedColumns,
		"updated_cells":  resp.UpdatedCells,
	}, nil
}

// CreateSpreadsheet creates a new spreadsheet.
func (c *SheetsClient) CreateSpreadsheet(ctx context.Context, title string) (*SpreadsheetInfo, error) {
	ss := &sheets.Spreadsheet{
		Properties: &sheets.SpreadsheetProperties{
			Title: title,
		},
	}

	created, err := c.service.Spreadsheets.Create(ss).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("sheets: creating spreadsheet: %w", err)
	}

	info := &SpreadsheetInfo{
		ID:    created.SpreadsheetId,
		Title: created.Properties.Title,
	}
	for _, s := range created.Sheets {
		info.Sheets = append(info.Sheets, SheetInfo{
			Title: s.Properties.Title,
			Index: s.Properties.Index,
		})
	}
	return info, nil
}
