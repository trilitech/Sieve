package gmail

import (
	"context"
	"fmt"

	"google.golang.org/api/calendar/v3"
)

// CalendarClient wraps the Google Calendar API.
type CalendarClient struct {
	service *calendar.Service
}

// NewCalendarClient creates a CalendarClient from an existing Calendar API service.
func NewCalendarClient(service *calendar.Service) *CalendarClient {
	return &CalendarClient{service: service}
}

// CalendarEvent represents a calendar event.
type CalendarEvent struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Description string   `json:"description,omitempty"`
	Location    string   `json:"location,omitempty"`
	Start       string   `json:"start"`
	End         string   `json:"end"`
	Attendees   []string `json:"attendees,omitempty"`
	Status      string   `json:"status,omitempty"`
	HTMLLink    string   `json:"html_link,omitempty"`
}

// CalendarListResult contains the results of an event listing.
type CalendarListResult struct {
	Events        []CalendarEvent `json:"events"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

func eventTime(et *calendar.EventDateTime) string {
	if et == nil {
		return ""
	}
	if et.DateTime != "" {
		return et.DateTime
	}
	return et.Date
}

func parseEvent(e *calendar.Event) CalendarEvent {
	ev := CalendarEvent{
		ID:          e.Id,
		Summary:     e.Summary,
		Description: e.Description,
		Location:    e.Location,
		Start:       eventTime(e.Start),
		End:         eventTime(e.End),
		Status:      e.Status,
		HTMLLink:    e.HtmlLink,
	}
	for _, a := range e.Attendees {
		ev.Attendees = append(ev.Attendees, a.Email)
	}
	return ev
}

// ListEvents lists events from a calendar.
func (c *CalendarClient) ListEvents(ctx context.Context, calendarID string, timeMin, timeMax string, maxResults int64, pageToken string) (*CalendarListResult, error) {
	if calendarID == "" {
		calendarID = "primary"
	}
	if maxResults == 0 {
		maxResults = 100
	}
	if maxResults > 2500 {
		maxResults = 2500
	}

	call := c.service.Events.List(calendarID).Context(ctx).
		MaxResults(maxResults).
		SingleEvents(true).
		OrderBy("startTime")

	if timeMin != "" {
		call = call.TimeMin(timeMin)
	}
	if timeMax != "" {
		call = call.TimeMax(timeMax)
	}
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}

	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: listing events: %w", err)
	}

	result := &CalendarListResult{
		NextPageToken: resp.NextPageToken,
	}
	for _, e := range resp.Items {
		result.Events = append(result.Events, parseEvent(e))
	}
	return result, nil
}

// GetEvent returns a single calendar event.
func (c *CalendarClient) GetEvent(ctx context.Context, calendarID, eventID string) (*CalendarEvent, error) {
	if calendarID == "" {
		calendarID = "primary"
	}

	e, err := c.service.Events.Get(calendarID, eventID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: getting event %s: %w", eventID, err)
	}

	ev := parseEvent(e)
	return &ev, nil
}

// CreateEvent creates a new calendar event.
func (c *CalendarClient) CreateEvent(ctx context.Context, calendarID string, summary, location, description, startTime, endTime string, attendees []string) (*CalendarEvent, error) {
	if calendarID == "" {
		calendarID = "primary"
	}

	event := &calendar.Event{
		Summary:     summary,
		Location:    location,
		Description: description,
	}

	if startTime != "" {
		event.Start = &calendar.EventDateTime{DateTime: startTime}
	}
	if endTime != "" {
		event.End = &calendar.EventDateTime{DateTime: endTime}
	}

	for _, email := range attendees {
		event.Attendees = append(event.Attendees, &calendar.EventAttendee{Email: email})
	}

	created, err := c.service.Events.Insert(calendarID, event).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: creating event: %w", err)
	}

	ev := parseEvent(created)
	return &ev, nil
}

// UpdateEvent updates an existing calendar event using PATCH semantics.
func (c *CalendarClient) UpdateEvent(ctx context.Context, calendarID, eventID string, summary, location, description, startTime, endTime string, attendees []string) (*CalendarEvent, error) {
	if calendarID == "" {
		calendarID = "primary"
	}

	event := &calendar.Event{}
	if summary != "" {
		event.Summary = summary
	}
	if location != "" {
		event.Location = location
	}
	if description != "" {
		event.Description = description
	}
	if startTime != "" {
		event.Start = &calendar.EventDateTime{DateTime: startTime}
	}
	if endTime != "" {
		event.End = &calendar.EventDateTime{DateTime: endTime}
	}
	if len(attendees) > 0 {
		for _, email := range attendees {
			event.Attendees = append(event.Attendees, &calendar.EventAttendee{Email: email})
		}
	}

	updated, err := c.service.Events.Patch(calendarID, eventID, event).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: updating event %s: %w", eventID, err)
	}

	ev := parseEvent(updated)
	return &ev, nil
}

// DeleteEvent deletes a calendar event.
func (c *CalendarClient) DeleteEvent(ctx context.Context, calendarID, eventID string) error {
	if calendarID == "" {
		calendarID = "primary"
	}

	err := c.service.Events.Delete(calendarID, eventID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("calendar: deleting event %s: %w", eventID, err)
	}
	return nil
}
