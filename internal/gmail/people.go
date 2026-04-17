package gmail

import (
	"context"
	"fmt"

	"google.golang.org/api/people/v1"
)

// PeopleClient wraps the Google People/Contacts API.
type PeopleClient struct {
	service *people.Service
}

// NewPeopleClient creates a PeopleClient from an existing People API service.
func NewPeopleClient(service *people.Service) *PeopleClient {
	return &PeopleClient{service: service}
}

// Contact represents a Google contact.
type Contact struct {
	ResourceName   string   `json:"resource_name"`
	Names          []string `json:"names,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	PhoneNumbers   []string `json:"phone_numbers,omitempty"`
}

// ContactListResult contains the results of a contacts listing.
type ContactListResult struct {
	Contacts      []Contact `json:"contacts"`
	NextPageToken string    `json:"next_page_token,omitempty"`
	TotalPeople   int64     `json:"total_people"`
}

func parseConnection(p *people.Person) Contact {
	c := Contact{
		ResourceName: p.ResourceName,
	}
	for _, n := range p.Names {
		c.Names = append(c.Names, n.DisplayName)
	}
	for _, e := range p.EmailAddresses {
		c.EmailAddresses = append(c.EmailAddresses, e.Value)
	}
	for _, ph := range p.PhoneNumbers {
		c.PhoneNumbers = append(c.PhoneNumbers, ph.Value)
	}
	return c
}

// ListContacts lists the user's contacts.
func (c *PeopleClient) ListContacts(ctx context.Context, pageSize int64, pageToken string) (*ContactListResult, error) {
	if pageSize == 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	call := c.service.People.Connections.List("people/me").Context(ctx).
		PageSize(pageSize).
		PersonFields("names,emailAddresses,phoneNumbers")

	if pageToken != "" {
		call = call.PageToken(pageToken)
	}

	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("people: listing contacts: %w", err)
	}

	result := &ContactListResult{
		NextPageToken: resp.NextPageToken,
		TotalPeople:   int64(resp.TotalPeople),
	}
	for _, p := range resp.Connections {
		result.Contacts = append(result.Contacts, parseConnection(p))
	}
	return result, nil
}

// GetContact returns a single contact by resource name.
func (c *PeopleClient) GetContact(ctx context.Context, resourceName string) (*Contact, error) {
	p, err := c.service.People.Get(resourceName).Context(ctx).
		PersonFields("names,emailAddresses,phoneNumbers").Do()
	if err != nil {
		return nil, fmt.Errorf("people: getting contact %s: %w", resourceName, err)
	}

	contact := parseConnection(p)
	return &contact, nil
}

// CreateContact creates a new contact.
func (c *PeopleClient) CreateContact(ctx context.Context, name, email, phone string) (*Contact, error) {
	person := &people.Person{}

	if name != "" {
		person.Names = []*people.Name{{GivenName: name}}
	}
	if email != "" {
		person.EmailAddresses = []*people.EmailAddress{{Value: email}}
	}
	if phone != "" {
		person.PhoneNumbers = []*people.PhoneNumber{{Value: phone}}
	}

	created, err := c.service.People.CreateContact(person).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("people: creating contact: %w", err)
	}

	contact := parseConnection(created)
	return &contact, nil
}

// UpdateContact updates an existing contact.
func (c *PeopleClient) UpdateContact(ctx context.Context, resourceName string, name, email, phone string) (*Contact, error) {
	// First get the current person to obtain the etag.
	existing, err := c.service.People.Get(resourceName).Context(ctx).
		PersonFields("names,emailAddresses,phoneNumbers").Do()
	if err != nil {
		return nil, fmt.Errorf("people: getting contact for update %s: %w", resourceName, err)
	}

	person := &people.Person{
		Etag: existing.Etag,
	}

	var updateFields []string
	if name != "" {
		person.Names = []*people.Name{{GivenName: name}}
		updateFields = append(updateFields, "names")
	}
	if email != "" {
		person.EmailAddresses = []*people.EmailAddress{{Value: email}}
		updateFields = append(updateFields, "emailAddresses")
	}
	if phone != "" {
		person.PhoneNumbers = []*people.PhoneNumber{{Value: phone}}
		updateFields = append(updateFields, "phoneNumbers")
	}

	if len(updateFields) == 0 {
		return nil, fmt.Errorf("people: no fields to update")
	}

	updated, err := c.service.People.UpdateContact(resourceName, person).Context(ctx).
		UpdatePersonFields(joinFields(updateFields)).Do()
	if err != nil {
		return nil, fmt.Errorf("people: updating contact %s: %w", resourceName, err)
	}

	contact := parseConnection(updated)
	return &contact, nil
}

// DeleteContact deletes a contact by resource name.
func (c *PeopleClient) DeleteContact(ctx context.Context, resourceName string) error {
	_, err := c.service.People.DeleteContact(resourceName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("people: deleting contact %s: %w", resourceName, err)
	}
	return nil
}

func joinFields(fields []string) string {
	result := ""
	for i, f := range fields {
		if i > 0 {
			result += ","
		}
		result += f
	}
	return result
}
