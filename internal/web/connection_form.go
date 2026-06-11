package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// This file is the single bridge between connection HTML forms and
// connector config maps. Both the create handler and the edit handler
// call into it; neither contains per-connector field code. The set of
// fields, their types, and their editability come exclusively from the
// connector's declared SetupFields (see connector.Field) — adding a
// field there automatically surfaces it in both forms.

// formMode distinguishes the two callers of applyConnectorFormFields.
type formMode int

const (
	formModeCreate formMode = iota
	formModeEdit
)

// renderableFieldTypes lists the field Type values the generic
// templates know how to render. Anything outside this set is filtered
// out by fieldInMode in BOTH modes — adding a new type means extending
// this set AND adding a branch in templates/connection_edit_field.html
// (and the create-side rendering when a generic create surface lands).
//
// Symmetry across modes prevents the class of bug where a field
// declared with an unknown type silently falls back to a plain text
// input on one form and is rejected on the other.
var renderableFieldTypes = map[string]bool{
	"text":     true,
	"password": true,
	"checkbox": true,
	"textarea": true,
	"number":   true,
	"json":     true,
	// "oauth" deliberately excluded — handled by per-connector bespoke
	// flows (Google) and not by the generic form.
	// "select" deliberately excluded — first-class select rendering
	// would require connector.Field to carry an Options []string list,
	// which no shipping connector needs today. Add it together with
	// the schema extension when a real use case appears.
}

// fieldInMode reports whether the field participates in the given form.
// A field is filtered out if its Type isn't renderable by the generic
// templates, regardless of mode. Within renderable types: create excludes
// EditOnly fields; edit excludes non-Editable fields.
func fieldInMode(f connector.Field, mode formMode) bool {
	if !renderableFieldTypes[f.Type] {
		return false
	}
	switch mode {
	case formModeCreate:
		return !f.EditOnly
	case formModeEdit:
		return f.Editable
	}
	return false
}

// applyConnectorFormFields walks the connector's declared fields and
// merges submitted form values into cfg. In formModeEdit, cfg should
// already contain the stored config so secret-keep and untouched fields
// flow through unchanged. Returns a user-facing error message ("" =
// success).
//
// Type-specific parsing:
//   - text / password / select: plain string. Secret fields submitted
//     empty in edit mode keep the stored value.
//   - checkbox: present in form -> true, absent -> false.
//   - textarea: newline-split into []any of trimmed non-empty lines.
//   - number: non-negative int64; empty -> 0.
//   - json: parsed object; empty -> key removed.
//
// Shape-level validation only. Semantic validation (URL formats,
// regex-constrained params, key prefixes) lives in the connector
// Factory; callers should instantiate via the registry after this
// returns to surface those errors uniformly.
func applyConnectorFormFields(meta connector.ConnectorMeta, mode formMode, r *http.Request, cfg map[string]any) string {
	// "Field absent from form" vs "field present but empty" are
	// different intents on edit: absent = "didn't touch it, keep
	// stored"; present + empty = "clear it" (only allowed for
	// non-Required strings). On create there's no stored value, so
	// the distinction collapses to "the operator omitted this".
	present := func(name string) bool {
		_, ok := r.Form[name]
		return ok
	}

	for _, f := range meta.SetupFields {
		if !fieldInMode(f, mode) {
			continue
		}
		raw := r.FormValue(f.Name)

		switch f.Type {
		case "checkbox":
			// HTML quirk: unchecked checkboxes don't submit at all.
			// Field absence IS the "false" value.
			cfg[f.Name] = present(f.Name)

		case "textarea":
			if mode == formModeEdit && !present(f.Name) {
				continue // keep stored
			}
			var lines []any
			for _, line := range strings.Split(raw, "\n") {
				t := strings.TrimSpace(line)
				if t == "" {
					continue
				}
				lines = append(lines, t)
			}
			cfg[f.Name] = lines

		case "number":
			if mode == formModeEdit && !present(f.Name) {
				continue
			}
			t := strings.TrimSpace(raw)
			if t == "" {
				cfg[f.Name] = int64(0)
				break
			}
			n, err := strconv.ParseInt(t, 10, 64)
			if err != nil || n < 0 {
				return fmt.Sprintf("%s must be a non-negative integer", f.Label)
			}
			cfg[f.Name] = n

		case "json":
			if mode == formModeEdit && !present(f.Name) {
				continue
			}
			t := strings.TrimSpace(raw)
			if t == "" {
				delete(cfg, f.Name)
				break
			}
			var obj map[string]any
			if err := json.Unmarshal([]byte(t), &obj); err != nil {
				return fmt.Sprintf("%s must be a JSON object: %v", f.Label, err)
			}
			cfg[f.Name] = obj

		default: // text, password, select, anything stringy
			// Secrets are never trimmed (could legitimately contain
			// leading/trailing whitespace as part of the key); every
			// other stringy field is trimmed so operators can't
			// silently bork themselves with stray whitespace from
			// copy-paste.
			val := raw
			if !f.Secret {
				val = strings.TrimSpace(raw)
			}
			if mode == formModeCreate {
				if f.Required && val == "" {
					return fmt.Sprintf("%s is required", f.Label)
				}
				if val == "" {
					continue // optional field omitted; let factory defaults apply
				}
				cfg[f.Name] = val
				continue
			}
			// Edit mode.
			if !present(f.Name) {
				continue // keep stored
			}
			if f.Secret && raw == "" {
				continue // secret empty submission = keep stored
			}
			// Required fields must remain non-empty after edit too — a
			// previously-create-only field becoming Editable shouldn't
			// also become "secretly clearable to an invalid empty
			// value." Secrets are exempt because an empty submission on
			// a Secret field is already interpreted as "keep stored"
			// above; the stored value satisfies the requirement.
			if f.Required && !f.Secret && val == "" {
				return fmt.Sprintf("%s is required", f.Label)
			}
			cfg[f.Name] = val
		}
	}
	return ""
}

// connectionFieldsForForm filters the connector's fields to those that
// participate in the given form mode, in declaration order. Templates
// iterate this to render the form.
func connectionFieldsForForm(meta connector.ConnectorMeta, mode formMode) []connector.Field {
	out := make([]connector.Field, 0, len(meta.SetupFields))
	for _, f := range meta.SetupFields {
		if fieldInMode(f, mode) {
			out = append(out, f)
		}
	}
	return out
}

// connectorRequiresBespokeAdd reports whether a connector type has its
// own add-flow handler that must run instead of the generic data-driven
// path. These connectors do something the generic save can't: validate
// credentials against the upstream (Slack), or run an OAuth dance
// (Google) where the connection is persisted only after callback.
func connectorRequiresBespokeAdd(connectorType string) bool {
	switch connectorType {
	case "slack", "google", "github":
		return true
	}
	return false
}
