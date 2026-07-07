namespace Sieve {
  entity RoleGroup;
  entity Role in [RoleGroup];
  entity Token in [Role];
  entity Connector;
  entity Connection in [Connector] = { "connection_status"?: String };

  action "read";
  action "write";
  action "anthropic/read" in ["read"];
  action "anthropic/write" in ["write"];
  action "github/read" in ["read"];
  action "github/write" in ["write"];
  action "gitlab/read" in ["read"];
  action "gitlab/write" in ["write"];
  action "google/read" in ["read"];
  action "google/write" in ["write"];
  action "http_proxy/write" in ["write"];
  action "linear/read" in ["read"];
  action "linear/write" in ["write"];
  action "mcp_proxy/write" in ["write"];
  action "slack/read" in ["read"];
  action "slack/write" in ["write"];
  action "google/calendar.read" in ["google/read"];
  action "google/calendar.write" in ["google/write"];
  action "google/docs.read" in ["google/read"];
  action "google/docs.write" in ["google/write"];
  action "google/drive.read" in ["google/read"];
  action "google/drive.write" in ["google/write"];
  action "google/gmail.read" in ["google/read"];
  action "google/gmail.write" in ["google/write"];
  action "google/people.read" in ["google/read"];
  action "google/people.write" in ["google/write"];
  action "google/sheets.read" in ["google/read"];
  action "google/sheets.write" in ["google/write"];

  action "anthropic/messages_count_tokens" in ["anthropic/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "messages"?: String, "model"?: String, "system"?: String, "tool_choice"?: String, "tools"?: String } }
  };
  action "anthropic/messages_create" in ["anthropic/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "max_cost"?: String, "max_tokens"?: Long, "messages"?: String, "metadata"?: String, "model"?: String, "stop_sequences"?: Set<String>, "system"?: String, "temperature"?: String, "tool_choice"?: String, "tools"?: String, "top_k"?: Long, "top_p"?: String } }
  };
  action "github/github_comment_issue" in ["github/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "number"?: Long, "owner"?: String, "repo"?: String } }
  };
  action "github/github_create_issue" in ["github/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "assignees"?: Set<String>, "body"?: String, "labels"?: Set<String>, "owner"?: String, "repo"?: String, "title"?: String } }
  };
  action "github/github_create_pr" in ["github/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "base"?: String, "body"?: String, "draft"?: Bool, "head"?: String, "owner"?: String, "repo"?: String, "title"?: String } }
  };
  action "github/github_get_file" in ["github/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "owner"?: String, "path"?: String, "ref"?: String, "repo"?: String } }
  };
  action "github/github_get_pr" in ["github/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "number"?: Long, "owner"?: String, "repo"?: String } }
  };
  action "github/github_list_issues" in ["github/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "labels"?: String, "owner"?: String, "page"?: Long, "per_page"?: Long, "repo"?: String, "state"?: String } }
  };
  action "github/github_list_prs" in ["github/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "owner"?: String, "page"?: Long, "per_page"?: Long, "repo"?: String, "state"?: String } }
  };
  action "github/github_list_repos" in ["github/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Owner],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "owner"?: String, "page"?: Long, "per_page"?: Long } }
  };
  action "github/github_put_file" in ["github/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Github::Repo],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "branch"?: String, "content"?: String, "message"?: String, "owner"?: String, "path"?: String, "repo"?: String, "sha"?: String } }
  };
  action "github/github_request" in ["github/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "method"?: String, "path"?: String, "query"?: String } }
  };
  action "github/github_search_code" in ["github/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "page"?: Long, "per_page"?: Long, "q"?: String } }
  };
  action "gitlab/gitlab_comment_issue" in ["gitlab/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "issue_iid"?: Long, "project"?: String } }
  };
  action "gitlab/gitlab_create_issue" in ["gitlab/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "assignee_id"?: Long, "description"?: String, "labels"?: String, "project"?: String, "title"?: String } }
  };
  action "gitlab/gitlab_create_mr" in ["gitlab/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "description"?: String, "labels"?: String, "project"?: String, "remove_source_branch"?: Bool, "source_branch"?: String, "target_branch"?: String, "title"?: String } }
  };
  action "gitlab/gitlab_get_file" in ["gitlab/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "path"?: String, "project"?: String, "ref"?: String } }
  };
  action "gitlab/gitlab_get_mr" in ["gitlab/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "mr_iid"?: Long, "project"?: String } }
  };
  action "gitlab/gitlab_list_issues" in ["gitlab/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "labels"?: String, "page"?: Long, "per_page"?: Long, "project"?: String, "state"?: String } }
  };
  action "gitlab/gitlab_list_mrs" in ["gitlab/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "page"?: Long, "per_page"?: Long, "project"?: String, "source_branch"?: String, "state"?: String, "target_branch"?: String } }
  };
  action "gitlab/gitlab_list_projects" in ["gitlab/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "membership"?: Bool, "owned"?: Bool, "page"?: Long, "per_page"?: Long, "search"?: String } }
  };
  action "gitlab/gitlab_put_file" in ["gitlab/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "branch"?: String, "commit_message"?: String, "content"?: String, "encoding"?: String, "path"?: String, "project"?: String, "update"?: Bool } }
  };
  action "gitlab/gitlab_request" in ["gitlab/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "method"?: String, "path"?: String, "query"?: String } }
  };
  action "gitlab/gitlab_search_blobs" in ["gitlab/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "page"?: Long, "per_page"?: Long, "project"?: String, "search"?: String } }
  };
  action "google/add_label" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "label_id"?: String, "message_id"?: String } }
  };
  action "google/archive" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "message_id"?: String } }
  };
  action "google/calendar.create_event" in ["google/calendar.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "attendees"?: Set<String>, "calendar_id"?: String, "description"?: String, "end"?: String, "location"?: String, "start"?: String, "summary"?: String } }
  };
  action "google/calendar.delete_event" in ["google/calendar.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "calendar_id"?: String, "event_id"?: String } }
  };
  action "google/calendar.get_event" in ["google/calendar.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "calendar_id"?: String, "event_id"?: String } }
  };
  action "google/calendar.list_events" in ["google/calendar.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "calendar_id"?: String, "max_results"?: Long, "page_token"?: String, "time_max"?: String, "time_min"?: String } }
  };
  action "google/calendar.update_event" in ["google/calendar.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "attendees"?: Set<String>, "calendar_id"?: String, "description"?: String, "end"?: String, "event_id"?: String, "location"?: String, "start"?: String, "summary"?: String } }
  };
  action "google/create_draft" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "cc"?: Set<String>, "reply_to"?: String, "subject"?: String, "to"?: Set<String> } }
  };
  action "google/docs.create_document" in ["google/docs.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "title"?: String } }
  };
  action "google/docs.get_document" in ["google/docs.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "document_id"?: String } }
  };
  action "google/docs.list_documents" in ["google/docs.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "page_size"?: Long, "page_token"?: String } }
  };
  action "google/docs.update_document" in ["google/docs.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "document_id"?: String, "requests"?: String } }
  };
  action "google/drive.download_file" in ["google/drive.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "file_id"?: String } }
  };
  action "google/drive.get_file" in ["google/drive.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "file_id"?: String } }
  };
  action "google/drive.list_files" in ["google/drive.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "page_size"?: Long, "page_token"?: String, "query"?: String } }
  };
  action "google/drive.share_file" in ["google/drive.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "email"?: String, "file_id"?: String, "role"?: String } }
  };
  action "google/drive.upload_file" in ["google/drive.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "content"?: String, "mime_type"?: String, "name"?: String, "parent_folder_id"?: String } }
  };
  action "google/get_attachment" in ["google/gmail.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "attachment_id"?: String, "message_id"?: String } }
  };
  action "google/list_emails" in ["google/gmail.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "max_results"?: Long, "page_token"?: String, "query"?: String } }
  };
  action "google/list_labels" in ["google/gmail.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long }
  };
  action "google/people.create_contact" in ["google/people.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "email"?: String, "name"?: String, "phone"?: String } }
  };
  action "google/people.delete_contact" in ["google/people.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "resource_name"?: String } }
  };
  action "google/people.get_contact" in ["google/people.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "resource_name"?: String } }
  };
  action "google/people.list_contacts" in ["google/people.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "page_size"?: Long, "page_token"?: String } }
  };
  action "google/people.update_contact" in ["google/people.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "email"?: String, "name"?: String, "phone"?: String, "resource_name"?: String } }
  };
  action "google/read_email" in ["google/gmail.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "message_id"?: String } }
  };
  action "google/read_email_raw" in ["google/gmail.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "message_id"?: String } }
  };
  action "google/read_thread" in ["google/gmail.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "thread_id"?: String } }
  };
  action "google/remove_label" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "label_id"?: String, "message_id"?: String } }
  };
  action "google/reply" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "cc"?: Set<String>, "message_id"?: String, "subject"?: String, "to"?: Set<String> } }
  };
  action "google/send_draft" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "draft_id"?: String } }
  };
  action "google/send_email" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "cc"?: Set<String>, "reply_to"?: String, "subject"?: String, "to"?: Set<String> } }
  };
  action "google/sheets.create_spreadsheet" in ["google/sheets.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "title"?: String } }
  };
  action "google/sheets.get_spreadsheet" in ["google/sheets.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "spreadsheet_id"?: String } }
  };
  action "google/sheets.read_range" in ["google/sheets.read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "range"?: String, "spreadsheet_id"?: String } }
  };
  action "google/sheets.write_range" in ["google/sheets.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "range"?: String, "spreadsheet_id"?: String, "values"?: String } }
  };
  action "google/update_draft" in ["google/gmail.write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "cc"?: Set<String>, "draft_id"?: String, "subject"?: String, "to"?: Set<String> } }
  };
  action "http_proxy/proxy_request" in ["http_proxy/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "method"?: String, "path"?: String } }
  };
  action "linear/linear_create_comment" in ["linear/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "body"?: String, "issue_id"?: String } }
  };
  action "linear/linear_create_issue" in ["linear/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "assignee_id"?: String, "description"?: String, "priority"?: Long, "state_id"?: String, "team_id"?: String, "title"?: String } }
  };
  action "linear/linear_get_issue" in ["linear/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "id"?: String } }
  };
  action "linear/linear_list_comments" in ["linear/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "after"?: String, "first"?: Long, "issue_id"?: String } }
  };
  action "linear/linear_list_issues" in ["linear/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "after"?: String, "assignee_id"?: String, "first"?: Long, "state_id"?: String, "team_id"?: String } }
  };
  action "linear/linear_list_teams" in ["linear/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "after"?: String, "first"?: Long } }
  };
  action "linear/linear_list_users" in ["linear/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "after"?: String, "first"?: Long } }
  };
  action "linear/linear_list_workflow_states" in ["linear/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "team_id"?: String } }
  };
  action "linear/linear_request" in ["linear/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "query"?: String, "variables"?: String } }
  };
  action "linear/linear_update_issue" in ["linear/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "assignee_id"?: String, "description"?: String, "id"?: String, "priority"?: Long, "state_id"?: String, "title"?: String } }
  };
  action "mcp_proxy/call" in ["mcp_proxy/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Mcp::Tool],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long }
  };
  action "slack/list_channels" in ["slack/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "cursor"?: String, "page_size"?: Long, "types"?: String } }
  };
  action "slack/list_users" in ["slack/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "cursor"?: String, "page_size"?: Long } }
  };
  action "slack/post_message" in ["slack/write"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "channel"?: String, "text"?: String } }
  };
  action "slack/read_channel_history" in ["slack/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "channel"?: String, "cursor"?: String, "page_size"?: Long } }
  };
  action "slack/read_thread" in ["slack/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "channel"?: String, "ts"?: String } }
  };
  action "slack/read_user_profile" in ["slack/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "user"?: String } }
  };
  action "slack/search_messages" in ["slack/read"] appliesTo {
    principal: [Sieve::Token],
    resource: [Sieve::Connection],
    context: { "http_method"?: String, "recipient_domains"?: Set<String>, "estimated_cost"?: Long, "param"?: { "cursor"?: String, "page_size"?: Long, "query"?: String } }
  };
}

namespace Sieve::Github {
  entity Owner in [Sieve::Connection];
  entity Repo in [Sieve::Github::Owner];
}

namespace Sieve::Mcp {
  entity Tool in [Sieve::Connection];
}
