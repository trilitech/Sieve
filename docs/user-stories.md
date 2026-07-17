# Sieve User Stories

367 user stories describing interactions with the Sieve web UI and the expected behavior. Each story follows the pattern: what the user does, and what should happen.

---

## Connections

**1. Add an HTTP proxy connection**
User fills in alias "anthropic", display name "Claude API", target URL "https://api.anthropic.com", auth header "x-api-key", auth value "sk-ant-...", and clicks Connect. The connection appears in the connections table. The connector is created in memory and can be used immediately by roles and tokens.

**2. Add a Google account connection**
User fills in alias "work-gmail" and display name "Work Gmail", clicks Connect Google. Browser redirects to Google's OAuth consent screen. After the user grants access, Google redirects back to `/oauth/callback`. The connection is saved with OAuth tokens and the user's email address is shown as the display name. The connection appears in the table.

**3. Add a connection with a duplicate alias**
User tries to add a connection with alias "anthropic" when one already exists. The server returns a 400 error: "connection anthropic already exists". The connection is not created.

**4. Add a connection with missing required fields**
User submits the HTTP proxy form with the target URL left blank. The server returns a 400 error. The connection is not created.

**5. Delete a connection**
User clicks Delete on a connection and confirms the dialog. The connection is removed from the database and disappears from the table. The live connector is removed from memory.

**6. Delete a connection that is referenced by a role**
User deletes a connection that is part of a role binding. The connection is deleted, but the role is NOT updated. Tokens using that role can no longer access operations through that connection — the API returns an error when the connection is looked up. The role's binding becomes a dangling reference.

**7. Filter connections by type**
User clicks "Google" in the nav sidebar under Connections. The page reloads showing only Google-type connections and the Google OAuth form. Clicking "LLM API" shows only LLM provider cards. Clicking "Proxy" shows HTTP and MCP proxy forms.

**8. OAuth flow times out**
User clicks Connect Google, gets redirected to Google, but takes longer than 10 minutes. When Google redirects back, the server returns "OAuth session expired — try adding the connection again." No connection is saved.

**9. OAuth flow fails at token exchange**
User completes Google consent, but the authorization code is invalid or expired. The server returns "token exchange failed" error. No connection is saved (the pending OAuth entry is consumed and deleted).

**10. Add an LLM connection (Anthropic)**
User goes to Connections > LLM API, fills in the Anthropic card with alias "claude", display name "Claude", and API key. A connection of type `http_proxy` is created with category "llm" and the Anthropic API endpoint pre-filled. The connection appears in the table and in the Settings page LLM connection dropdown.

**11. Add an AWS account connection**
User goes to Connections > Cloud, fills in the AWS card with alias "aws-prod", region "us-east-1", access key ID, and secret key. A connection of type `http_proxy` is created with AWS auth headers. The connection can be used for EC2, S3, Lambda, and other AWS policy scopes.

**12. Add an MCP proxy connection**
User fills in alias "internal-mcp", display name "Internal MCP Server", target URL pointing to an MCP server, and auth details. A connection of type `mcp_proxy` is created. The MCP proxy discovers upstream tools on first use.

---

## Tokens

**13. Create a token with a role**
User fills in name "deploy-bot", selects role "project-x-dev" from the dropdown, and clicks Create Token. A new token is created and the plaintext (starting with `sieve_tok_`) is displayed in an amber alert box. This is the only time the plaintext is shown.

**14. Copy a newly created token**
User clicks the Copy button next to the plaintext token. The token value is copied to the system clipboard via `navigator.clipboard.writeText()`.

**15. Create a token with 24-hour expiry**
User selects "24 hours" from the Expires dropdown and creates the token. The token's `expires_at` is set to 24 hours from now. After 24 hours, API calls with this token return 401.

**16. Create a token with no expiry**
User leaves the Expires dropdown on "Never" and creates the token. The token has no `expires_at` and remains valid until explicitly revoked.

**17. Create a token without selecting a role**
User tries to create a token without selecting a role. The server returns 400 "a role is required". No token is created.

**18. Create a token with a duplicate name**
User tries to create a token with name "deploy-bot" when one already exists. The server returns an error (unique constraint violation). No token is created.

**19. Revoke a token**
User clicks Revoke on an active token and confirms the dialog. The token is marked as revoked. Subsequent API calls with this token return 401 "invalid token". The token appears in the Revoked filter view.

**20. Revoke a token that is currently in use by an agent**
User revokes a token while an agent is actively using it. The next API call the agent makes returns 401. However, if an operation is already in-flight (past the auth check), it completes — including approval waits. The token is validated once at the start of the request; there is no re-validation after approval resolution. This means an approved operation executes even if the token was revoked while waiting.

**21. View active tokens only**
User clicks the "Active" filter tab. Only tokens that are not revoked and not expired are shown.

**22. View revoked tokens only**
User clicks the "Revoked" filter tab. Only tokens that have been revoked are shown. The Revoke button is replaced with a dash in the Actions column.

**23. View expired tokens only**
User clicks the "Expired" filter tab. Only tokens that have a past `expires_at` and are not explicitly revoked are shown.

**24. View all tokens**
User clicks the "All" filter tab. All tokens (active, revoked, expired) are shown in the table.

**25. Token table shows role name, not role ID**
User views the tokens table. The Role column displays the human-readable role name (e.g., "project-x-dev"), not the hex role ID. If the role has been deleted, the column shows the raw ID.

---

## Roles

**26. Create a role with one connection and one policy**
User types role name "read-only-agent", clicks "+ Add connection", selects "work-gmail" from the connection dropdown, checks the "read-only" policy checkbox, and clicks Create Role. The role is created with one binding: `{connection_id: "work-gmail", policy_ids: ["read-only-id"]}`. The role appears in the table.

**27. Create a role with multiple connections**
User creates a role "full-agent" with two bindings: "work-gmail" with policies "read-only" + "drafter", and "anthropic" with policy "sonnet-only". The role has two bindings, each with their own connection and policy set.

**28. Create a role with no bindings**
User types a role name and clicks Create Role without adding any connection bindings. The role is created with an empty bindings array. Tokens using this role have access to zero connections — all API calls are denied.

**29. Create a role with a connection but no policies**
User adds a connection binding but does not check any policy checkboxes. The binding is created with an empty `policy_ids` array. This means the agent can see the connection exists (via `list_connections`) but all operations through it are denied — "no policies" means deny-all.

**30. Edit a role to change its name**
User clicks Edit on a role, changes the name from "old-name" to "new-name", and clicks Save Changes. The role is updated in the database. All tokens referencing this role are unaffected — they still work but now report the new role name.

**31. Edit a role to add a new connection binding**
User clicks Edit, clicks "+ Add connection", selects a new connection and policies, and saves. The role now has an additional binding. Existing tokens using this role immediately gain access to the new connection.

**32. Edit a role to remove a connection binding**
User clicks Edit, clicks Remove on an existing binding, and saves. The binding is removed. Existing tokens using this role immediately lose access to that connection.

**33. Edit a role to change policies on a connection**
User clicks Edit, unchecks one policy and checks a different one on a connection binding, and saves. The policy enforcement changes immediately for all tokens using this role.

**34. Delete a role**
User clicks Delete on a role and confirms the dialog. The role is removed from the database. Any tokens referencing this role become orphaned — API calls with those tokens fail because the role cannot be found.

**35. Delete a role that has active tokens**
User deletes a role while tokens reference it. The role is deleted. The tokens remain in the database but their `role_id` points to nothing. API calls return an error like "role not found". The tokens still appear in the tokens table but are effectively non-functional.

**36. Role table shows connection bindings summary**
User views the roles table. Each role row shows its connection bindings: the connection ID, and "(N policies)" or "(deny all)" in red if no policies are assigned to that connection.

---

## Policies

**37. Create a Gmail policy allowing only email reading**
User navigates to Policies > Google > Gmail, types name "email-reader", clicks Add Rule, checks "list_emails" and "read_email", selects action "Allow", clicks Add, sets default action to Deny, and clicks Create Policy. The policy is created with two allow rules and a deny default. Any operation not explicitly allowed is denied.

**38. Create a policy with a deny rule and a reason**
User creates a rule with action "Allow" (not Deny — the reason field is only visible for allow-action rules in the extras section), fills in the reason field, and adds it. The reason is stored in the rule and shown when the policy is evaluated. Note: the reason field is hidden for deny/approval_required actions in the current UI.

**39. Create a policy with a script action**
User clicks Add Rule, checks an operation, selects "Run Script" action. Script fields appear: Command (e.g., "python3") and Script Path (e.g., "./policies/email_filter.py"). The script is executed during policy evaluation; its exit code and stdout determine the decision.

**40. Create a policy requiring approval for send operations**
User clicks Add Rule, checks "send_email" and "send_draft", selects action "Require Approval", and adds the rule. When an agent tries to send, the operation is queued for human approval before executing.

**41. Load a preset policy**
User selects "read-only" from the preset dropdown and clicks Load. The rule builder is populated with the preset's rules (allow read operations, deny writes). The user can modify the loaded rules before creating the policy.

**42. Create a policy with content filtering**
User creates an allow rule for "list_emails", fills in the "Exclude content" field with "CONFIDENTIAL", and the "Redact patterns" field with a regex for SSN patterns. Responses have matching items removed and patterns redacted before reaching the agent.

**43. Create a policy with label-based filtering**
User creates an allow rule for "list_emails", and fills in the "Label" filter field with "project-x". Only emails with the "project-x" label are accessible to the agent.

**44. Create a policy with sender filtering**
User creates an allow rule for "read_email", and fills in the "From matches" filter with "*@company.com". Only emails from company.com addresses are readable.

**45. Edit a policy to change its name**
User clicks Edit on a policy, changes the name, and clicks Save. The policy is updated. All roles referencing this policy continue to work with the same policy ID.

**46. Edit a policy to add new rules**
User opens the edit page for a policy, adds a new rule allowing "create_draft", and saves. The policy now permits drafts in addition to its previous rules. The change takes effect immediately for all tokens using roles that include this policy.

**47. Edit a policy to change default action from deny to allow**
User opens the edit page, changes the default action dropdown from Deny to Allow, and saves. Now any operation not explicitly matched by a rule is allowed instead of denied. This is a dangerous change that effectively opens up access.

**48. Delete a policy**
User clicks Delete on a policy and confirms. The policy is removed. Roles that reference this policy ID in their bindings still have the ID, but building a policy evaluator fails because the policy doesn't exist. Effectively, the connection binding using this deleted policy breaks — the agent loses access.

**49. Delete a preset policy**
User deletes "read-only" (a preset policy). The policy is removed. On next server restart, `SeedPresets()` re-creates it with a new ID. Any roles that referenced the old ID are broken until manually updated to use the new ID.

**50. Create a policy for LLM operations**
User navigates to Policies > LLM API, creates a policy allowing Anthropic and OpenAI inference calls with a max cost filter of $0.10 per request. The policy restricts which providers the agent can use and caps per-request cost.

**51. Create a policy for HTTP proxy with path restriction**
User navigates to Policies > HTTP Proxy, creates a policy allowing only GET requests matching path "/v1/messages*". The policy ensures the agent can only call specific API endpoints.

**52. Create a policy for AWS EC2 with instance type restriction**
User navigates to Policies > Cloud > AWS > EC2, creates a policy allowing `ec2.run_instances` but restricting instance type to "t3.micro" and max instances to 3. This prevents the agent from launching large or excessive instances.

**53. Create a policy for Google Drive with read-only access**
User navigates to Policies > Google > Drive, creates a policy allowing `drive.list_files` and `drive.get_file` but denying `drive.upload_file` and `drive.share_file`. The agent can browse and read files but not upload or share them.

**54. Policy scoping in the nav**
User clicks through policy sub-categories in the nav: Gmail, Drive, Calendar, People, Sheets, Docs, LLM API, HTTP Proxy, EC2, S3, etc. Each category shows operations relevant to that scope, and the create form's operation checkboxes change accordingly.

**55. Multiple rules with first-match-wins semantics**
User creates a policy with: Rule 1 (deny send_email), Rule 2 (allow all Gmail operations). An agent trying to send_email hits Rule 1 first and is denied. An agent listing emails skips Rule 1 (no match) and hits Rule 2 (allowed). Order matters.

**56. Reorder rules in a policy**
User uses the move-up/move-down buttons on rules in the rule builder to change the evaluation order. The first matching rule determines the outcome, so reordering changes policy behavior.

---

## Approvals

**57. View pending approvals**
User navigates to the Approvals page. All pending approval items are shown as cards with token ID, connection, operation, request data (JSON), and Approve/Reject buttons. The page auto-refreshes every 5 seconds.

**58. Approve a pending operation**
User clicks Approve on a pending send_email request. The approval is marked as approved. The blocked API call (if waiting via WaitForResolution) is unblocked and the operation executes. The item disappears from the pending list.

**59. Reject a pending operation**
User clicks Reject on a pending request. The approval is marked as rejected. The blocked API call receives a "rejected" response. The item disappears from the pending list.

**60. Approve a policy proposal**
An agent submits a `propose_policy` request via MCP. The proposal appears in the approvals queue with the proposed policy name, description, and rules. User clicks Approve. The server creates a new policy from the proposal's request data and the item is resolved.

**61. Reject a policy proposal**
User clicks Reject on a policy proposal. No policy is created. The agent is notified that the proposal was rejected.

**62. Two admins try to approve the same item simultaneously**
Admin A and Admin B both see a pending item and click Approve at nearly the same time. The first request succeeds (conditional UPDATE with `WHERE status = 'pending'`). The second request gets "already resolved" error. Only one approval is recorded.

**63. Agent tries to self-approve via the web UI**
An agent makes an HTTP request to the web UI's `/approvals/{id}/approve` endpoint with its Sieve bearer token. The `rejectIfAgentToken()` function detects the `sieve_tok_` prefix and returns 403 "approval endpoints are not accessible to agents."

**64. Approval page shows "All clear" when empty**
After all pending items are resolved (approved or rejected), the page shows a centered checkmark icon and "All clear — No pending approvals" message.

**65. Auto-refresh shows new approvals**
User has the Approvals page open. An agent triggers a require_approval action. Within 5 seconds, the new approval card appears on the page without the user needing to manually refresh (HTMX polling).

---

## Audit Log

**66. View audit log**
User navigates to the Audit Log page. Recent API calls are shown in a table: timestamp, token name, connection, operation, result (allow/deny badge), and duration in milliseconds. Entries are ordered most-recent-first.

**67. Filter audit log by operation**
User types "send_email" in the Operation filter field and clicks Filter. Only entries with operation "send_email" are shown. Other operations disappear from the table.

**68. Filter audit log by connection**
User types "work-gmail" in the Connection filter. Only entries for the "work-gmail" connection are shown.

**69. Filter audit log by token**
User types a token ID in the Token filter. Only entries for that specific token are shown. This is useful for auditing what a particular agent has been doing.

**70. Filter audit log by date**
User selects a date in the "After" date picker. Only entries after that date are shown. This is useful for investigating incidents.

**71. Combine multiple filters**
User fills in both Operation "list_emails" and Connection "work-gmail". Only entries matching both criteria are shown.

**72. Clear audit filters**
User clears all filter fields and clicks Filter. All entries are shown again (up to the page limit).

**73. Paginate through audit log**
The audit log has more than one page of entries. Pagination controls show "Page 1 of 5 (247 total entries)". User clicks Next to see page 2. Filter parameters are preserved in the pagination links.

**74. Audit shows denied operations**
An agent attempts an operation that gets denied by policy. The audit log shows an entry with a red "deny" badge, the operation name, and the denial reason.

**75. Audit shows approval-required operations**
An agent triggers an operation requiring approval. The audit log shows an entry with a yellow "approval_required" badge.

---

## Settings

**76. Configure LLM connection for script generation**
User navigates to Settings, selects an LLM connection from the dropdown (filtered to show only LLM-capable connections), enters model name "claude-sonnet-4-20250514" and max tokens "4096", and clicks Save Settings. A success message appears.

**77. Settings persist after page reload**
User saves settings and reloads the page. The previously saved values (connection, model, max tokens) are pre-populated in the form fields.

**78. Update LLM settings**
User changes the model from "claude-sonnet" to "gpt-4" and saves. The new model is used for subsequent AI script generation requests.

**79. LLM dropdown shows only LLM connections**
User views the Settings page. The LLM Connection dropdown only shows connections that are LLM-capable (HTTP proxy connections with LLM-related target URLs or category "llm"). Google account connections and non-LLM proxies are excluded.

**80. Save settings with empty fields**
User clears the model field and saves. The setting is stored as empty string. Script generation will fail until a valid model is configured.

---

## Cross-Entity Workflows

**81. Full agent setup: connection -> policy -> role -> token**
User adds a Google connection, creates a "read-only" policy for Gmail, creates a role binding the connection to the policy, and creates a token with that role. The agent can now use the token to list and read emails but not send them.

**82. Change policy, all tokens update immediately**
User edits a policy to add an "allow send_email" rule. All roles using this policy and all tokens using those roles immediately gain send capability — no token rotation needed.

**83. Change role bindings, all tokens update immediately**
User edits a role to add a new connection binding with a policy. All tokens using this role immediately gain access to the new connection.

**84. Delete connection used by active tokens**
User deletes a connection. Tokens with roles that reference this connection still exist but operations through that connection fail. The role's binding becomes a dangling reference. The user should remove the binding from the role manually.

**85. Delete policy used by active tokens**
User deletes a policy. Roles that include this policy ID in their bindings still reference it, but building a policy evaluator fails. The agent loses access to the connection that used this policy.

**86. Delete role used by active tokens**
User deletes a role. Tokens referencing this role become non-functional — API calls return "role not found". The tokens still appear in the tokens table but are effectively dead.

**87. Revoke token, audit trail preserved**
User revokes a token. The token is invalidated for future use. All historical audit entries for this token remain in the log and are still searchable by token ID.

**88. Create overlapping policies with different outcomes**
User creates Policy A (allow list_emails) and Policy B (deny list_emails). A role binds a connection to both policies. The composite evaluator evaluates all policies — if any denies, the final decision is deny (first-deny-wins). So Policy B's deny overrides Policy A's allow.

**89. Agent proposes policy, admin reviews and approves**
An agent calls `propose_policy` via MCP, describing what access it needs. The proposal appears in the approvals queue with the agent's description and proposed rules. The admin reviews the rules, clicks Approve, and a new policy is created from the proposal. The admin can then add this policy to the agent's role.

**90. Multiple agents sharing a role**
Admin creates one role "data-analyst" with read-only Gmail access. Admin creates three tokens all using this role. All three agents have identical access. When the admin edits the role or its policies, all three agents are affected simultaneously.

---

## Navigation and UI

**91. Root URL redirects to connections**
User navigates to the root URL `/`. The browser redirects to `/connections`.

**92. Nav sidebar highlights active page**
User navigates to `/tokens`. The Tokens link in the nav sidebar is visually highlighted (different background color) to indicate the current page.

**93. Collapsible nav sections**
User clicks the Connections section header in the nav. The sub-items (Google, Cloud, LLM API, Proxy) toggle visibility. Clicking again collapses them. The same behavior applies to the Policies section and its nested sub-sections.

**94. Nav policy sub-sections with nesting**
User expands Policies > Cloud > AWS in the nav. Nested sub-items appear: EC2, S3, Lambda, SES, DynamoDB. Each links to the policies page filtered by that scope.

**95. Documentation links in nav footer**
User clicks "Google OAuth Setup" in the nav footer. A documentation page loads explaining how to set up Google OAuth credentials. Similar links exist for "Gmail REST API" and "Policy Scripts."

---

## Edge Cases and Error Handling

**96. Create policy with no rules**
User creates a policy with zero rules and default action "deny". The policy denies all operations. If default action is "allow", it allows everything. This is a valid but potentially dangerous configuration.

**97. Token with expired role reference**
A role is deleted after a token was created with it. The token's `role_id` is a dangling reference. API calls fail with "role not found". The token appears in the UI with the raw hex ID in the Role column (since the role name can't be looked up).

**98. Connection config update refreshes live connector**
User updates a connection's config (e.g., rotating an API key via `UpdateConfig`). The live connector is recreated with the new config. Existing sessions using the old connector are replaced. The next API call uses the new credentials.

**99. Server restart preserves all data**
User restarts the Sieve server. On startup, the database is reopened, all connections are initialized via `InitAll()`, and preset policies are re-seeded. Tokens, roles, policies, audit entries, and pending approvals are all preserved. Any connection that fails to initialize (e.g., expired OAuth token) logs a warning but doesn't prevent the server from starting.

**100. Concurrent policy evaluation for the same token**
Two API requests arrive simultaneously for the same token. Each request builds its own policy evaluator (no cache) and evaluates independently. There is no shared mutable state between evaluations — the policy engine is stateless per-request. Both requests get correct, independent decisions.

---

## Edit Button Discoverability

These stories verify that the user can find and use edit functionality — broken if the edit link/button is missing or doesn't load data correctly.

**101. Policy table has an Edit link per row**
User views the policies table. Every policy row has an "Edit" link in the Actions column. The link points to `/policies/{id}/edit`.

**102. Clicking Edit on a policy loads the edit page with the policy name pre-populated**
User clicks Edit on policy "email-reader". The edit page loads. The name input field contains "email-reader". The user can change it and save.

**103. Policy edit page pre-populates existing rules**
User clicks Edit on a policy that has 3 rules (allow list_emails, allow read_email, deny send_email). The edit page shows all 3 rules in the rule list with their operations, actions, and filter values intact. The rules are not empty — the existing rule data was loaded from the policy config.

**104. Policy edit page pre-populates the default action**
User clicks Edit on a policy with default action "deny". The default action dropdown on the edit page is set to "Deny", not "Allow". Saving without changes preserves the existing default action.

**105. Role table has an Edit link per row**
User views the roles table. Every role row has an "Edit" link in the Actions column next to the Delete button. The link points to `/roles/{id}/edit`.

**106. Clicking Edit on a role loads the edit page with the role name pre-populated**
User clicks Edit on role "project-x-dev". The edit page loads with the name input containing "project-x-dev".

**107. Role edit page pre-populates existing connection bindings**
User clicks Edit on a role that has two bindings: "work-gmail" with "read-only" policy, and "anthropic" with "sonnet-only" policy. The edit page shows two binding cards. The connection dropdowns are set to the correct connections. The policy checkboxes for the assigned policies are checked.

**108. Connections table has NO Edit link**
User views the connections table. There is no Edit link or button — only Delete. To change a connection's config (e.g., rotate an API key), the user must delete and re-create the connection, or use the CLI/API.

**109. Tokens table has NO Edit link**
User views the tokens table. There is no way to edit a token's name, role, or expiry after creation. The only action is Revoke.

**110. User cannot un-revoke a token**
User looks at a revoked token in the table. There is no "Un-revoke" or "Reactivate" button. The only option is to create a new token. Revocation is permanent.

---

## Confirmation Dialogs and Cancel Flows

**111. Delete connection confirmation dialog**
User clicks Delete on a connection. A browser confirmation dialog appears: "Delete connection 'work-gmail'? This cannot be undone." If the user clicks Cancel, nothing happens — the connection remains. If the user clicks OK, the connection is deleted.

**112. Delete role confirmation dialog**
User clicks Delete on a role. A browser confirmation dialog appears: "Delete role 'project-x-dev'?" If the user clicks Cancel, the role remains.

**113. Delete policy confirmation dialog**
User clicks Delete on a policy. A browser confirmation dialog appears: "Delete this policy?" If the user clicks Cancel, the policy remains.

**114. Revoke token confirmation dialog**
User clicks Revoke on a token. A browser confirmation dialog appears: "Revoke token 'deploy-bot'?" If the user clicks Cancel, the token remains active.

**115. Cancel editing a role**
User clicks Edit on a role, changes the name, then clicks the Cancel link (instead of Save). The browser navigates back to `/roles`. The role name is unchanged — the edit was not saved.

**116. Cancel editing a policy (navigate away)**
User clicks Edit on a policy, changes the name, then navigates to a different page via the nav sidebar. The changes are lost — the policy retains its original name.

---

## Duplicate Name and Constraint Violations

**117. Create a role with a duplicate name**
User tries to create a role named "project-x-dev" when one already exists. The server returns an error (UNIQUE constraint on role name). The role is not created. The user sees an error message.

**118. Create a policy with a duplicate name**
User tries to create a policy named "read-only" when one already exists. The server returns an error (UNIQUE constraint on policy name). The policy is not created.

**119. Edit a role to use an existing name**
User edits role "old-role" and changes the name to "project-x-dev" (which already exists). The server returns an error. The name is not changed.

**120. Edit a policy to use an existing name**
User edits a policy and changes the name to "read-only" (which already exists). The server returns an error. The name is not changed.

---

## Empty State and Missing Dependencies

**121. Create token when no roles exist**
User navigates to the Tokens page when no roles have been created. The role dropdown is empty (no options to select). The user cannot create a token because a role is required. The form should display a message or the submit fails with "a role is required".

**122. Create role when no connections exist**
User navigates to the Roles page when no connections have been created. The "+ Add connection" button works but the connection dropdown has no options (only "Select connection..."). The user can create a role with no bindings, but can't bind to any connection.

**123. Create role when no policies exist**
User navigates to the Roles page when no policies have been created (presets were deleted). The "+ Add connection" button works and connections appear in the dropdown, but the policies checkbox list is empty. The binding has `policy_ids: []`, which means deny-all.

**124. Policies page with no scope selected**
User navigates to `/policies` without a scope parameter. The policies table is shown listing all policies, but the create form is hidden. Instead, a message says "Select a policy type from the left menu to create a new policy."

**125. Empty policies table**
User navigates to policies after deleting all policies (including presets). The table shows "No policies" or an empty table body. The user can still create new ones via the scope-specific pages.

**126. Empty roles table**
User views the roles page with no roles created. The table shows "No roles yet. Create one above."

**127. Empty tokens table**
User views the tokens page with no tokens created. The table body is empty.

**128. Empty audit log**
User views the audit page before any API calls have been made. The table shows "No audit entries found."

**129. Approvals page with no pending items**
User views the approvals page when all items have been resolved. The page shows a checkmark icon and "All clear — No pending approvals. New items will appear here automatically."

---

## Removing Rules and Bindings

**130. Remove a rule from a policy via the edit page**
User clicks Edit on a policy, sees 3 rules. User clicks the remove/delete button on the second rule. The rule disappears from the list. User clicks Save. The policy now has 2 rules. The removed rule no longer applies.

**131. Remove all rules from a policy**
User edits a policy and removes every rule, leaving only the default action. The policy now acts purely based on its default action (deny-all or allow-all).

**132. Remove a binding from a role via the edit page**
User clicks Edit on a role with two bindings. User clicks Remove on the "anthropic" binding. The binding card disappears. User clicks Save. The role now has one binding. Tokens using this role lose access to the removed connection immediately.

**133. Remove all bindings from a role**
User edits a role and removes every binding. The role becomes empty. Tokens using this role have access to zero connections — all API calls are denied.

---

## API Enforcement (Agent-Side)

**134. Expired token calls the API**
An agent uses a token that expired 2 hours ago. The API returns 401 "invalid token". The agent cannot perform any operations. An expired token is indistinguishable from a nonexistent token to the caller.

**135. Revoked token calls the API**
An agent uses a revoked token. The API returns 401 "invalid token". The error message does not reveal whether the token was revoked vs. expired vs. never existed (prevents enumeration).

**136. Token accesses a connection not in its role**
An agent with role bound to "work-gmail" tries to call `/api/v1/connections/personal-gmail/ops/list_emails`. The API returns 403 because "personal-gmail" is not in the role's bindings.

**137. Token calls an operation denied by policy**
An agent with a read-only policy calls `send_email`. The API returns 403 with body containing "policy denied" and the reason from the deny rule.

**138. Token calls an operation allowed by policy**
An agent with a read-only policy calls `list_emails`. The API returns 200 with the operation result. An audit entry is logged with result "allow".

**139. Token calls an operation requiring approval — synchronous API**
An agent calls `send_email` through the REST API where the policy says "require_approval". The API blocks (WaitForResolution, up to 5 minutes). If a human approves within that time, the operation executes and the API returns 200. If timeout elapses, the API returns 504 Gateway Timeout.

**140. Token calls an operation requiring approval — MCP**
An agent calls `send_email` through the MCP server where the policy says "require_approval". The MCP server returns immediately with an approval ID and instructions to poll. The agent does not block.

**141. No-auth request to the API**
A request hits the API without an Authorization header. The API returns 401 "missing or invalid Authorization header".

**142. Wrong token format**
A request uses "Bearer not-a-sieve-token". The token is hashed and looked up in the database (there is no prefix check — validation is purely hash-based). Since no matching hash exists, the API returns 401 "invalid token".

**143. Valid token lists its connections**
An agent calls `GET /api/v1/connections`. The API returns a JSON array of connections the token has access to (based on its role's bindings), with id, connector type, and display name. Config/secrets are not included.

---

## MCP Server (Agent-Side)

**144. Agent discovers tools via MCP tools/list**
An agent sends a `tools/list` JSON-RPC request to the MCP server with its bearer token. The server returns tool definitions for all operations on all connections in the token's role, plus built-in tools (list_connections, list_policies, get_my_policy, propose_policy).

**145. Tool names include connector prefix for multi-connection tokens**
An agent's token has access to two connections (both Google type). Tool names are prefixed with the connector type: `google_list_emails`, `google_send_email`. When the token has only one connection, tools are unprefixed: `list_emails`, `send_email`.

**146. Agent calls list_connections via MCP**
Agent calls the `list_connections` built-in tool. The response contains a JSON array of the token's accessible connections with id, connector type, and display name.

**147. Agent calls get_my_policy via MCP**
Agent calls the `get_my_policy` built-in tool. The response shows the full policy configuration for each connection binding in the token's role, including all rules, default actions, and filter settings.

**148. Agent calls propose_policy via MCP**
Agent calls `propose_policy` with a name, description, and rules array. The proposal is submitted to the approval queue. The agent receives a confirmation with the approval ID. No policy is created until a human approves.

**149. MCP denormalized dots in tool names**
A Drive operation named "drive.list_files" is exposed as tool "drive_list_files" (dots replaced with underscores). When the agent calls "drive_list_files", the MCP server converts it back to "drive.list_files" before calling the connector.

**150. MCP initialize handshake**
Agent sends an `initialize` JSON-RPC request. The server responds with protocol version "2024-11-05", server name "sieve", version "0.1.0", and capabilities including tools.

---

## Script Generation

**151. Generate a policy script via AI**
User navigates to a policy scope page, clicks a "Generate Script" button, types a description like "only allow emails from @company.com addresses", and submits. The server calls the configured LLM connection with a scope-specific prompt template. The generated Python script is displayed for review.

**152. Accept a generated script**
User reviews the AI-generated script and clicks Accept. The script is saved to the `policies/` directory on disk. The user can then reference this script path in a policy rule with action "run_script".

**153. Script generation fails when no LLM is configured**
User tries to generate a script but no LLM connection is configured in Settings. The generation fails with an error message telling the user to configure an LLM connection first.

---

## Cascading Effects and Data Integrity

**154. Delete the only policy in a role binding**
User deletes a policy. A role has a binding `{connection_id: "gmail", policy_ids: ["deleted-id"]}`. The binding still exists with the dead policy ID. When a token using this role tries to access "gmail", the policy evaluator fails to build (policy not found), and the operation is denied.

**155. Delete a connection, then view the role that references it**
User deletes connection "old-gmail". A role still has a binding to "old-gmail". When viewing the roles table, the binding shows "old-gmail" but the connection no longer exists. Editing the role shows "old-gmail" in the connection dropdown only if it's still in the binding data — the dropdown won't have it as a selectable option since it's deleted.

**156. Create a token, delete its role, try to use the token**
User creates a token with role "temp-role", then deletes "temp-role". The token still exists and appears in the tokens table. API calls with this token fail with "role not found". The tokens table shows the role ID (hex) instead of a name since the role no longer exists.

**157. Edit a policy that is currently being evaluated**
Admin edits a policy while an agent is mid-request. There is no race condition — each request builds a fresh evaluator from the database. The in-flight request uses the old policy. The next request uses the updated policy.

**158. Two admins edit the same role simultaneously**
Admin A and Admin B both open the edit page for role "shared". Admin A saves first (name → "shared-v2"). Admin B still has the old form and saves (name → "shared-v3"). Admin B's save overwrites Admin A's change. Last-write-wins semantics — no conflict detection.

**159. Delete all connections, try to create a role**
User deletes every connection. On the roles page, clicking "+ Add connection" shows an empty connection dropdown. The user can create a role but can't bind any connection. Tokens using this role are denied access to everything.

**160. Delete all policies, roles still reference them**
User deletes every policy (including presets). Existing roles still have bindings with the deleted policy IDs. Token operations fail because the policy evaluator can't find any of the referenced policies.

---

## Token Display and Feedback

**161. After creating a token, the plaintext is shown exactly once**
User creates a token. The page re-renders showing an amber alert box with the plaintext token (`sieve_tok_...`). If the user navigates away and comes back to `/tokens`, the plaintext is no longer shown — only the token name appears in the table.

**162. Token plaintext is long enough to copy correctly**
The plaintext token contains the prefix `sieve_tok_` followed by enough random hex characters to be cryptographically secure. The code element has `user-select: all` styling so clicking selects the entire token for easy copy-paste.

**163. After revoking a token, the page shows it as revoked**
User revokes a token and the page reloads. The revoked token now shows a red "Revoked" badge in the Status column, and the Revoke button is replaced with a dash.

---

## Documentation Pages

**164. Google OAuth Setup doc loads**
User clicks "Google OAuth Setup" in the nav footer. The page loads with step-by-step instructions for creating a Google Cloud project, enabling APIs, and configuring OAuth credentials. The page returns 200, not 404.

**165. Gmail REST API doc loads**
User clicks "Gmail REST API" in the nav footer. The page loads with documentation about the Gmail-compatible API endpoints that Sieve exposes.

**166. Policy Scripts doc loads**
User clicks "Policy Scripts" in the nav footer. The page loads with documentation about writing Python policy scripts, the script interface, and examples.

**167. Nonexistent doc page returns 404**
User navigates to `/docs/nonexistent`. The server returns 404 "doc not found".

---

## Per-Operation Policy Rules (Gmail)

**168. Allow only list_emails, deny everything else**
User creates a policy with one rule: allow list_emails. Default action: deny. Agent calls list_emails → 200. Agent calls read_email → 403. Agent calls send_email → 403.

**169. Allow list_emails and read_email but deny send**
User creates a policy with: Rule 1 (allow list_emails, read_email), Rule 2 (deny send_email, send_draft). Default: deny. Agent can browse and read but not send.

**170. Allow compose but not send**
User creates a policy allowing create_draft and update_draft, denying send_email and send_draft. Default: deny. Agent can write drafts but cannot send them — a human reviews and sends manually.

**171. Allow all Gmail operations (full-assist)**
User creates a policy with default action: allow. No deny rules. Agent can perform any Gmail operation including sending, labeling, and archiving.

**172. Require approval for send, allow everything else**
User creates a policy with: Rule 1 (require_approval for send_email, send_draft), default: allow. Agent can freely read and draft, but sending triggers the approval queue.

**173. Deny archive and label modification**
User creates a policy allowing reads and sends but denying archive, add_label, and remove_label. Agent cannot reorganize the inbox.

**174. Allow only get_attachment**
User creates a policy allowing only get_attachment. Default: deny. Agent can download attachments from known message IDs but cannot list or read emails.

**175. Allow read_thread but deny read_email**
User creates a policy allowing read_thread but denying read_email. Agent can view threaded conversations but not individual messages. (Whether this makes practical sense depends on the connector implementation.)

**176. Allow list_labels only**
User creates a policy allowing only list_labels. Default: deny. Agent can discover what labels exist but cannot read any email content.

---

## Per-Operation Policy Rules (Google Drive)

**177. Drive read-only policy**
User creates a policy allowing drive.list_files and drive.get_file. Denies drive.upload_file and drive.share_file. Agent can browse and read files but not modify or share them.

**178. Drive upload but no share**
User creates a policy allowing drive.upload_file but denying drive.share_file. Agent can upload files but cannot change sharing permissions.

**179. Drive download restricted to PDFs**
User creates a policy allowing drive.download_file with a MIME type filter of "application/pdf". Agent can only download PDF files, not spreadsheets or documents.

---

## Per-Operation Policy Rules (Google Calendar)

**180. Calendar read-only**
User creates a policy allowing calendar.list_events and calendar.get_event. Denies write operations. Agent can see the calendar but not create or modify events.

**181. Calendar create but not delete**
User creates a policy allowing calendar.create_event and calendar.update_event, denying calendar.delete_event. Agent can add and modify events but not remove them.

**182. Calendar restricted to a specific calendar ID**
User creates a policy allowing calendar operations with the calendar ID filter set to "work@group.calendar.google.com". Agent can only interact with that specific calendar.

---

## Per-Operation Policy Rules (Google People/Contacts)

**183. Contacts read-only**
User creates a policy allowing people.list_contacts and people.get_contact, denying writes. Agent can look up contacts but not create or modify them.

**184. Contacts restricted to specific fields**
User creates a policy allowing people.get_contact with the "allowed fields" filter set to "names,emailAddresses". Agent can only see names and emails, not phone numbers or addresses.

---

## Per-Operation Policy Rules (Google Sheets)

**185. Sheets read-only**
User creates a policy allowing sheets.get_spreadsheet and sheets.read_range. Denies sheets.write_range and sheets.create_spreadsheet. Agent can read data but not modify it.

**186. Sheets restricted to a specific spreadsheet**
User creates a policy allowing sheets operations with the spreadsheet ID filter set to a specific ID. Agent can only access that one spreadsheet.

**187. Sheets restricted to a specific range**
User creates a policy allowing sheets.read_range with range filter "Sheet1!A:Z". Agent can only read from Sheet1, not other sheets in the workbook.

---

## Per-Operation Policy Rules (Google Docs)

**188. Docs read-only**
User creates a policy allowing docs.get_document and docs.list_documents. Denies docs.create_document and docs.update_document.

**189. Docs restricted by title**
User creates a policy allowing docs.get_document with title filter "Meeting Notes*". Agent can only access documents whose title starts with "Meeting Notes".

---

## Per-Operation Policy Rules (AWS EC2)

**190. EC2 describe-only**
User creates a policy allowing all ec2.describe_* operations. Denies ec2.run_instances, ec2.terminate_instances, and all lifecycle operations. Agent can inspect infrastructure but not change it.

**191. EC2 allow run_instances with instance type restriction**
User creates a policy allowing ec2.run_instances with instance type filter "t3.micro,t3.small". Agent cannot launch large instances.

**192. EC2 deny terminate_instances**
User creates a policy with default: allow but an explicit deny rule for ec2.terminate_instances. Agent can do everything except terminate instances.

**193. EC2 restrict to specific region**
User creates a policy allowing EC2 operations with region filter "us-east-1". Agent cannot operate in other AWS regions.

**194. EC2 max instances limit**
User creates a policy allowing ec2.run_instances with max count filter of 5. Agent cannot launch more than 5 instances in a single API call.

**195. EC2 restrict security group ingress to specific ports**
User creates a policy allowing ec2.authorize_security_group_ingress with allowed ports "443,8080". Agent cannot open port 22 (SSH) or other ports.

**196. EC2 block 0.0.0.0/0 CIDR**
User creates a policy allowing ec2.authorize_security_group_ingress with allowed CIDR filter that excludes "0.0.0.0/0". Agent cannot make security groups publicly accessible.

---

## Per-Operation Policy Rules (AWS S3)

**197. S3 read-only**
User creates a policy allowing s3.list_buckets, s3.list_objects, s3.get_object, s3.head_object. Denies s3.put_object, s3.delete_object, s3.copy_object.

**198. S3 restricted to specific bucket**
User creates a policy allowing S3 operations with bucket filter "data-lake-prod". Agent can only access objects in that bucket.

**199. S3 restricted to key prefix**
User creates a policy allowing S3 operations with prefix filter "public/". Agent can only access objects under the "public/" prefix.

---

## Per-Operation Policy Rules (AWS Lambda)

**200. Lambda invoke but no list**
User creates a policy allowing lambda.invoke but denying lambda.list_functions and lambda.get_function. Agent can call known functions but cannot discover what functions exist.

**201. Lambda read-only**
User creates a policy allowing lambda.list_functions and lambda.get_function. Denies lambda.invoke. Agent can see functions but not execute them.

---

## Per-Operation Policy Rules (AWS SES)

**202. SES send but no manage**
User creates a policy allowing ses.send_email but denying ses.list_identities and ses.get_send_quota. Agent can send emails but cannot enumerate verified identities.

**203. SES read quota only**
User creates a policy allowing ses.get_send_quota. Denies sending. Agent can check sending limits without being able to send.

---

## Per-Operation Policy Rules (AWS DynamoDB)

**204. DynamoDB read-only**
User creates a policy allowing dynamodb.get_item, dynamodb.query, dynamodb.scan, dynamodb.list_tables. Denies dynamodb.put_item, dynamodb.update_item, dynamodb.delete_item.

**205. DynamoDB write but no delete**
User creates a policy allowing dynamodb.put_item and dynamodb.update_item but denying dynamodb.delete_item. Agent can add and update records but not remove them.

---

## Per-Operation Policy Rules (Hyperstack)

**206. Hyperstack VM read-only**
User creates a policy allowing hyperstack.list_vms, hyperstack.get_vm, hyperstack.list_flavors, hyperstack.list_images. Denies hyperstack.create_vm, hyperstack.delete_vm, and lifecycle operations.

**207. Hyperstack create and stop but no delete**
User creates a policy allowing hyperstack.create_vm, hyperstack.stop_vm, hyperstack.start_vm. Denies hyperstack.delete_vm. Agent can provision and manage VMs but cannot permanently destroy them.

---

## Per-Operation Policy Rules (LLM API)

**208. LLM restrict to Anthropic only**
User creates a policy allowing LLM calls with only the Anthropic provider checkbox checked. Agent cannot call OpenAI, Gemini, or Bedrock endpoints.

**209. LLM restrict model to specific pattern**
User creates a policy allowing LLM calls with model filter "claude-haiku-*". Agent can only use Haiku models, not Sonnet or Opus.

**210. LLM max cost per request**
User creates a policy allowing LLM calls with max cost filter "$0.05". Agent's requests are denied if the estimated cost exceeds $0.05.

**211. LLM restrict max output tokens**
User creates a policy allowing LLM calls with max tokens filter 1024. Agent cannot request more than 1024 output tokens per call.

**212. LLM disable extended thinking (Anthropic)**
User creates a policy with the Anthropic extended thinking filter set to "Disabled". Agent cannot use Anthropic's extended thinking feature.

**213. LLM require JSON mode (OpenAI)**
User creates a policy with the OpenAI JSON mode filter set to "Required". Agent must use JSON mode for all OpenAI calls.

**214. LLM restrict temperature (OpenAI)**
User creates a policy with max temperature filter 0.5. Agent cannot set temperature above 0.5 for OpenAI calls.

**215. LLM multiple providers allowed**
User creates a policy checking both Anthropic and OpenAI provider boxes. Agent can call either provider but not Gemini or Bedrock.

---

## Per-Operation Policy Rules (HTTP Proxy)

**216. HTTP proxy GET only**
User creates a policy allowing only GET requests. Denies POST, PUT, DELETE, PATCH. Agent can read from the API but not write.

**217. HTTP proxy restricted to specific path**
User creates a policy allowing requests with path filter "/v1/chat/completions". Agent can only call that specific endpoint.

**218. HTTP proxy restricted by request body**
User creates a policy allowing POST requests with body filter that must not contain "system". Agent cannot send system prompts.

**219. HTTP proxy allow all methods to all paths**
User creates a policy with default: allow. No restrictions. The proxy forwards everything. Only the auth header is substituted.

---

## Per-Operation Policy Rules (MCP Proxy)

**220. MCP proxy allow specific tools**
User creates a policy allowing specific tool operations discovered from the upstream MCP server. Other tools are denied by default.

---

## Filter Field Interactions

**221. Gmail from+label filter combination**
User creates a rule allowing read_email with from filter "*@vip.com" and label filter "inbox". Both filters must match for the rule to apply — emails from vip.com that are in the inbox.

**222. Gmail subject+content filter combination**
User creates a rule allowing list_emails with subject filter "Project X" and content filter "milestone". Only emails about Project X containing "milestone" are accessible.

**223. EC2 instance type + region filter combination**
User creates a rule allowing ec2.run_instances with instance type "t3.micro" and region "us-east-1". Both must match — agent can only launch t3.micro in us-east-1.

**224. S3 bucket + prefix filter combination**
User creates a rule allowing s3.get_object with bucket "prod-data" and prefix "reports/". Agent can only read objects from prod-data/reports/.

---

## Content Filtering and Redaction

**225. Exclude emails containing specific keywords**
User creates an allow rule for list_emails with exclude filter "CONFIDENTIAL". Response has any email containing "CONFIDENTIAL" removed before reaching the agent.

**226. Redact SSN patterns from email content**
User creates an allow rule for read_email with redact pattern `\d{3}-\d{2}-\d{4}`. Any Social Security numbers in the email body are replaced with `[REDACTED]`.

**227. Redact credit card numbers**
User creates an allow rule with redact pattern `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`. Credit card numbers are redacted from all responses.

**228. Both exclude and redact on the same rule**
User creates an allow rule with exclude "PRIVATE" and redact `\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`. Emails containing "PRIVATE" are removed entirely, and in remaining emails, email addresses are redacted.

**229. Content filter on a deny rule has no effect**
User creates a deny rule with exclude and redact fields filled in. Since the operation is denied, the content filters are never applied — they only matter for allow rules that produce a response.

---

## Complex Multi-Policy Scenarios

**230. Two policies: one allows, one denies the same operation**
Role binds a connection to Policy A (allow list_emails) and Policy B (deny list_emails). CompositeEvaluator runs both. Policy B's deny wins — first-deny-wins semantics. Agent cannot list emails.

**231. Two policies: one allows with redaction, one allows without**
Role binds to Policy A (allow read_email, redact SSN) and Policy B (allow read_email, no redaction). Both allow, so redactions from both are merged. SSN patterns are still redacted.

**232. Three policies with different operation sets**
Role binds a connection to Policy A (allows list_emails, read_email), Policy B (allows drive.list_files, drive.get_file), Policy C (denies calendar.list_events, calendar.get_event). The composite evaluator handles all three. Note: scope is a UI-only category — the engine matches by operation name, not scope. Gmail and Drive reads are allowed because those operation names are in allow rules. Calendar is denied because those operation names are in deny rules.

**233. Policy with approval_required + policy with allow for same operation**
Role binds to Policy A (require_approval for send_email) and Policy B (allow send_email). CompositeEvaluator treats require_approval as more restrictive than allow. The operation requires approval even though one policy allows it.

**234. Policy chain where first policy allows but second requires approval**
Role binds to Policy A (allow all) and Policy B (require_approval for send_email). Composite evaluation: allow for most operations, require_approval for send_email. The more restrictive decision wins.

---

## Role + Connection + Policy Binding Combinations

**235. One role, two connections, same policy**
User creates a role with bindings: "work-gmail" → [read-only], "personal-gmail" → [read-only]. Agent can read emails from both accounts with the same policy restrictions.

**236. One role, two connections, different policies**
User creates a role: "work-gmail" → [read-only], "anthropic" → [sonnet-only]. Different policies for different connections. Agent can read work emails and use Sonnet for LLM calls.

**237. One role, one connection, multiple policies**
User creates a role: "work-gmail" → [read-only, drafter]. Both policies are evaluated via CompositeEvaluator. If read-only allows and drafter allows, the operation is allowed. If either denies, it's denied.

**238. Switch a token to a different role**
User wants to change an agent's permissions. Since tokens can't be edited, the user creates a new token with the desired role and revokes the old one. The agent must be configured with the new token.

---

## Token Expiry Scenarios

**239. Create token with 7-day expiry, use it on day 6**
Agent uses a 7-day token on day 6. The token is still valid — API calls succeed. On day 8, the same token returns 401.

**240. Create token with 30-day expiry, revoke it on day 5**
The token is revoked on day 5. Even though it wouldn't expire until day 30, revocation is immediate. API calls fail with 401 from day 5 onward.

**241. View expired tokens in the filter**
User created tokens with 24-hour expiry 3 days ago. Clicking the "Expired" filter shows these tokens. They still show the Revoke button (the button is shown for any non-revoked token regardless of expiry) and an "Active" badge even though they're expired. Clicking Revoke would mark them as revoked, moving them to the Revoked filter instead.

---

## Audit Log Deep Scenarios

**242. Audit entry for allowed operation includes duration**
Agent calls list_emails, which takes 150ms. The audit entry shows "allow" result and "150" in the Duration column.

**243. Audit entry for denied operation includes reason**
Agent calls send_email, denied by policy with reason "sending blocked". The audit entry shows "deny" result. The reason is stored in response_summary.

**244. Audit entry for approval-required operation**
Agent calls send_email requiring approval. The audit entry shows "approval_required" result with a yellow badge.

**245. Audit entries for built-in MCP tools**
Agent calls list_connections via MCP. An audit entry is logged with operation "list_connections", connection empty, and result "allow".

**246. Audit entries accumulate over time**
After many agent interactions, the audit log has thousands of entries. Pagination shows 100 per page. The user can filter and paginate to find specific events.

**247. Filter audit by date range**
User sets the "After" date to yesterday. Only entries from today are shown. Entries from earlier are filtered out.

**248. Audit entries survive server restart**
User restarts the server. All audit entries are preserved in SQLite. Navigating to the audit page shows the same entries as before the restart.

---

## Connection-Specific Scenarios

**249. Add OpenAI connection**
User goes to Connections > LLM API, fills in the OpenAI card with alias "openai", API key, and clicks Connect. The connection is created with target URL pointing to OpenAI's API.

**250. Add Gemini connection**
User fills in the Gemini card with alias "gemini" and API key. Connection is created with Google AI Studio endpoint.

**251. Add AWS Bedrock connection**
User fills in the Bedrock card with alias "bedrock", access key, secret key, and region. Connection is created with Bedrock endpoint including region-specific URL.

**252. Add OpenAI-compatible connection (Ollama)**
User fills in the "OpenAI-Compatible" card with alias "ollama", target URL "http://localhost:11434/v1", and optionally an API key. Connection is created pointing to the local Ollama server.

**253. Add Hyperstack connection**
User fills in the Hyperstack card with alias "hyperstack" and API key. Connection is created with the Hyperstack API endpoint.

**254. Connection deletion removes it from live connector cache**
User deletes a connection. The live connector (in-memory authenticated client) is immediately removed. If an agent tries to use it in the same second, the request fails — no stale cached connector is used.

**255. Google OAuth token refresh persists to database**
A Google connection's access token expires. The next API call triggers an automatic token refresh via the persistingTokenSource. The new access token is saved back to the connection's config in the database. On server restart, the fresh token is available.

---

## Settings Edge Cases

**256. Settings page shows no LLM connections when none exist**
User views Settings when no LLM-type connections have been created. The LLM Connection dropdown shows only "-- Select a connection --" with no other options. A hint tells the user to create an LLM connection first.

**257. Settings dropdown excludes Google connections**
User has a Google account connection and an Anthropic HTTP proxy connection. The Settings LLM dropdown shows only the Anthropic connection, not the Google one — Google connections are not LLM providers.

**258. Save settings shows success message**
User saves settings. The page reloads with query parameter `?saved=1` and a green "Settings saved successfully" message appears at the top.

---

## Approval Edge Cases

**259. Approve an item after the requesting agent's token was revoked**
Agent sends a request requiring approval. Admin revokes the agent's token. Admin then approves the pending request. The operation executes because the token was validated at the start of the request and is not re-checked after approval. The result is returned to the agent's still-open HTTP connection (if it hasn't timed out). This is a security concern — a revoked token's pending operations can still complete if approved.

**260. Multiple pending approvals from the same token**
Agent sends 3 operations requiring approval. All 3 appear as separate cards in the approvals page. Admin can approve or reject each independently.

**261. Approve an item, agent retries and gets the result**
Agent calls send_email (approval required). The API blocks on WaitForResolution. Admin clicks Approve. The WaitForResolution channel receives the resolved item. The API unblocks, executes the operation, and returns the result to the agent.

**262. Reject an item, agent gets rejection error**
Agent calls send_email (approval required). The API blocks. Admin clicks Reject. WaitForResolution returns the rejected item. The API returns 403 "approval request was rejected".

**263. Approval times out**
Agent calls send_email (approval required). Nobody approves within 5 minutes. WaitForResolution times out. The API returns 504 "approval request timed out". The pending item remains in the queue (status still "pending") and can still be approved later, but the original request already failed.

---

## Multi-Account Gmail Scenarios

**264. Two Google accounts, agent uses userId to select**
Admin creates connections "work" and "personal" (both Google type). A role binds both to a read-only policy. Agent calls `GET /gmail/v1/users/work/messages` to list work emails and `GET /gmail/v1/users/personal/messages` for personal.

**265. Agent uses "me" as userId with single Google connection**
Token has access to one Google connection. Agent calls `GET /gmail/v1/users/me/messages`. The "me" userId resolves to the only available Google connection.

**266. Agent uses "me" with multiple Google connections**
Token has access to two Google connections. Agent calls `GET /gmail/v1/users/me/messages`. The system uses the first (default) Google connection.

**267. Agent discovers available accounts via users endpoint**
Agent calls `GET /gmail/v1/users`. The response lists all Google connections the token has access to, with their aliases. This is a Sieve extension — not part of the standard Gmail API.

---

## HTTP Proxy Scenarios

**268. Proxy forwards GET request with credential substitution**
Agent sends `GET /proxy/anthropic/v1/models` with its Sieve token. The proxy strips the Sieve Authorization header, injects the real Anthropic API key from the connection config, and forwards the request to `https://api.anthropic.com/v1/models`. The response is passed back to the agent.

**269. Proxy forwards POST request with body**
Agent sends `POST /proxy/openai/v1/chat/completions` with a JSON body. The proxy forwards the request with the real OpenAI API key. The response is returned to the agent.

**270. Proxy request to unknown connection**
Agent sends a request to `/proxy/nonexistent/v1/test`. The API returns 403 because the connection doesn't exist or isn't in the token's role.

**271. Proxy applies policy before forwarding**
Agent sends `POST /proxy/anthropic/v1/messages` but the policy denies POST requests. The proxy returns 403 without ever contacting Anthropic.

---

## MCP Proxy Scenarios

**272. MCP proxy discovers upstream tools**
An MCP proxy connection is created pointing to an upstream MCP server. On first tools/list request, the proxy calls the upstream's tools/list, caches the results, and merges them into the token's tool list.

**273. MCP proxy forwards tool call with credentials**
Agent calls a tool via the MCP proxy. Sieve strips the agent's token, injects the upstream credentials, and forwards the JSON-RPC request. The response is passed back.

---

## Navigation Detail Scenarios

**274. Connections nav sub-items link to filtered views**
Clicking "Google" in the Connections nav submenu navigates to `/connections?type=google`. Clicking "Cloud" navigates to `/connections?type=cloud`. Each shows only the relevant connection type and creation forms.

**275. Policies nav sub-items link to scoped views**
Clicking "Gmail" under Policies in the nav navigates to `/policies?scope=gmail`. The page shows the policies table (filtered by scope if applicable) and the Gmail-specific rule builder.

**276. Policies nested nav: Google > Drive**
User expands Policies > Google > Drive in the nav. Navigates to `/policies?scope=drive`. The rule builder shows Drive-specific operations (list_files, get_file, upload_file, share_file) and Drive-specific filter fields.

**277. Policies nested nav: Cloud > AWS > EC2**
User expands Policies > Cloud > AWS > EC2 in the nav. Navigates to `/policies?scope=aws-ec2`. The rule builder shows EC2 operations and EC2-specific filters (instance type, region, max count).

---

## Rule Builder UI Interactions

**278. Selecting Gmail read operations shows from/subject/label filters**
User clicks Add Rule and checks "list_emails" and "read_email". The "From matches", "Subject contains", "Content contains", and "Label" filter fields become visible. Unchecking those operations hides the filters.

**279. Selecting send operations shows the "to" filter**
User checks "send_email". The "To matches" filter field becomes visible, allowing the user to restrict who the agent can email.

**280. Selecting "Run Script" action hides extras section, shows script fields**
User selects the "Run Script" radio button. The "Exclude content", "Redact patterns", and "Reason" fields disappear. The "Command" and "Script Path" fields appear.

**281. Selecting "Allow" action shows extras section**
User selects the "Allow" radio button. The "Exclude content", "Redact patterns", and "Reason" fields become visible. The script fields disappear.

**282. Selecting "Deny" action hides extras section**
User selects the "Deny" radio button. The extras section (exclude, redact, reason) is hidden because deny rules don't produce a response to filter.

**283. Default action dropdown starts at "Deny"**
User opens the policy create form. The default action dropdown is pre-set to "Deny" — fail-closed by default. The user must explicitly change it to "Allow" if they want a permissive default.

---

## Script Action Details

**284. Create a rule with script action pointing to a Python file**
User creates a rule with action "Run Script", command "python3", path "./policies/email_filter.py". When an agent triggers this rule, the script is executed with the request data on stdin. The script's exit code determines allow (0) or deny (non-zero), and stdout can contain response modifications.

**285. Script action with nonexistent script file**
User creates a rule pointing to a script file that doesn't exist. When the rule is triggered, the script fails to execute. The policy evaluator returns a deny decision (fail-closed).

**286. Script action with syntax error in script**
User creates a rule pointing to a Python script with a syntax error. The script exits with non-zero status. The policy evaluator treats this as deny.

---

## Data Persistence Scenarios

**287. Create all entity types, restart server, verify all persist**
User creates connections, policies, roles, tokens, submits approvals, and generates audit entries. Server is restarted. All connections, policies, roles, tokens, pending approvals, and audit entries are present in the database. Live connectors are re-initialized from stored configs.

**288. SQLite WAL mode enables concurrent reads during writes**
While an agent is actively making API calls (writing audit entries), an admin is browsing the audit log (reading). Both operations succeed concurrently thanks to WAL mode. No "database is locked" errors.

**289. Database file permissions are restricted**
The SQLite database file is created with 0600 permissions (owner read/write only). Other users on the system cannot read the file, which contains credentials and tokens.

---

## Error Recovery Scenarios

**290. Connection creation fails, user retries**
User submits a connection form. The server encounters a database error and returns 500. The user fixes the issue (e.g., restarts the database) and resubmits. The connection is created successfully.

**291. OAuth callback with duplicate state replay**
An attacker intercepts an OAuth callback URL and replays it. The state parameter has already been consumed (deleted from pendingOAuth map). The server returns "invalid or expired state." No connection is created.

**292. Form submission with invalid JSON in bindings**
User (or a malicious client) submits a role creation form with `bindings` field set to invalid JSON like `{broken`. The server returns 400 "invalid bindings JSON." No role is created.

**293. Form submission with invalid JSON in policy config**
User submits a policy with `policy_config` set to invalid JSON. The server returns 400 "invalid policy config JSON." No policy is created.

---

## Agent Experience Scenarios

**294. Agent gets clear error message on policy denial**
Agent calls send_email, denied by policy with reason "sending is not permitted for this agent". The API response body contains: `{"error": "policy denied: sending is not permitted for this agent"}`. The agent can show this to the user.

**295. Agent discovers it has no access to a connection**
Agent calls list_connections. The response shows only the connections it has access to. It does not see connections outside its role. There is no way for the agent to discover what connections exist beyond its scope.

**296. Agent inspects its own policy via MCP**
Agent calls get_my_policy via MCP. The response shows the full policy for each connection binding: rule list, default action, filter settings. The agent can use this to understand what it's allowed to do before attempting operations.

**297. Agent proposes a more permissive policy**
Agent determines it needs send_email access (which its current policy denies). It calls propose_policy with a modified policy that includes an allow rule for send_email. The proposal goes to the admin's approval queue with the agent's description of why it needs the access.

---

## Complex Workflow Scenarios

**298. Principle of least privilege setup**
Admin creates a connection to Gmail. Creates a "triage" policy (allow list and label, deny read content and send). Creates a role "email-triage-bot" binding Gmail to triage. Creates a token. The agent can label and archive emails based on subject lines but cannot read email bodies or send messages.

**299. Gradual permission escalation via policy updates**
Admin starts an agent with a read-only policy. After observing it works correctly in the audit log, the admin edits the policy to add draft creation. After more observation, adds send_email with require_approval. Permissions are expanded incrementally without creating new tokens.

**300. Emergency revocation of all agent access**
An agent is behaving unexpectedly. Admin navigates to Tokens, revokes the agent's token. The agent is immediately cut off from all API access. Admin checks the audit log to review what the agent did. Admin can later create a new token with more restrictive policies.

**301. Rotating credentials without agent downtime**
Admin needs to rotate an API key for the Anthropic connection. Admin creates a second connection "anthropic-v2" with the new key. Edits the role to swap the binding from "anthropic" to "anthropic-v2". All tokens using that role immediately use the new credentials. Admin deletes the old "anthropic" connection.

**302. Audit investigation after an incident**
Something went wrong — an important email was sent. Admin opens the audit log, filters by operation "send_email", and finds the entry. The entry shows which token sent it, when, to what connection, and how long it took. The admin can trace back from the token to its role to its policy to understand how the send was authorized.

**303. Multi-agent setup with shared and private access**
Admin creates a "shared-data" role (read-only Gmail + read-only Drive) and a "deploy" role (Gmail + AWS EC2). Creates token A with "shared-data" for the data analysis agent. Creates token B with "deploy" for the deployment agent. Each agent has distinct, scoped access. Changing the "shared-data" role's policies affects agent A but not agent B.

**304. Temporary elevated access via token expiry**
Admin creates a role with full Gmail access (including send). Creates a token with 1-hour expiry for an agent that needs to send a report. After 1 hour, the token expires automatically. No manual revocation needed.

---

## Connection Update Scenarios

**305. Google OAuth token expires and auto-refreshes**
A Google connection's access token expires (typically after 1 hour). An agent makes an API call. The persistingTokenSource detects the expired token, uses the refresh token to get a new access token, and persists it to the database. The API call succeeds transparently.

**306. Google OAuth refresh token is revoked by the user**
The user revokes Sieve's access in their Google Account settings. The next agent API call triggers a refresh attempt, which fails. The connector returns an error. The admin must re-authenticate via the OAuth flow (delete and re-add the connection).

---

## Concurrent Access Scenarios

**307. Two agents using the same token simultaneously**
Two agent instances share one token. Both make API calls at the same time. Each request gets its own policy evaluator. Both succeed (or fail) independently. The token is not a mutex — it supports concurrent use.

**308. Admin edits policy while agent is mid-request**
Agent sends a request. While the connector is executing the operation, admin saves a policy change. The in-flight request completes with the old policy (evaluator was built before the change). The next request uses the new policy.

**309. Two admins on different pages making changes**
Admin A is editing a role. Admin B is editing a policy referenced by that role. Both save at the same time. Both writes succeed independently — there is no transaction across entities. The final state reflects both changes.

---

## Batch and Scale Scenarios

**310. Hundreds of audit entries with pagination**
The audit log has 5000 entries. The page shows 100 at a time with pagination. User navigates to page 25. The correct entries are shown with all filters preserved.

**311. Many connections in the dropdown**
Admin has created 50 connections. The role binding connection dropdown shows all 50, ordered by creation time. The dropdown is scrollable.

**312. Many policies in the checkbox list**
Admin has created 100 policies. The role binding policy checkbox list shows all 100. The list has overflow scrolling (`max-h-32 overflow-y-auto`).

**313. Many tokens in the table**
Admin has created 200 tokens across different roles. The tokens table shows all 200. Filtering by "active" narrows it to currently valid tokens.

---

## Edge Cases in Policy Evaluation

**314. Rule with empty operations list matches everything**
User creates a rule with action "deny" but checks no operation checkboxes. The rule's match has an empty operations list. Because the operations check is skipped when the list is empty, this rule matches every operation. If it's a deny rule, it effectively denies everything. This is a dangerous footgun — an empty operations list is a wildcard, not a no-op.

**315. Rule with no match criteria matches everything**
A rule is created with no match criteria at all (no operations, no filters). This rule matches every operation. If it's an allow rule at the top, everything is allowed. If it's a deny rule at the top, everything is denied.

**316. Default action is the last resort**
Agent calls an operation that doesn't match any rule. The default action (deny or allow) determines the outcome. If default is deny, the operation is denied. If allow, it's allowed.

**317. First matching rule wins, subsequent rules are skipped**
Policy has: Rule 1 (allow list_emails), Rule 2 (deny list_emails). Agent calls list_emails. Rule 1 matches first → allowed. Rule 2 is never evaluated. (This is opposite to the composite evaluator behavior, which is first-deny-wins across multiple policies.)

---

## Negative Testing

**318. SQL injection in filter fields**
User types `'; DROP TABLE audit_log; --` in the audit operation filter. The filter uses parameterized queries. The SQL injection attempt is treated as a literal string. No tables are dropped. The filter returns zero results (no operation matches that string).

**319. XSS in connection display name**
User creates a connection with display name `<script>alert('xss')</script>`. The template engine (Go html/template) auto-escapes HTML entities. The script tag is rendered as text, not executed.

**320. Extremely long policy name**
User creates a policy with a 10,000-character name. The name is stored in the database. The UI may render it awkwardly (overflowing the table cell) but no crash occurs.

**321. Unicode in all text fields**
User creates a connection with display name "Gmail Travail 🇫🇷", a policy named "politique de lecture", and a role named "rôle d'agent". All UTF-8 characters are stored and displayed correctly.

**322. Empty string token name**
User submits the token creation form with an empty name field. The browser's `required` attribute prevents submission. If somehow bypassed, the server's form parsing accepts empty strings — this is a potential gap that should return 400.

---

## Responsiveness and Visual Feedback

**323. Successful form submission redirects to the list page**
After creating a token, the page redirects to `/tokens` showing the token list and the plaintext alert. After creating a role, the page redirects to `/roles`. After creating a policy, the page redirects to `/policies`.

**324. Error on form submission shows error message**
If a form submission fails (e.g., duplicate name), the server returns an HTTP error. The browser shows the error message. The user can go back and fix their input.

**325. Delete action redirects back to list**
After deleting a connection/role/policy, the page redirects to the respective list page. The deleted item is no longer visible.

**326. Approval approve/reject redirects back to approvals**
After clicking Approve or Reject, the page redirects to `/approvals`. The resolved item is gone from the pending list.

**327. Settings save shows success message**
After saving settings, the page reloads with `?saved=1` and shows a green "Settings saved successfully" message.

---

## Time-Based Display

**328. "Just now" for recent timestamps**
A connection created seconds ago shows "just now" in the Added column. An audit entry from moments ago shows "just now" in the Time column.

**329. "5 minutes ago" for slightly older items**
A token created 5 minutes ago shows "5 minutes ago" in the Created column.

**330. Relative time display for old items**
A policy created 3 months ago shows "3mo ago" in the Created column. The timeAgo function always returns relative time — it never switches to absolute date formatting, even for very old entries.

---

## Two-Port Architecture

**331. Web UI runs on port 19816**
Admin accesses the web UI at `https://localhost:19816`. All connection management, policy editing, token creation, and approval handling happens on this port.

**332. API/MCP runs on port 19817**
Agents connect to `http://localhost:19817` for REST API calls, Gmail-compatible API calls, proxy requests, and MCP tool calls. This port requires a valid bearer token for all requests.

**333. Agent cannot access web UI port**
An agent with a Sieve token cannot access the web UI endpoints (different port). Even if an agent somehow reaches the web UI port, the approval endpoints reject agent tokens (defense-in-depth via rejectIfAgentToken).

**334. Admin does not need a token for the web UI**
The web UI port has no authentication — it's assumed to be accessible only to trusted operators (e.g., behind a firewall or on localhost). All admin actions are performed without credentials.

---

## Docker and Deployment

**335. Docker container starts both servers**
The Docker container runs the Sieve binary which starts both the web UI server (19816) and the API/MCP server (19817). Both ports are exposed.

**336. SQLite database persists via Docker volume**
The database file is stored in a Docker volume mount. Stopping and restarting the container preserves all data.

**337. Python scripts available in Docker**
The Docker image includes Python (via uv) for policy script execution. Scripts in the policies directory are executable from within the container.

---

## CLI Commands

**338. CLI serve starts the servers**
Running `sieve serve` starts both the web UI and API servers. The command blocks until the process is killed.

**339. CLI connection add (non-interactive)**
Running `sieve connection add --id anthropic --type http_proxy --display-name Claude --target-url https://api.anthropic.com --auth-header x-api-key --auth-value sk-ant-...` creates a connection without the web UI.

**340. CLI token create**
Running `sieve token create --name deploy-bot --role project-x-dev` creates a token and prints the plaintext to stdout.

**341. CLI role create**
Running `sieve role create --name read-only-agent --binding work-gmail:read-only` creates a role with the specified binding.

**342. CLI policy create**
Running `sieve policy create --name email-reader --config '{"rules": [...], "default_action": "deny"}'` creates a policy from a JSON config.

---

## MCP Server Protocol Details

**343. Invalid JSON-RPC version**
Agent sends a JSON-RPC request with `"jsonrpc": "1.0"`. The MCP server returns error code -32600 "invalid jsonrpc version".

**344. Unknown JSON-RPC method**
Agent sends a request with method "resources/list" (not implemented). The MCP server returns error code -32601 "method not found: resources/list".

**345. Invalid params for tools/call**
Agent sends tools/call with malformed params (not a valid ToolCallParams object). The MCP server returns error code -32602 "invalid params".

**346. GET request to MCP endpoint**
A client sends a GET request to the MCP endpoint. The server returns error code -32600 "only POST is supported".

**347. Connection argument for multi-connection tool call**
Agent with multiple connections calls a tool with an explicit `"connection": "work-gmail"` argument. The MCP server uses the specified connection instead of guessing from the tool name prefix.

---

## Response Filter Application

**348. Response filter excludes matching items from list**
Policy has an allow rule for list_emails with exclude "SPAM". The connector returns 10 emails, 3 containing "SPAM". The response filter removes those 3. The agent receives 7 emails.

**349. Response filter redacts patterns in individual items**
Policy has an allow rule for read_email with redact `\d{3}-\d{2}-\d{4}`. The email body contains "SSN: 123-45-6789". The agent receives the email with body "SSN: [REDACTED]".

**350. Response filter script processes the response**
Policy has an allow rule with a response filter script. After the connector returns data, the script receives the response JSON on stdin and outputs modified JSON on stdout. The agent receives the script's output.

**351. Multiple response filters are applied in sequence**
A rule has both exclude and redact filters, and there are global response filters on the policy. All filters are collected and applied in sequence: rule-level exclude → rule-level redact → global filters.

---

## Composite Evaluator Detailed Behavior

**352. Composite evaluator merges redaction lists**
Policy A has redact `\d{3}-\d{2}-\d{4}`. Policy B has redact `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`. Composite evaluator merges both redaction patterns. Both SSNs and credit card numbers are redacted.

**353. Composite evaluator short-circuits on first deny**
Policy A denies the operation. Policy B would allow it. The composite evaluator evaluates Policy A first, gets deny, and returns immediately without evaluating Policy B.

**354. Composite evaluator collects all allow decisions' filters**
Policy A allows with redaction. Policy B allows with exclude filter. Both are evaluated. The composite evaluator merges: allow decision with both redaction patterns and exclude filters applied.

**355. Single policy bypasses composite evaluator**
A role binding has only one policy ID. The system creates a direct evaluator (not wrapped in CompositeEvaluator). This is an optimization but behavior is identical.

---

## Per-Scope Policy Form Differences

**356. Gmail scope shows email-specific operations and filters**
Navigating to `/policies?scope=gmail` shows: list_emails, read_email, read_thread, get_attachment, create_draft, update_draft, reply, send_email, send_draft, add_label, remove_label, archive, list_labels. Filter fields include from, to, subject, content, label.

**357. LLM scope shows provider checkboxes instead of operation checkboxes**
Navigating to `/policies?scope=llm` shows provider checkboxes (Anthropic, OpenAI, Gemini, Bedrock) instead of individual operation checkboxes. Operations are auto-generated based on selected providers.

**358. HTTP Proxy scope shows HTTP method checkboxes**
Navigating to `/policies?scope=http_proxy` shows method checkboxes (GET, POST, PUT, DELETE, PATCH) and path/body filter fields.

**359. Each AWS scope shows service-specific operations**
EC2 scope shows ec2.* operations. S3 scope shows s3.* operations. Each has service-specific filter fields (instance type, bucket name, etc.).

**360. Drive scope shows file operations and MIME/owner filters**
Navigating to `/policies?scope=drive` shows drive.list_files, drive.get_file, drive.download_file, drive.upload_file, drive.share_file. Filters include MIME type, owner email, folder path, shared status.

---

## Cleanup and Maintenance

**361. Audit log cleanup removes old entries**
Admin (via CLI or scheduled job) calls audit.Cleanup(30). All entries older than 30 days are deleted. Recent entries are preserved.

**362. Presets are re-seeded on server start**
Server starts and calls SeedPresets(). If "read-only" was deleted, it's re-created. If "read-only" exists, its config is updated to the latest version (e.g., adding new scope field).

**363. Database migration handles legacy schema**
On first start after an upgrade, the database migration runs. Old schemas (gmail → google connector type, policy_id → policy_ids, connections+policy_ids → role_id) are migrated automatically. No manual intervention needed.

**364. Orphaned bindings don't crash the system**
A role references a deleted connection and a deleted policy. The system handles this gracefully: the connection is skipped when listing tools, and the policy evaluator returns an error that results in a deny. No panics.

**365. Server handles graceful shutdown**
Admin sends SIGTERM to the server. Open database connections are closed cleanly. In-flight requests complete. Pending approval waits are cancelled.

**366. WAL checkpoint on database close**
When the server shuts down, the SQLite WAL file is checkpointed (merged into the main database file). This ensures data is not lost in the WAL.

**367. File permissions on new database**
When the server creates a new database file, it sets permissions to 0600. Only the owner (the Sieve process user) can read or write the file.

---

## Match Field Enforcement (Bugs found from patterns)

These stories were added after discovering that many UI filter fields were not enforced by the policy engine. Stories marked [FIXED] have been implemented. Stories marked [BUG] describe behavior that is currently broken.

**368. [FIXED] To field restricts who agents can email**
Admin creates a policy allowing send_email with To filter "*@company.com". Agent calls send_email with to="external@gmail.com". The engine checks the To match field and denies the request because the recipient doesn't match the glob pattern. Agent calls send_email with to="alice@company.com" — allowed.

**369. [FIXED] Model field restricts which LLM models agents can use**
Admin creates a policy allowing LLM calls with Model filter "claude-*". Agent calls with model="claude-sonnet-4-20250514" — allowed. Agent calls with model="gpt-4o" — denied. The glob pattern supports wildcard prefix and suffix.

**370. [FIXED] MaxTokens field enforces output token limits**
Admin creates a policy allowing LLM calls with MaxTokens 1024. Agent calls with max_tokens=500 — allowed. Agent calls with max_tokens=2000 — denied. The value is compared numerically regardless of whether it arrives as int, float64, or string.

**371. [FIXED] Path field restricts HTTP proxy endpoints**
Admin creates a policy allowing HTTP proxy requests with Path filter "/v1/messages*". Agent calls /v1/messages — allowed. Agent calls /v2/chat — denied. The glob pattern supports prefix and suffix wildcards.

**372. [FIXED] Bucket field restricts S3 access**
Admin creates a policy allowing S3 operations with Bucket filter "prod-*". Agent accesses prod-data — allowed. Agent accesses dev-data — denied.

**373. [FIXED] Content filtering action ("filter") is recognized by engine**
Admin creates a policy with an allow rule for list_emails and sets "Exclude content" to "CONFIDENTIAL". The UI sets action="filter". The engine recognizes "filter" as equivalent to "allow" and returns an allow decision with the ResponseFilter attached. The caller applies the filter to the response.

**374. [FIXED] Policy edit page loses non-Gmail match fields on save**
Admin creates a policy for LLM scope with model="claude-*" and max_tokens=1024. Admin later clicks Edit on this policy. The edit page loads but the model and max_tokens fields are empty — the rule loader JS (policy_edit.html lines 651-658) only restores operations, from, subject, content, and labels. If the admin saves without noticing, the model and max_tokens restrictions are silently lost. The policy becomes more permissive than intended.

**375. [FIXED] Policy edit page loses AWS/Drive/Calendar/People/Sheets/Docs filter fields**
Admin creates a policy for EC2 with instance_type="t3.micro" and region="us-east-1". Admin edits the policy. The instance_type and region fields are empty on the edit page. Saving silently removes the restrictions.

**376. [FIXED] Policy edit prepareSubmit() doesn't map most match fields**
The policy_edit.html prepareSubmit() function only maps to, from, subject, content, labels to the match object. It does NOT map: model, providers, path, body_contains, max_tokens, max_cost, instance_type, region, bucket, key_prefix, or any other scope-specific fields. Even if the edit page restored these fields visually, they would be dropped on save.

**377. [FIXED] InstanceType field restricts EC2 instance launches**
Admin creates a policy allowing ec2.run_instances with InstanceType "t3.micro". Agent tries to launch a c5.xlarge — denied. Agent launches a t3.micro — allowed. Comparison is case-insensitive.

**378. [FIXED] Region field restricts AWS operations to specific regions**
Admin creates a policy allowing EC2 operations with Region "us-east-1". Agent tries to operate in eu-west-1 — denied. Agent operates in us-east-1 — allowed.

**379. [FIXED] KeyPrefix field restricts S3 object access by path**
Admin creates a policy allowing S3 operations with KeyPrefix "public/". Agent accesses key "public/data.csv" — allowed. Agent accesses key "private/secrets.json" — denied. Uses prefix matching, not glob.

**380. [FIXED] MaxCost field enforces per-request cost limits**
Admin creates a policy allowing LLM calls with MaxCost 0.05. Agent sends a request with estimated_cost=0.03 — allowed. Agent sends with estimated_cost=0.10 — denied.

**381. [FIXED] Providers field restricts which LLM providers are allowed**
Admin creates a policy allowing LLM calls with Providers ["anthropic", "openai"]. Agent calls with provider="anthropic" — allowed. Agent calls with provider="gemini" — denied.

**382. [FIXED] BodyContains field restricts HTTP proxy by request body content**
Admin creates a policy allowing HTTP POST with BodyContains filter. The engine checks if the request body parameter contains the specified string. This can be used to block requests containing certain patterns.

---

## UI-to-Engine Data Loss Bugs

These stories describe bugs where the UI collects data but it's lost during submission or editing.

**383. [FIXED] Extended thinking filter is stored but not enforced**
Admin creates an LLM policy with extended_thinking="disabled". The UI saves this in the JSON via prepareSubmit(). But RuleMatch has no ExtendedThinking field and matches() never checks it. The filter has no effect.

**384. [FIXED] System prompt filter is stored but not enforced**
Admin creates an LLM policy with system_prompt_contains="you are a helpful assistant". Stored in JSON but never checked by the engine.

**385. [FIXED] Temperature filter is stored but not enforced**
Admin creates an LLM policy with max_temperature=0.5. Stored in JSON as match.max_temperature but RuleMatch has no MaxTemperature field.

**386. [FIXED] JSON mode filter is stored but not enforced**
Admin creates an OpenAI policy with json_mode="required". Stored but never checked.

**387. [FIXED] Grounding filter is stored but not enforced**
Admin creates a Gemini policy with grounding="enabled". Stored but never checked.

**388. [FIXED] Safety threshold filter is stored but not enforced**
Admin creates a Gemini policy with safety_threshold="high". Stored but never checked.

**389. [FIXED] Drive MIME type filter is stored but not enforced**
Admin creates a Drive policy with mime_type="application/pdf". Stored in JSON but never checked by the engine. Agent can download any file type.

**390. [FIXED] Drive owner filter is stored but not enforced**
Admin creates a Drive policy with owner="*@company.com". Stored but never checked.

**391. [FIXED] Drive shared status filter is stored but not enforced**
Admin creates a Drive policy with shared_status="owned by me". Stored but never checked.

**392. [FIXED] Calendar ID filter is stored but not enforced**
Admin creates a Calendar policy with calendar_id="work@group.calendar.google.com". Stored but never checked. Agent can access any calendar.

**393. [FIXED] Calendar attendee filter is stored but not enforced**
Admin creates a Calendar policy with attendee="*@company.com". Stored but never checked. Agent can invite anyone.

**394. [FIXED] People contact group filter is stored but not enforced**
Admin creates a Contacts policy with contact_group="myContacts". Stored but never checked.

**395. [FIXED] People allowed fields filter is stored but not enforced**
Admin creates a Contacts policy with allowed_fields="names,emailAddresses". Stored but never checked. Agent sees all contact fields.

**396. [FIXED] Sheets spreadsheet ID filter is stored but not enforced**
Admin creates a Sheets policy with spreadsheet_id="abc123". Stored but never checked. Agent can access any spreadsheet.

**397. [FIXED] Sheets range filter is stored but not enforced**
Admin creates a Sheets policy with range_pattern="Sheet1!A:Z". Stored but never checked.

**398. [FIXED] Docs document ID filter is stored but not enforced**
Admin creates a Docs policy with document_id="doc123". Stored but never checked.

**399. [FIXED] Docs title filter is stored but not enforced**
Admin creates a Docs policy with title_contains="Meeting Notes". Stored but never checked.

**400. [FIXED] EC2 max count filter is stored but not enforced**
Admin creates an EC2 policy with max_count=5. Stored but never checked. Agent can launch unlimited instances.

**401. [FIXED] EC2 AMI filter is stored but not enforced**
Admin creates an EC2 policy with ami="ami-0abcdef*". Stored but never checked.

**402. [FIXED] EC2 VPC/subnet filter is stored but not enforced**
Admin creates an EC2 policy with vpc="vpc-abc123". Stored but never checked.

**403. [FIXED] EC2 tag filter is stored but not enforced**
Admin creates an EC2 policy with tag="env=dev". Stored but never checked.

**404. [FIXED] EC2 allowed ports filter is stored but not enforced**
Admin creates an EC2 policy with ports="443,8080". Stored but never checked. Agent can open any port.

**405. [FIXED] EC2 CIDR filter is stored but not enforced**
Admin creates an EC2 policy with cidr restriction to block 0.0.0.0/0. Stored but never checked. Agent can make security groups publicly accessible.

**406. [FIXED] Lambda function name filter is stored but not enforced**
Admin creates a Lambda policy with function_name="my-function". Stored but never checked.

**407. [FIXED] SES recipient filter is stored but not enforced**
Admin creates an SES policy with recipient="*@company.com". Stored but never checked. Agent can email anyone via SES.

**408. [FIXED] SES sender identity filter is stored but not enforced**
Admin creates an SES policy with sender_identity="noreply@company.com". Stored but never checked.

**409. [FIXED] DynamoDB table name filter is stored but not enforced**
Admin creates a DynamoDB policy with table_name="users". Stored but never checked. Agent can access any table.

**410. [FIXED] DynamoDB index filter is stored but not enforced**
Admin creates a DynamoDB policy with index_name="email-index". Stored but never checked.

**411. [FIXED] Hyperstack flavor filter is stored but not enforced**
Admin creates a Hyperstack policy with flavor="a100". Stored but never checked.

**412. [FIXED] Hyperstack max VMs filter is stored but not enforced**
Admin creates a Hyperstack policy with max_vms=3. Stored but never checked. Agent can create unlimited VMs.

---

## MCP Tool Name Collision Bugs

**413. [KNOWN] Two connections of the same connector type produce duplicate tool names**
Admin creates two Google connections "work" and "personal". A role binds both. MCP tools/list prefixes tools with the connector type: "google_list_emails" for both. This produces duplicate tool names — the agent can only call one, and which one depends on the iteration order of ConnectionIDs().

**414. Tool name prefix uses connector type, not connection ID**
When multiConn is true, the tool name prefix is `conn.ConnectorType + "_"` (e.g., "google_"). Two connections of the same type (e.g., two Google accounts) get the same prefix. The agent must use the explicit "connection" argument to disambiguate, but the tool definitions don't explain which connection each tool targets.

---

## Edit Page Data Restoration Bugs

**415. [FIXED] Editing a policy with "to" match loses the to field**
Admin creates a Gmail policy with to="*@company.com". Admin clicks Edit. The rule loader (policy_edit.html line 651-658) does not restore `r.match.to` into `uiRule.to`. The to field is empty. Saving loses the restriction.

**416. [FIXED] Editing a policy with "model" match loses the model field**
Admin creates an LLM policy with model="claude-*". Admin edits. The model field is empty because the loader doesn't restore it. Saving makes the policy allow any model.

**417. [FIXED] Editing a policy with "providers" match loses the providers**
Admin creates an LLM policy allowing only Anthropic. Admin edits. The provider checkboxes are unchecked because the loader doesn't restore them. Saving makes the policy allow all providers.

**418. [FIXED] Editing a policy with "path" match loses the path field**
Admin creates an HTTP proxy policy with path="/v1/messages*". Admin edits. The path field is empty. Saving allows all paths.

**419. [FIXED] Editing a policy with any AWS/Drive/Calendar match fields loses them all**
Any scope-specific match field (instance_type, region, bucket, calendar_id, spreadsheet_id, etc.) is lost when the policy is edited because the rule loader doesn't restore these fields from the match object.

---

## Numeric and Type Coercion Edge Cases

**420. MaxTokens arrives as string from form submission**
The HTML number input sends values as strings in form data. The JSON serialization in prepareSubmit() uses parseInt(), which produces a number. But if a policy is created via CLI with max_tokens as a string "1024", the matches() function must handle string comparison. Verify the engine handles int, float64, and string representations.

**421. MaxCost arrives as string "0.05" from form**
Same issue for float values. prepareSubmit() uses parseFloat(), but CLI-created policies may have string values. The matches() function must handle both.

**422. MaxCount for EC2 is stored but not enforced**
Even though instance_type and region are now enforced, max_count (a numeric field) is not in RuleMatch and not checked by matches(). An agent can launch unlimited instances of the allowed type.

---

## Glob Matching Edge Cases

**423. Glob with * in the middle is not supported**
Model filter "claude-*-latest" (wildcard in the middle) only supports prefix-* and *-suffix patterns. The middle wildcard doesn't match. Admin expects "claude-sonnet-4-latest" to match but it doesn't.

**424. Multiple wildcards in the same pattern are not supported**
Path filter "*/v1/*" doesn't work as expected. Only single leading or trailing * is implemented. Admin must use exact patterns or single-wildcard patterns.

**425. Case sensitivity in glob matching varies by field**
From and To use ToLower for case-insensitive matching. Model uses ToLower. But Path does NOT — it's case-sensitive. Bucket uses ToLower. InstanceType uses EqualFold. There's no consistent pattern — admins can't predict whether a given field is case-sensitive.

---

## Provider Context Missing from Requests

**426. [FIXED] Provider field requires agents to include it in params**
The Providers match field checks params["provider"]. For native API/MCP calls, the agent must include "provider" in the request params. For HTTP proxy calls, the proxy now parses the JSON request body and merges top-level fields into policy params, so if the LLM request body contains "provider", it will be matched.

**427. [FIXED] HTTP proxy now parses request body into policy params**
The HTTP proxy handler now reads the request body, parses it as JSON, and merges top-level fields (model, max_tokens, etc.) into the PolicyRequest params before evaluation. The body is then restored for forwarding. This means LLM-specific policy fields (model, max_tokens, max_cost) are enforced for proxy requests.

---

## Approval Queue Integrity

**428. Pending approvals survive server restart**
Admin submits operations requiring approval. Server restarts. The pending items are in the database. However, the WaitForResolution channels are in-memory — the blocked API calls are gone. The pending items remain pending forever unless the admin manually approves or rejects them.

**429. Stale pending approvals accumulate**
If agents frequently trigger approval_required and admins don't respond, pending items accumulate indefinitely. There is no auto-rejection timeout, no cleanup, and no pagination on the approvals page. Eventually the page becomes unusable.

**430. Approvals page has no history view**
After approving or rejecting items, they disappear from the pending view. There is no way to see past approval decisions — no "resolved" tab or history view. The only record is in the audit log (if the operation was logged).

---

## Security Gaps

**431. [KNOWN] No token re-validation after approval wait**
Agent submits send_email requiring approval. Admin revokes the token. Admin approves the operation. The operation executes because the token was validated once at request start and never re-checked. The agent's revoked token completed an operation.

**432. Web UI has no authentication**
The web UI on port 19816 has no login, session management, or access control. Anyone who can reach the port can create/delete connections, tokens, roles, and policies, approve operations, and view credentials. In production, the port must be behind a firewall or VPN.

**433. OAuth state stored in memory only**
Pending OAuth flows are stored in an in-memory map. If the server restarts during an OAuth flow, the callback fails with "invalid or expired state". The user must retry. This is a usability issue, not a security bug.
