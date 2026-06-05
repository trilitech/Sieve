import { test, expect } from '@playwright/test';
import { startTestServer, stopTestServer, apiCall, ServerInfo } from './helpers';

let s: ServerInfo;

test.beforeAll(async () => {
  s = await startTestServer();
});

test.afterAll(async () => {
  stopTestServer(s);
});

// ─── Workflow 1: Full policy lifecycle ───────────────────────────────────────
// Create a policy with rules via the UI, verify it persists by editing it,
// then use it in a role + token and verify the API enforces it.

test.describe('Policy lifecycle', () => {
  test('create policy with allow/deny rules, verify rules persist in edit page', async ({ page }) => {
    // Navigate to Gmail-scoped policy creator.
    await page.goto(`${s.web_url}/policies?scope=gmail`);

    // Fill the policy name.
    await page.fill('input[name="name"]', 'e2e-lifecycle-policy');

    // Add a rule: allow list_emails.
    await page.locator('#btn-add-rule').click();
    // Check "list_emails" operation checkbox.
    await page.locator('input.rule-op[value="list_emails"]').check();
    // Select "allow" action (should be default but be explicit).
    await page.locator('input[name="rule-action"][value="allow"]').check();
    // Click the "Add" button inside the add-rule form.
    // The second "Add Rule" button is the one inside the inline form.
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();

    // Add a second rule: deny send_email.
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="send_email"]').check();
    await page.locator('input[name="rule-action"][value="deny"]').check();
    // Note: reason field is inside extras-section which is hidden for deny action.
    // This is fine — deny rules don't need a reason in the UI.
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();

    // Set default action to deny.
    await page.locator('#default-action').selectOption('deny');

    // Submit the form.
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Verify the policy appears in the list.
    await page.goto(`${s.web_url}/policies`);
    await expect(page.locator('td:has-text("e2e-lifecycle-policy")')).toBeVisible();

    // Click edit to verify rules persisted.
    await page.locator('tr:has-text("e2e-lifecycle-policy") a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/policies\/.*\/edit/);

    // The edit page should show the policy name.
    const nameVal = await page.locator('input[name="name"]').inputValue();
    expect(nameVal).toBe('e2e-lifecycle-policy');

    // Verify the rules are visible on the page (rule summary text).
    const pageText = await page.textContent('body');
    expect(pageText).toContain('list_emails');
    expect(pageText).toContain('send_email');
    expect(pageText).toContain('allow');
    expect(pageText).toContain('deny');
  });

  test('edit existing policy name, verify change persists', async ({ page }) => {
    // Create a policy first.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 'rename-me-policy');
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Find the policy and edit it.
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("rename-me-policy") a:has-text("Edit")').click();

    // Change the name.
    await page.fill('input[name="name"]', 'renamed-policy');
    await page.locator('form button[type="submit"]').click();

    // Verify the new name appears, old name doesn't.
    await page.goto(`${s.web_url}/policies`);
    await expect(page.locator('td:has-text("renamed-policy")')).toBeVisible();
    await expect(page.locator('td:has-text("rename-me-policy")')).not.toBeVisible();
  });

  test('delete policy, verify it disappears', async ({ page }) => {
    // Create a throwaway policy.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 'delete-me-policy');
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    await page.goto(`${s.web_url}/policies`);
    await expect(page.locator('td:has-text("delete-me-policy")')).toBeVisible();

    // Delete it.
    page.on('dialog', d => d.accept());
    await page.locator('tr:has-text("delete-me-policy") form[action*="/delete"] button').click();

    await page.goto(`${s.web_url}/policies`);
    await expect(page.locator('td:has-text("delete-me-policy")')).not.toBeVisible();
  });

  test('load preset populates rules', async ({ page }) => {
    await page.goto(`${s.web_url}/policies?scope=gmail`);

    // Select a preset.
    await page.locator('#preset-select').selectOption({ index: 1 });
    await page.locator('button:has-text("Load")').first().click();

    // After loading, rules should appear on the page.
    const rulesArea = page.locator('#rules-list, .rules-container, [id*="rule"]');
    // The page text should now contain operation names from the preset.
    const bodyText = await page.textContent('body');
    // read-only preset allows list_emails, read_email, etc.
    expect(bodyText).toContain('list_emails');
  });
});

// ─── Workflow 2: Role + Token + API enforcement ─────────────────────────────
// Create a role binding a connection to a policy, create a token with that role,
// then verify the API actually enforces the policy.

test.describe('Role-Token-API enforcement', () => {
  test('create role with connection+policy binding, create token, verify API enforces policy', async ({ page }) => {
    // Step 1: Create a restrictive policy (allow list_emails, deny everything else).
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 'e2e-enforce-policy');
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="list_emails"]').check();
    await page.locator('input[name="rule-action"][value="allow"]').check();
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Step 2: Create a role binding test-conn to this policy.
    // Use JavaScript to directly set the bindings since the dynamic form
    // uses JS event listeners that are hard to drive via Playwright selectors.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'e2e-enforce-role');

    // Click "+ Add connection" to render the binding form.
    await page.locator('text=Add connection').click();

    // Select connection from the rendered dropdown.
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    // Trigger the change event so JS updates the bindings array.
    await connSelect.dispatchEvent('change');

    // Check the e2e-enforce-policy checkbox.
    const policyCheckbox = page.locator('label:has-text("e2e-enforce-policy") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');

    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Verify role was created with binding.
    await page.goto(`${s.web_url}/roles`);
    await expect(page.locator('td:has-text("e2e-enforce-role")')).toBeVisible();

    // Step 3: Create a token with this role.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'e2e-enforce-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("e2e-enforce-role")');
    const roleValue = await roleOption.getAttribute('value');
    expect(roleValue).toBeTruthy();
    await roleSelect.selectOption(roleValue!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    // Capture the plaintext token.
    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    expect(tokenText!.trim()).toMatch(/^sieve_tok_/);
    const plaintextToken = tokenText!.trim();

    // Step 4: Call the API with this token.
    // list_emails should be allowed.
    const allowed = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', plaintextToken, {});
    expect(allowed.status).toBe(200);

    // send_email should be denied (default deny, no allow rule for it).
    const denied = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', plaintextToken, {
      to: ['test@test.com'], subject: 'Hi', body: 'Hello',
    });
    expect(denied.status).toBe(403);
  });

  test('token with seed read-only policy can list but not send', async () => {
    // Use the pre-seeded token.
    const allowed = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', s.seed_token, {});
    expect(allowed.status).toBe(200);
    // read-only preset should deny send_email.
    const denied = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', s.seed_token, {
      to: ['x@x.com'], subject: 'X', body: 'X',
    });
    expect(denied.status).toBe(403);
  });

  test('invalid token is rejected by API', async () => {
    const resp = await apiCall(s.api_url, 'GET', '/api/v1/connections', 'sieve_tok_fakefakefakefakefake1234567', undefined);
    expect(resp.status).toBe(401);
  });

  test('no token is rejected by API', async () => {
    const resp = await fetch(`${s.api_url}/api/v1/connections`);
    expect(resp.status).toBe(401);
  });

  test('access to unbound connection is denied', async () => {
    // seed token is bound to test-conn only, not second-conn.
    const resp = await apiCall(s.api_url, 'POST', '/api/v1/connections/second-conn/ops/list_emails', s.seed_token, {});
    expect(resp.status).toBe(403);
  });
});

// ─── Workflow 3: Token lifecycle ─────────────────────────────────────────────
// Create, revoke, verify status changes.

test.describe('Token lifecycle', () => {
  test('create token, revoke it, verify it stops working', async ({ page }) => {
    // Create token.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'revoke-test-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const firstOption = roleSelect.locator('option').nth(1);
    await roleSelect.selectOption(await firstOption.getAttribute('value') || '');
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    // Capture the plaintext token.
    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const plaintext = tokenText!.trim();

    // Verify the token works.
    const beforeRevoke = await apiCall(s.api_url, 'GET', '/api/v1/connections', plaintext, undefined);
    expect(beforeRevoke.status).toBe(200);

    // Revoke it via the UI.
    page.on('dialog', d => d.accept());
    await page.goto(`${s.web_url}/tokens`);
    await page.locator('tr:has-text("revoke-test-token") form[action*="/revoke"] button').click();
    await page.waitForLoadState('networkidle');

    // Verify the token no longer works.
    const afterRevoke = await apiCall(s.api_url, 'GET', '/api/v1/connections', plaintext, undefined);
    expect(afterRevoke.status).toBe(401);

    // Verify it shows as revoked in the UI.
    await page.goto(`${s.web_url}/tokens?filter=revoked`);
    await expect(page.locator('td:has-text("revoke-test-token")')).toBeVisible();

    // Verify it's gone from the active filter.
    await page.goto(`${s.web_url}/tokens?filter=active`);
    await expect(page.locator('td:has-text("revoke-test-token")')).not.toBeVisible();
  });

  test('create token with expiry, verify expiry shows in UI', async ({ page }) => {
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'expiry-test-token');
    const roleSelect = page.locator('select[name="role_id"]');
    await roleSelect.selectOption(await roleSelect.locator('option').nth(1).getAttribute('value') || '');
    await page.locator('select[name="expires_in"]').selectOption('24h');
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    // Token should appear with expiry info.
    await page.goto(`${s.web_url}/tokens`);
    await expect(page.locator('td:has-text("expiry-test-token")')).toBeVisible();
  });
});

// ─── Workflow 4: Role CRUD ───────────────────────────────────────────────────

test.describe('Role lifecycle', () => {
  test('create role, edit it via Edit link, verify changes persist', async ({ page }) => {
    // Create a role.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'edit-test-role');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Verify it exists and has an Edit link (this was a bug — Edit link was missing).
    await page.goto(`${s.web_url}/roles`);
    await expect(page.locator('td:has-text("edit-test-role")')).toBeVisible();
    const editLink = page.locator('tr:has-text("edit-test-role") a:has-text("Edit")');
    await expect(editLink).toBeVisible();

    // Click Edit.
    await editLink.click();
    await expect(page).toHaveURL(/\/roles\/.*\/edit/);

    // Change the name.
    await page.fill('input[name="name"]', 'edited-role');
    await page.locator('form button[type="submit"]').click();

    // Verify the name changed.
    await page.goto(`${s.web_url}/roles`);
    await expect(page.locator('td:has-text("edited-role")')).toBeVisible();
    await expect(page.locator('td:has-text("edit-test-role")')).not.toBeVisible();
  });

  test('delete role, verify it disappears', async ({ page }) => {
    // Create a role to delete.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'delete-this-role');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    await page.goto(`${s.web_url}/roles`);
    await expect(page.locator('td:has-text("delete-this-role")')).toBeVisible();

    page.on('dialog', d => d.accept());
    await page.locator('tr:has-text("delete-this-role") form[action*="/delete"] button').click();

    await page.goto(`${s.web_url}/roles`);
    await expect(page.locator('td:has-text("delete-this-role")')).not.toBeVisible();
  });
});

// ─── Workflow 5: Connection CRUD ─────────────────────────────────────────────

test.describe('Connection lifecycle', () => {
  test('connections page shows seeded connections', async ({ page }) => {
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('text=Test Connection')).toBeVisible();
    await expect(page.locator('text=Second Connection')).toBeVisible();
  });
});

// ─── Workflow 6: Approval workflow ───────────────────────────────────────────
// Approve one, reject the other, verify they're gone from pending.

test.describe('Approval workflow', () => {
  test('approve an item, verify it leaves pending list', async ({ page }) => {
    await page.goto(`${s.web_url}/approvals`);

    // Count pending approvals.
    const pendingBefore = await page.locator('button:has-text("Approve")').count();
    expect(pendingBefore).toBeGreaterThanOrEqual(1);

    // Approve the first one.
    await page.locator('button:has-text("Approve")').first().click();
    await page.waitForURL(/\/approvals/);

    // Should have one fewer pending item.
    const pendingAfter = await page.locator('button:has-text("Approve")').count();
    expect(pendingAfter).toBe(pendingBefore - 1);
  });

  test('reject an item, verify it leaves pending list', async ({ page }) => {
    await page.goto(`${s.web_url}/approvals`);

    const pendingBefore = await page.locator('button:has-text("Reject")').count();
    expect(pendingBefore).toBeGreaterThanOrEqual(1);

    await page.locator('button:has-text("Reject")').first().click();
    await page.waitForURL(/\/approvals/);

    const pendingAfter = await page.locator('button:has-text("Reject")').count();
    expect(pendingAfter).toBe(pendingBefore - 1);
  });
});

// ─── Workflow 7: Audit log filtering ─────────────────────────────────────────

test.describe('Audit log', () => {
  test('audit page shows entries, filter narrows results', async ({ page }) => {
    await page.goto(`${s.web_url}/audit`);

    // Should show multiple operations.
    await expect(page.locator('td:has-text("list_emails")').first()).toBeVisible();
    await expect(page.locator('td:has-text("send_email")').first()).toBeVisible();

    // Filter by operation.
    await page.fill('input[name="operation"]', 'send_email');
    await page.locator('form button[type="submit"]').click();

    // Now only send_email should be visible.
    await expect(page.locator('td:has-text("send_email")').first()).toBeVisible();
    // list_emails should NOT be visible after filtering.
    await expect(page.locator('td:has-text("list_emails")')).not.toBeVisible();
  });
});

// ─── Workflow 8: Settings persistence ────────────────────────────────────────

test.describe('Settings', () => {
  test('save settings, reload page, verify they persist', async ({ page }) => {
    await page.goto(`${s.web_url}/settings`);

    // Set values.
    await page.fill('input[name="llm_model"]', 'test-model-42');
    await page.fill('input[name="llm_max_tokens"]', '9999');
    await page.locator('form[action="/settings"] button[type="submit"]').click();

    // Reload and verify persistence.
    await page.goto(`${s.web_url}/settings`);
    expect(await page.locator('input[name="llm_model"]').inputValue()).toBe('test-model-42');
    expect(await page.locator('input[name="llm_max_tokens"]').inputValue()).toBe('9999');

    // Change again to verify update works (not just insert).
    await page.fill('input[name="llm_model"]', 'updated-model');
    await page.locator('form[action="/settings"] button[type="submit"]').click();

    await page.goto(`${s.web_url}/settings`);
    expect(await page.locator('input[name="llm_model"]').inputValue()).toBe('updated-model');
  });
});

// ─── Workflow 9: Navigation ──────────────────────────────────────────────────

test.describe('Navigation', () => {
  test('every nav link reaches its page', async ({ page }) => {
    const routes = [
      { path: '/connections', expect: 'Connections' },
      { path: '/tokens', expect: 'Tokens' },
      { path: '/roles', expect: 'Roles' },
      { path: '/policies', expect: 'Policies' },
      { path: '/approvals', expect: 'Approvals' },
      { path: '/audit', expect: 'Audit' },
      { path: '/settings', expect: 'Settings' },
    ];

    for (const route of routes) {
      await page.goto(`${s.web_url}${route.path}`);
      const heading = page.locator('h1, h2').first();
      const text = await heading.textContent();
      expect(text).toContain(route.expect);
    }
  });

  test('root redirects to connections', async ({ page }) => {
    await page.goto(s.web_url);
    await expect(page).toHaveURL(/\/connections/);
  });

  test('doc pages load without 404', async ({ page }) => {
    for (const doc of ['google-oauth-setup', 'gmail-api', 'policy-scripts']) {
      const resp = await page.goto(`${s.web_url}/docs/${doc}`);
      expect(resp?.status()).toBe(200);
    }
  });
});

// ─── Workflow 10: Policy edit preserves non-Gmail match fields ──────────────
// Regression test: editing a policy with scope-specific match fields (e.g. LLM
// model, HTTP proxy path) must not silently drop those fields on load or save.

test.describe('Policy edit field preservation', () => {
  // Helper: create a policy by POSTing directly to the create endpoint.
  async function createPolicyDirect(webUrl: string, name: string, config: object) {
    const form = new URLSearchParams();
    form.set('name', name);
    form.set('policy_type', 'rules');
    form.set('policy_config', JSON.stringify(config));
    const resp = await fetch(`${webUrl}/policies/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
      redirect: 'manual',
    });
    // 303 See Other redirect to /policies means success.
    expect(resp.status).toBe(303);
  }

  // Helper: read the policy config from the edit page by calling prepareSubmit()
  // (a global function) which populates the hidden policy_config field, then reading it.
  async function getConfigFromEditPage(page: any) {
    await page.waitForLoadState('domcontentloaded');
    return page.evaluate(() => {
      // prepareSubmit is a top-level function declaration in <script>, so it's global.
      if (typeof prepareSubmit === 'function') {
        prepareSubmit();
      }
      const el = document.getElementById('policy_config') as HTMLInputElement;
      return el && el.value ? JSON.parse(el.value) : null;
    });
  }

  test('edit preserves LLM model field across save round-trip', async ({ page }) => {
    const config = {
      scope: 'llm',
      default_action: 'deny',
      rules: [
        {
          action: 'allow',
          match: { model: 'claude-*', operations: ['chat'] },
          reason: 'Allow claude models only',
        },
      ],
    };

    // Step 1: Create the policy directly.
    await createPolicyDirect(s.web_url, 'llm-model-preserve', config);

    // Step 2: Navigate to the edit page.
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("llm-model-preserve") a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/policies\/.*\/edit/);

    // Step 3: Read back the config that prepareSubmit would produce.
    const configBefore = await getConfigFromEditPage(page);
    expect(configBefore).toBeTruthy();
    expect(configBefore.rules).toHaveLength(1);
    expect(configBefore.rules[0].match.model).toBe('claude-*');
    expect(configBefore.rules[0].reason).toBe('Allow claude models only');

    // Step 4: Actually save (submit the edit form).
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Step 5: Navigate to edit page again.
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("llm-model-preserve") a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/policies\/.*\/edit/);

    // Step 6: Verify the model field survived the round-trip.
    const configAfter = await getConfigFromEditPage(page);
    expect(configAfter).toBeTruthy();
    expect(configAfter.rules).toHaveLength(1);
    expect(configAfter.rules[0].match.model).toBe('claude-*');
    expect(configAfter.rules[0].reason).toBe('Allow claude models only');
  });

  test('edit preserves HTTP proxy path field across save round-trip', async ({ page }) => {
    const config = {
      scope: 'http_proxy',
      default_action: 'deny',
      rules: [
        {
          action: 'allow',
          match: { path: '/v1/messages', body_contains: 'safe-keyword' },
        },
      ],
    };

    await createPolicyDirect(s.web_url, 'http-path-preserve', config);

    // Edit page: verify fields loaded.
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("http-path-preserve") a:has-text("Edit")').click();
    const configBefore = await getConfigFromEditPage(page);
    expect(configBefore.rules[0].match.path).toBe('/v1/messages');
    expect(configBefore.rules[0].match.body_contains).toBe('safe-keyword');

    // Save and re-verify.
    await page.locator('#create-policy-form button[type="submit"]').click();
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("http-path-preserve") a:has-text("Edit")').click();
    const configAfter = await getConfigFromEditPage(page);
    expect(configAfter.rules[0].match.path).toBe('/v1/messages');
    expect(configAfter.rules[0].match.body_contains).toBe('safe-keyword');
  });

  test('edit preserves AWS S3 bucket and key_prefix fields', async ({ page }) => {
    const config = {
      scope: 'aws-s3',
      default_action: 'deny',
      rules: [
        {
          action: 'allow',
          match: { bucket: 'my-secure-bucket', key_prefix: 'data/exports/' },
        },
      ],
    };

    await createPolicyDirect(s.web_url, 's3-fields-preserve', config);

    // Edit page.
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("s3-fields-preserve") a:has-text("Edit")').click();
    const configBefore = await getConfigFromEditPage(page);
    expect(configBefore.rules[0].match.bucket).toBe('my-secure-bucket');
    expect(configBefore.rules[0].match.key_prefix).toBe('data/exports/');

    // Save and re-verify round-trip.
    await page.locator('#create-policy-form button[type="submit"]').click();
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("s3-fields-preserve") a:has-text("Edit")').click();
    const configAfter = await getConfigFromEditPage(page);
    expect(configAfter.rules[0].match.bucket).toBe('my-secure-bucket');
    expect(configAfter.rules[0].match.key_prefix).toBe('data/exports/');
  });
});

// ─── Workflow 11: End-to-end policy scope enforcement ───────────────────────
// Verify that a policy with require_approval actually triggers the approval queue.
// The generic API blocks on WaitForResolution, so we fire-and-forget the request
// and verify the approval shows up in the queue via the UI.

test.describe('Approval-required policy enforcement', () => {
  test('policy with approval_required creates an approval in the queue', async ({ page }) => {
    // Create a policy that requires approval for send_email.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 'approval-policy');
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="send_email"]').check();
    await page.locator('input[name="rule-action"][value="require_approval"]').check();
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Create a role binding test-conn to this policy via the UI.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'approval-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    const policyCheckbox = page.locator('label:has-text("approval-policy") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Verify role was created with the binding.
    await page.goto(`${s.web_url}/roles`);
    const roleRow = page.locator('tr:has-text("approval-role")');
    await expect(roleRow).toBeVisible();
    // Verify it has test-conn binding.
    await expect(roleRow.locator('text=test-conn')).toBeVisible();

    // Create a token.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'approval-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("approval-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    // Get the token.
    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const token = tokenText!.trim();

    // The generic API blocks on WaitForResolution (up to 5 minutes), so we
    // fire-and-forget with a short timeout. The approval is submitted to the
    // queue before the blocking wait, so it will appear in the UI.
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 1000);
    try {
      await fetch(`${s.api_url}/api/v1/connections/test-conn/ops/send_email`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: ['test@test.com'], subject: 'Test', body: 'body' }),
        signal: controller.signal,
      });
    } catch {
      // Expected: aborted because the API blocks waiting for approval.
    }

    // Give the server time to process the submission before checking the queue.
    await page.waitForTimeout(1500);

    // Verify the approval shows up in the UI.
    await page.goto(`${s.web_url}/approvals`);
    await expect(page.locator('text=send_email').first()).toBeVisible();
  });
});

// ─── Stories 101-107: Edit button discoverability ───────────────────────────

test.describe('Edit button discoverability', () => {
  test('every policy row has an Edit link (story 101)', async ({ page }) => {
    await page.goto(`${s.web_url}/policies`);
    const rows = page.locator('tbody tr:has(td)');
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      await expect(rows.nth(i).locator('a:has-text("Edit")')).toBeVisible();
    }
  });

  test('clicking Edit on a policy pre-populates the name field (story 102)', async ({ page }) => {
    // Use the seeded read-only policy.
    await page.goto(`${s.web_url}/policies`);
    const row = page.locator('tr:has-text("read-only")');
    await expect(row).toBeVisible();
    await row.locator('a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/policies\/.*\/edit/);
    const nameVal = await page.locator('input[name="name"]').inputValue();
    expect(nameVal).toBe('read-only');
  });

  test('every role row has an Edit link (story 105)', async ({ page }) => {
    await page.goto(`${s.web_url}/roles`);
    const rows = page.locator('tbody tr:has(td)');
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      await expect(rows.nth(i).locator('a:has-text("Edit")')).toBeVisible();
    }
  });

  test('clicking Edit on a role pre-populates the name field (story 106)', async ({ page }) => {
    await page.goto(`${s.web_url}/roles`);
    const row = page.locator('tr:has-text("seed-role")');
    await expect(row).toBeVisible();
    await row.locator('a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/roles\/.*\/edit/);
    const nameVal = await page.locator('input[name="name"]').inputValue();
    expect(nameVal).toBe('seed-role');
  });

  test('connections have NO Edit link, only Delete (story 108)', async ({ page }) => {
    await page.goto(`${s.web_url}/connections`);
    const rows = page.locator('tbody tr:has(td)');
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      await expect(rows.nth(i).locator('a:has-text("Edit")')).not.toBeVisible();
      await expect(rows.nth(i).locator('button:has-text("Delete")')).toBeVisible();
    }
  });

  test('revoked tokens have no Revoke button, show dash instead (story 110)', async ({ page }) => {
    // Create and revoke a token so we can check the revoked state.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'no-unrevoke-token');
    const roleSelect = page.locator('select[name="role_id"]');
    await roleSelect.selectOption(await roleSelect.locator('option').nth(1).getAttribute('value') || '');
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    // Revoke it.
    page.on('dialog', d => d.accept());
    await page.goto(`${s.web_url}/tokens`);
    await page.locator('tr:has-text("no-unrevoke-token") form[action*="/revoke"] button').click();
    await page.waitForLoadState('networkidle');

    // View revoked tokens.
    await page.goto(`${s.web_url}/tokens?filter=revoked`);
    const row = page.locator('tr:has-text("no-unrevoke-token")');
    await expect(row).toBeVisible();
    // Should NOT have a Revoke button or Edit button.
    await expect(row.locator('button:has-text("Revoke")')).not.toBeVisible();
    await expect(row.locator('a:has-text("Edit")')).not.toBeVisible();
    // The actions column (last td) should show a dash instead of a Revoke button.
    const actionsCell = row.locator('td').last();
    const dashSpan = actionsCell.locator('span');
    await expect(dashSpan).toBeVisible();
    const dashText = await dashSpan.textContent();
    expect(dashText!.trim()).toBe('-');
  });
});

// ─── Stories 111-114: Confirmation dialogs (cancel) ─────────────────────────

test.describe('Confirmation dialogs', () => {
  test('canceling delete on a role leaves the role intact (story 112)', async ({ page }) => {
    // Create a role to test cancel-delete on.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'cancel-delete-role');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    await page.goto(`${s.web_url}/roles`);
    await expect(page.locator('td:has-text("cancel-delete-role")')).toBeVisible();

    // Dismiss (cancel) the confirmation dialog.
    page.on('dialog', d => d.dismiss());
    await page.locator('tr:has-text("cancel-delete-role") form[action*="/delete"] button').click();

    // Role should still be there.
    await page.goto(`${s.web_url}/roles`);
    await expect(page.locator('td:has-text("cancel-delete-role")')).toBeVisible();
  });

  test('canceling revoke on a token leaves the token active (story 114)', async ({ page }) => {
    // Create a token.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'cancel-revoke-token');
    const roleSelect = page.locator('select[name="role_id"]');
    await roleSelect.selectOption(await roleSelect.locator('option').nth(1).getAttribute('value') || '');
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    await page.goto(`${s.web_url}/tokens`);
    await expect(page.locator('td:has-text("cancel-revoke-token")')).toBeVisible();

    // Cancel the revoke dialog.
    page.on('dialog', d => d.dismiss());
    await page.locator('tr:has-text("cancel-revoke-token") form[action*="/revoke"] button').click();

    // Token should still be active.
    await page.goto(`${s.web_url}/tokens?filter=active`);
    await expect(page.locator('td:has-text("cancel-revoke-token")')).toBeVisible();
  });
});

// ─── Stories 124, 129: Empty states ─────────────────────────────────────────

test.describe('Empty states', () => {
  test('policies page without scope shows "Select a policy type" message (story 124)', async ({ page }) => {
    await page.goto(`${s.web_url}/policies`);
    await expect(page.locator('text=Select a policy type from the left menu to create a new policy.')).toBeVisible();
    // The create form should NOT be visible.
    await expect(page.locator('#create-policy-form')).not.toBeVisible();
  });
});

// ─── Stories 117-118: Duplicate names ───────────────────────────────────────

test.describe('Duplicate names', () => {
  test('creating a role with a duplicate name shows an error (story 117)', async ({ page }) => {
    // seed-role already exists from the test server.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'seed-role');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Should show some error indication and the role should NOT be duplicated.
    // The server returns an error page or inline error.
    const bodyText = await page.textContent('body');
    // Check for error-like text (UNIQUE constraint or "already exists").
    const hasError = bodyText!.includes('UNIQUE') || bodyText!.includes('already exists') || bodyText!.includes('error') || bodyText!.includes('Error');
    expect(hasError).toBe(true);
  });

  test('creating a policy with a duplicate name shows an error (story 118)', async ({ page }) => {
    // read-only already exists as a preset.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 'read-only');
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    const bodyText = await page.textContent('body');
    const hasError = bodyText!.includes('UNIQUE') || bodyText!.includes('already exists') || bodyText!.includes('error') || bodyText!.includes('Error');
    expect(hasError).toBe(true);
  });
});

// ─── Stories 278-283: Rule builder interactions ─────────────────────────────

test.describe('Rule builder interactions', () => {
  test('checking Gmail read operations shows filter fields (story 278)', async ({ page }) => {
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.locator('#btn-add-rule').click();

    // Before checking: filter fields should be hidden.
    await expect(page.locator('#filter-from')).toBeHidden();
    await expect(page.locator('#filter-label')).toBeHidden();
    await expect(page.locator('#filter-subject')).toBeHidden();

    // Check list_emails and read_email.
    await page.locator('input.rule-op[value="list_emails"]').check();
    await page.locator('input.rule-op[value="read_email"]').check();

    // Filter fields should now be visible.
    await expect(page.locator('#filter-from')).toBeVisible();
    await expect(page.locator('#filter-label')).toBeVisible();
    await expect(page.locator('#filter-subject')).toBeVisible();
  });

  test('selecting "Run Script" action shows script fields and hides extras (story 280)', async ({ page }) => {
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.locator('#btn-add-rule').click();

    // Extras section should be visible by default (Allow is selected).
    await expect(page.locator('#extras-section')).toBeVisible();
    await expect(page.locator('#script-fields')).toBeHidden();

    // Select "Run Script".
    await page.locator('input[name="rule-action"][value="run_script"]').check();

    // Script fields visible, extras hidden.
    await expect(page.locator('#script-fields')).toBeVisible();
    await expect(page.locator('#extras-section')).toBeHidden();
  });

  test('selecting "Allow" action shows extras and hides script fields (story 281)', async ({ page }) => {
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.locator('#btn-add-rule').click();

    // Switch to Run Script first.
    await page.locator('input[name="rule-action"][value="run_script"]').check();
    await expect(page.locator('#script-fields')).toBeVisible();
    await expect(page.locator('#extras-section')).toBeHidden();

    // Switch back to Allow.
    await page.locator('input[name="rule-action"][value="allow"]').check();
    await expect(page.locator('#extras-section')).toBeVisible();
    await expect(page.locator('#script-fields')).toBeHidden();
  });

  test('selecting "Deny" action hides extras section (story 282)', async ({ page }) => {
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.locator('#btn-add-rule').click();

    // Extras starts visible (Allow is default).
    await expect(page.locator('#extras-section')).toBeVisible();

    // Select Deny.
    await page.locator('input[name="rule-action"][value="deny"]').check();

    // Extras should be hidden.
    await expect(page.locator('#extras-section')).toBeHidden();
  });
});

// ─── Stories 115-116: Cancel flows ──────────────────────────────────────────

test.describe('Cancel flows', () => {
  test('clicking Cancel on role edit returns to roles list without saving (story 115)', async ({ page }) => {
    // Create a role to edit.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'cancel-edit-role');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Go to roles, click Edit.
    await page.goto(`${s.web_url}/roles`);
    await page.locator('tr:has-text("cancel-edit-role") a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/roles\/.*\/edit/);

    // Change the name.
    await page.fill('input[name="name"]', 'should-not-save');

    // Click Cancel.
    await page.locator('a:has-text("Cancel")').click();

    // Should return to roles list.
    await expect(page).toHaveURL(/\/roles$/);

    // Name should NOT have changed.
    await expect(page.locator('td:has-text("cancel-edit-role")')).toBeVisible();
    await expect(page.locator('td:has-text("should-not-save")')).not.toBeVisible();
  });
});

// ─── Story 298: Principle of least privilege ────────────────────────────────

test.describe('Principle of least privilege (story 298)', () => {
  test('triage policy allows list+label, denies read+send', async ({ page }) => {
    // Create a triage policy: allow list_emails and add_label, deny everything else.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 'e2e-triage-policy');

    // Add rule: allow list_emails and list_labels.
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="list_emails"]').check();
    await page.locator('input.rule-op[value="list_labels"]').check();
    await page.locator('input[name="rule-action"][value="allow"]').check();
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();

    // Set default to deny.
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Create role binding test-conn to triage policy.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'e2e-triage-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    const policyCheckbox = page.locator('label:has-text("e2e-triage-policy") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Create a token.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'e2e-triage-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("e2e-triage-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const token = tokenText!.trim();

    // list_emails should be allowed.
    const listResp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', token, {});
    expect(listResp.status).toBe(200);

    // list_labels should be allowed.
    const labelResp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_labels', token, {});
    expect(labelResp.status).toBe(200);

    // read_email should be denied (default deny).
    const readResp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/read_email', token, {
      message_id: 'msg-1',
    });
    expect(readResp.status).toBe(403);

    // send_email should be denied.
    const sendResp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', token, {
      to: ['test@test.com'], subject: 'Hi', body: 'Hello',
    });
    expect(sendResp.status).toBe(403);
  });
});

// ─── Story 300: Emergency revocation ────────────────────────────────────────

test.describe('Emergency revocation (story 300)', () => {
  test('revoking token immediately cuts off API access', async ({ page }) => {
    // Create a role and token.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 'e2e-emergency-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    // Bind to read-only preset.
    const policyCheckbox = page.locator('label:has-text("read-only") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 'e2e-emergency-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("e2e-emergency-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const token = tokenText!.trim();

    // Token works before revocation.
    const before = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', token, {});
    expect(before.status).toBe(200);

    // Revoke via UI.
    page.on('dialog', d => d.accept());
    await page.goto(`${s.web_url}/tokens`);
    await page.locator('tr:has-text("e2e-emergency-token") form[action*="/revoke"] button').click();
    await page.waitForLoadState('networkidle');

    // Token is immediately cut off.
    const after = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', token, {});
    expect(after.status).toBe(401);

    // Verify in audit log that previous API call was recorded.
    await page.goto(`${s.web_url}/audit`);
    await expect(page.locator('td:has-text("list_emails")').first()).toBeVisible();
  });
});

// ─── Story 82: Change policy, all tokens update immediately ───────────────

test.describe('Story 82: Policy change propagates to existing tokens', () => {
  test('editing a policy immediately affects API enforcement for existing tokens', async ({ page }) => {
    // Step 1: Create a policy that denies send_email but allows everything else.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 's82-deny-send-policy');
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="send_email"]').check();
    await page.locator('input[name="rule-action"][value="deny"]').check();
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();
    await page.locator('#default-action').selectOption('allow');
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Step 2: Create a role binding test-conn to this policy.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 's82-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    const policyCheckbox = page.locator('label:has-text("s82-deny-send-policy") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Step 3: Create a token with this role.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 's82-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("s82-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    // Capture the plaintext token.
    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const plaintextToken = tokenText!.trim();

    // Step 4: send_email should be denied.
    const denied = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', plaintextToken, {
      to: ['test@test.com'], subject: 'Hi', body: 'Hello',
    });
    expect(denied.status).toBe(403);

    // Step 5: Edit the policy to allow send_email.
    // Navigate to policies, find the policy, click Edit.
    await page.goto(`${s.web_url}/policies`);
    await page.locator('tr:has-text("s82-deny-send-policy") a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/policies\/.*\/edit/);

    // Remove the existing deny rule by calling the global removeRule function.
    // `removeRule` is a function declaration in the template's <script> tag,
    // so it's accessible on window and has closure over the `rules` array.
    await page.evaluate(() => {
      (window as any).removeRule(0);
    });

    // Add a new allow rule for send_email via the UI form.
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="send_email"]').check();
    await page.locator('input[name="rule-action"][value="allow"]').check();
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();

    // Keep default action as allow.
    await page.locator('#default-action').selectOption('allow');

    // Submit the edit form.
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Step 6: Same token, same API call -- should now be allowed.
    const allowed = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', plaintextToken, {
      to: ['test@test.com'], subject: 'Hi', body: 'Hello',
    });
    expect(allowed.status).toBe(200);
  });
});

// ─── Story 87: Revoke token, audit trail preserved ────────────────────────

test.describe('Story 87: Revoke token, audit trail preserved', () => {
  test('audit entries survive token revocation', async ({ page }) => {
    // Step 1: Create role+token.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 's87-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    const policyCheckbox = page.locator('label:has-text("read-only") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 's87-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("s87-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const plaintext = tokenText!.trim();

    // Step 2: Make an API call (list_emails) -- should succeed.
    const resp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', plaintext, {});
    expect(resp.status).toBe(200);

    // Step 3: Revoke the token via UI.
    page.on('dialog', d => d.accept());
    await page.goto(`${s.web_url}/tokens`);
    await page.locator('tr:has-text("s87-token") form[action*="/revoke"] button').click();
    await page.waitForLoadState('networkidle');

    // Step 4: Navigate to the audit page.
    await page.goto(`${s.web_url}/audit`);

    // Step 5: Filter by operation.
    await page.fill('input[name="operation"]', 'list_emails');
    await page.locator('form button[type="submit"]').click();

    // Step 6: Verify the audit entry is visible (the operation was logged before revocation).
    await expect(page.locator('td:has-text("list_emails")').first()).toBeVisible();
    // The token name should still appear in the audit log even though the token is revoked.
    await expect(page.locator('td:has-text("s87-token")').first()).toBeVisible();
  });
});

// ─── Story 172: Require approval end-to-end ───────────────────────────────

test.describe('Story 172: Require approval end-to-end', () => {
  test('approval-required policy triggers approval, admin approves, item leaves pending', async ({ page }) => {
    // Step 1: Create a policy requiring approval for send_email.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 's172-approval-policy');
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="send_email"]').check();
    await page.locator('input[name="rule-action"][value="require_approval"]').check();
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Step 2: Create role+token.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 's172-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    const policyCheckbox = page.locator('label:has-text("s172-approval-policy") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 's172-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("s172-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const token = tokenText!.trim();

    // Step 3: Fire-and-forget an API call to send_email (it blocks on approval).
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 1000);
    try {
      await fetch(`${s.api_url}/api/v1/connections/test-conn/ops/send_email`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: ['alice@test.com'], subject: 'Story 172', body: 'needs approval' }),
        signal: controller.signal,
      });
    } catch {
      // Expected: aborted because the API blocks waiting for approval.
    }

    // Wait for the approval to be enqueued.
    await page.waitForTimeout(1500);

    // Step 4: Navigate to approvals page.
    await page.goto(`${s.web_url}/approvals`);

    // Step 5: Verify the send_email approval appears.
    await expect(page.locator('text=send_email').first()).toBeVisible();

    // Count current pending approvals that have an Approve button.
    const pendingBefore = await page.locator('button:has-text("Approve")').count();
    expect(pendingBefore).toBeGreaterThanOrEqual(1);

    // Step 6: Click Approve on the first matching approval.
    await page.locator('button:has-text("Approve")').first().click();
    await page.waitForURL(/\/approvals/);

    // Step 7: Verify it leaves the pending list (one fewer).
    const pendingAfter = await page.locator('button:has-text("Approve")').count();
    expect(pendingAfter).toBe(pendingBefore - 1);
  });
});

// ─── Story 81: Full agent setup workflow ──────────────────────────────────

test.describe('Story 81: Full agent setup workflow', () => {
  test('connections -> policy -> role -> token -> API calls -> audit verification', async ({ page }) => {
    // Step 1: Navigate to connections -- verify test-conn exists.
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('text=test-conn')).toBeVisible();

    // Step 2: Navigate to policies -- create a policy allowing list_emails only.
    await page.goto(`${s.web_url}/policies?scope=gmail`);
    await page.fill('input[name="name"]', 's81-list-only-policy');
    await page.locator('#btn-add-rule').click();
    await page.locator('input.rule-op[value="list_emails"]').check();
    await page.locator('input[name="rule-action"][value="allow"]').check();
    await page.locator('#add-rule-form button:has-text("Add"), #add-rule-form button:has-text("add")').first().click();
    await page.locator('#default-action').selectOption('deny');
    await page.locator('#create-policy-form button[type="submit"]').click();

    // Step 3: Navigate to roles -- create a role binding test-conn to the policy.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 's81-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    const policyCheckbox = page.locator('label:has-text("s81-list-only-policy") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Step 4: Navigate to tokens -- create a token with that role.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 's81-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("s81-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    // Step 5: Capture the plaintext token.
    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const token = tokenText!.trim();

    // Step 6: Call list_emails via API -- should succeed (200).
    const listResp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', token, {});
    expect(listResp.status).toBe(200);

    // Step 7: Call send_email -- should be denied (403).
    const sendResp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', token, {
      to: ['test@test.com'], subject: 'Hi', body: 'Hello',
    });
    expect(sendResp.status).toBe(403);

    // Step 8: Call read_email -- should be denied (403).
    const readResp = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/read_email', token, {
      message_id: 'msg-1',
    });
    expect(readResp.status).toBe(403);

    // Step 9: Navigate to audit -- verify list_emails entry appears with "allow".
    await page.goto(`${s.web_url}/audit`);
    await page.fill('input[name="operation"]', 'list_emails');
    await page.locator('form button[type="submit"]').click();
    await expect(page.locator('td:has-text("list_emails")').first()).toBeVisible();
    // Verify the result column shows "allow".
    await expect(page.locator('text=allow').first()).toBeVisible();

    // Step 10: Navigate to audit -- verify send_email appears with "deny".
    await page.goto(`${s.web_url}/audit`);
    await page.fill('input[name="operation"]', 'send_email');
    await page.locator('form button[type="submit"]').click();
    await expect(page.locator('td:has-text("send_email")').first()).toBeVisible();
    await expect(page.locator('text=deny').first()).toBeVisible();
  });
});

// ─── Story 301: Rotating credentials without agent downtime ───────────────

test.describe('Story 301: Rotating credentials without agent downtime', () => {
  test('edit role binding from one connection to another, same token keeps working', async ({ page }) => {
    // Step 1: Verify test-conn and second-conn both exist.
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('td:has-text("test-conn")')).toBeVisible();
    await expect(page.locator('td:has-text("second-conn")')).toBeVisible();

    // Step 2: Create a role binding test-conn to read-only policy.
    await page.goto(`${s.web_url}/roles`);
    await page.fill('input[name="name"]', 's301-role');
    await page.locator('text=Add connection').click();
    const connSelect = page.locator('select.binding-conn').first();
    await connSelect.selectOption('test-conn');
    await connSelect.dispatchEvent('change');
    const policyCheckbox = page.locator('label:has-text("read-only") input[type="checkbox"]');
    await policyCheckbox.check();
    await policyCheckbox.dispatchEvent('change');
    await page.locator('form[action="/roles/create"] button[type="submit"]').click();

    // Step 3: Create token with this role.
    await page.goto(`${s.web_url}/tokens`);
    await page.fill('input[name="name"]', 's301-token');
    const roleSelect = page.locator('select[name="role_id"]');
    const roleOption = roleSelect.locator('option:has-text("s301-role")');
    const roleVal = await roleOption.getAttribute('value');
    expect(roleVal).toBeTruthy();
    await roleSelect.selectOption(roleVal!);
    await page.locator('form[action="/tokens/create"] button[type="submit"]').click();

    const tokenText = await page.locator('#token-value, code:has-text("sieve_tok_")').first().textContent();
    expect(tokenText).toBeTruthy();
    const token = tokenText!.trim();

    // Step 4: Call API with token on test-conn -- should succeed.
    const resp1 = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', token, {});
    expect(resp1.status).toBe(200);

    // Step 5: Edit role via UI to change binding from test-conn to second-conn.
    await page.goto(`${s.web_url}/roles`);
    await page.locator('tr:has-text("s301-role") a:has-text("Edit")').click();
    await expect(page).toHaveURL(/\/roles\/.*\/edit/);

    // The edit page has JS bindings array. We need to change the connection.
    // Remove the existing binding and add a new one for second-conn.
    // Use page.evaluate to manipulate the bindings array directly.
    await page.evaluate(() => {
      // The role_edit template exposes `bindings` as a global JS variable.
      // Clear existing bindings and add second-conn with read-only policy.
      const pols = (window as any).policies as Array<{ id: string; name: string }>;
      const readOnlyPolicy = pols.find((p: any) => p.name === 'read-only');
      (window as any).bindings = [
        { connection_id: 'second-conn', policy_ids: readOnlyPolicy ? [readOnlyPolicy.id] : [] },
      ];
      (window as any).renderBindings();
    });

    // Submit the edit form.
    await page.locator('form button[type="submit"]').click();

    // Step 6: Same token -- test-conn should now be denied (no longer bound).
    const resp2 = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', token, {});
    expect(resp2.status).toBe(403);

    // Same token -- second-conn should now work.
    const resp3 = await apiCall(s.api_url, 'POST', '/api/v1/connections/second-conn/ops/list_emails', token, {});
    expect(resp3.status).toBe(200);
  });
});

// ─── Documentation IA: categorized landing, in-page TOC, search ──────────────
// Verifies the redesigned /docs surface (specs/001-docs-navigation/).

test.describe('Documentation IA', () => {
  test('home shows categorized sections with descriptions, not a flat A–Z list', async ({ page }) => {
    await page.goto(`${s.web_url}/docs`);
    await expect(page).toHaveTitle(/Documentation/);

    // At least four real categories are rendered as section headings.
    const required = ['Getting Started', 'Connectors', 'Policies & Approvals', 'Security'];
    for (const cat of required) {
      await expect(page.locator(`h2:has-text("${cat}")`)).toBeVisible();
    }

    // Each visible page card has both a title and a one-line description.
    const card = page.locator('a[href^="/docs/"]:has(span.font-medium)').first();
    await expect(card).toBeVisible();
    await expect(card.locator('span.text-xs')).not.toHaveText(/^\s*$/);
  });

  test('clicking a category card lands on the category landing scoped to that group', async ({ page }) => {
    await page.goto(`${s.web_url}/docs`);
    await page.locator('h2:has-text("Connectors") a, a[href="/docs/category/connectors"]').first().click();
    await expect(page).toHaveURL(/\/docs\/category\/connectors$/);
    // Connectors-specific page must be present.
    await expect(page.locator('a[href="/docs/connections-guide"]')).toBeVisible();
    // A page from a different category must NOT be present in the listing.
    await expect(page.locator('a[href="/docs/credential-encryption"]')).toHaveCount(0)
      .catch(async () => {
        // The rail shows it, so scope to the main listing area only.
        const main = page.locator('main >> nth=0');
        await expect(main.locator('ul a[href="/docs/credential-encryption"]')).toHaveCount(0);
      });
  });

  test('breadcrumbs read Documentation › Category › Page on a doc detail view', async ({ page }) => {
    await page.goto(`${s.web_url}/docs/concepts`);
    const crumbs = page.locator('nav[aria-label="Breadcrumb"]');
    await expect(crumbs).toContainText('Documentation');
    await expect(crumbs).toContainText('Getting Started');
    // Trailing crumb (the title) is the one without a hyperlink.
    const last = crumbs.locator('span.text-slate-200');
    await expect(last).toBeVisible();
  });

  test('rail highlights the active page on a doc detail view', async ({ page }) => {
    await page.goto(`${s.web_url}/docs/policy-rules-reference`);
    const active = page.locator('aside a[href="/docs/policy-rules-reference"]');
    await expect(active.first()).toHaveClass(/text-indigo-400/);
  });

  test('long doc shows a TOC with multiple entries; clicking jumps and highlights', async ({ page }) => {
    await page.goto(`${s.web_url}/docs/policy-rules-reference`);
    // Wait for marked.js to populate the article.
    await page.waitForFunction(() => {
      const a = document.querySelector('#content');
      return !!(a && a.querySelectorAll('h2').length >= 2);
    });
    const tocLinks = page.locator('#toc-list a.toc-link');
    expect(await tocLinks.count()).toBeGreaterThanOrEqual(2);

    const firstLink = tocLinks.first();
    const targetID = await firstLink.getAttribute('data-target');
    expect(targetID).toBeTruthy();
    await firstLink.click();
    await expect(page).toHaveURL(new RegExp(`#${targetID}$`));
  });

  test('doc with fewer than two H2 headings hides the TOC', async ({ page }) => {
    // Pick a short page; if our shortest doc has ≥2 H2s, this assertion still
    // passes for any future short doc and is harmless here.
    await page.goto(`${s.web_url}/docs/mcp-integration`);
    await page.waitForFunction(() => {
      return !!document.querySelector('#content article, #content > *');
    }).catch(() => { /* tolerate */ });
    const aside = page.locator('#toc-aside');
    const h2Count = await page.locator('#content h2').count();
    if (h2Count < 2) {
      await expect(aside).toBeHidden();
    } else {
      await expect(aside).toBeVisible();
    }
  });

  test('internal .md cross-link in a doc body navigates to the rendered doc page', async ({ page }) => {
    // policy-scripts.md links across to other docs; pick whichever .md link is present.
    await page.goto(`${s.web_url}/docs/policy-scripts`);
    await page.waitForFunction(() => !!document.querySelector('#content a[href]'));
    const link = page.locator('#content a[href^="/docs/"]').first();
    if (await link.count() === 0) test.skip();
    const href = await link.getAttribute('href');
    expect(href).toMatch(/^\/docs\/[a-z0-9-]+(?:#.*)?$/);
    await link.click();
    await expect(page).toHaveURL(new RegExp(`${href!.split('#')[0]}(?:#.*)?$`));
    // Confirm the new page rendered (not a 404).
    await expect(page.locator('nav[aria-label="Breadcrumb"]')).toBeVisible();
  });

  test('search returns matching pages with highlighted excerpts', async ({ page }) => {
    await page.goto(`${s.web_url}/docs`);
    const input = page.locator('#docs-search');
    await input.fill('approval');
    await page.waitForSelector('#docs-results a', { state: 'visible' });
    const results = page.locator('#docs-results a');
    expect(await results.count()).toBeGreaterThan(0);
    await expect(results.first().locator('mark')).toHaveCount(1);
  });

  test('search shows a clear empty-state message when nothing matches', async ({ page }) => {
    await page.goto(`${s.web_url}/docs`);
    await page.locator('#docs-search').fill('zzzzz-no-matches-here');
    await page.waitForSelector('#docs-results', { state: 'visible' });
    await expect(page.locator('#docs-results')).toContainText(/no documentation matches/i);
  });

  test('clicking a search result navigates to /docs/{slug}#{anchor} when matched in a section', async ({ page }) => {
    await page.goto(`${s.web_url}/docs`);
    await page.locator('#docs-search').fill('approval');
    await page.waitForSelector('#docs-results a');
    const first = page.locator('#docs-results a').first();
    const href = await first.getAttribute('href');
    expect(href).toMatch(/^\/docs\/[a-z0-9-]+(?:#[a-z0-9-]+)?$/);
    await first.click();
    await expect(page).toHaveURL(new RegExp(href!.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$'));
  });

  test('unknown category id returns 404', async ({ page }) => {
    const resp = await page.goto(`${s.web_url}/docs/category/this-id-does-not-exist`);
    expect(resp?.status()).toBe(404);
  });
});

// ─── Passphrase rotation ─────────────────────────────────────────────────────
// UI passphrase rotation. The e2e testserver boots with passphrase
// "e2e-test-passphrase" (see e2e/testserver/main.go). The first test rotates
// to "rotated-via-ui" and asserts that an agent credential call against the
// running instance still succeeds without restart. Subsequent tests in this
// describe block run against the post-rotation state; the testserver keeps
// the new in-memory KEK so credential calls keep working.

test.describe('Passphrase rotation', () => {
  test('Rotate passphrase from settings page', async ({ page }) => {
    // Open the settings page and confirm the rotation form is rendered
    // alongside the existing LLM Configuration card.
    await page.goto(`${s.web_url}/settings`);
    await expect(page.locator('#rotate-passphrase-form')).toBeVisible();
    await expect(page.locator('input#current_passphrase')).toBeVisible();
    await expect(page.locator('input#new_passphrase')).toBeVisible();
    await expect(page.locator('input#new_passphrase_confirm')).toBeVisible();

    // Fill the form and submit. Use the testserver default passphrase
    // ("e2e-test-passphrase"); rotate to a fresh value.
    await page.fill('input#current_passphrase', 'e2e-test-passphrase');
    await page.fill('input#new_passphrase', 'rotated-via-ui');
    await page.fill('input#new_passphrase_confirm', 'rotated-via-ui');
    await Promise.all([
      page.waitForURL(/\/settings\?rotated=1&count=\d+/),
      page.click('#rotate-passphrase-submit'),
    ]);

    // Success card MUST be visible and reference the records-rewrapped
    // count. The seed test environment has at least one connection, so
    // count >= 1.
    const successText = await page.locator('div').filter({ hasText: /Passphrase rotated\.\s+\d+\s+credential record/ }).first().textContent();
    expect(successText).toMatch(/Passphrase rotated\.\s+\d+\s+credential record/);

    // Exercise an existing agent-side credential flow against the post-
    // rotation keyring to confirm requests still succeed without restart.
    // The seed token and a list-emails call against the mock connector
    // are wired by the testserver — apiCall returns the JSON response.
    const emails = await apiCall(s, 'GET', `/api/v1/connections/test-conn/ops/list_emails`, undefined, s.seed_token);
    expect(emails).toBeTruthy();
  });

  test('Submit with confirmation mismatch shows error and does not rotate', async ({ page }) => {
    await page.goto(`${s.web_url}/settings`);
    // Use the post-rotation passphrase as the current; pick deliberately
    // mismatched new + confirm fields.
    await page.fill('input#current_passphrase', 'rotated-via-ui');
    await page.fill('input#new_passphrase', 'attempt-A');
    await page.fill('input#new_passphrase_confirm', 'attempt-B');
    await page.click('#rotate-passphrase-submit');
    // The page re-renders at /settings/rotate-passphrase with the chip;
    // assert the confirmation-mismatch message is visible and that the
    // URL did NOT enter the success-redirect state.
    await expect(page).not.toHaveURL(/rotated=1/);
    const body = await page.textContent('body');
    expect(body).toContain('new passphrase and confirmation do not match');
  });
});

// ─── Slack connector — UI surfaces & status lifecycle ─────────────────
//
// The full Slack OAuth + token-entry flows are unit-tested in
// internal/web/slack_test.go against a mocked Slack OAuth surface. The
// testserver doesn't run a mock Slack API, so this group validates the
// pieces that ARE reachable end-to-end: status-column rendering across
// connector types, the disable/enable button flow on seeded connections,
// and presence of the Slack tile + token-entry form in the connector
// picker.

test.describe('Slack connector — UI surfaces', () => {
  test('connections page renders status badge for all rows', async ({ page }) => {
    await page.goto(`${s.web_url}/connections`);
    // Every existing connection has status=active after the migration.
    // The status column shows an Active badge.
    const activeBadges = page.locator('span:has-text("Active")');
    expect(await activeBadges.count()).toBeGreaterThanOrEqual(1);
  });

  test('Slack tile appears in connector picker with token-entry form', async ({ page }) => {
    await page.goto(`${s.web_url}/connections`);
    // The Slack connector tile is rendered conditionally by the
    // template based on connector_type=='slack'. Look for an
    // unambiguous surface (the configure form or the install button)
    // inside the connector picker section, not just the literal
    // "Slack" text — that also matches the sidebar nav link which is
    // hidden behind the collapsed menu.
    await expect(
      page.locator(
        'form[action="/connections/slack/oauth/configure"], form[action="/connections/slack/oauth/start"]'
      ).first()
    ).toBeVisible();
  });

  test('disable button transitions a connection to disabled status', async ({ page, request }) => {
    // Seed a fresh connection via the API (no Slack creds needed).
    // Use the existing "test-conn" mock connection (already seeded
    // by testserver/main.go) — disable, verify status flip, re-enable.
    await page.goto(`${s.web_url}/connections`);

    const row = page.locator('tr:has-text("test-conn")');
    await expect(row).toBeVisible();

    // Auto-confirm the hx-confirm dialog Playwright can't dismiss
    // through hx-confirm directly — drive POST via the request fixture
    // so we exercise the same handler path with no UI confirmation.
    const disableResp = await request.post(`${s.web_url}/connections/test-conn/disable`);
    expect(disableResp.status()).toBe(200); // Playwright follows the 303 redirect
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('tr:has-text("test-conn") span:has-text("Disabled")')).toBeVisible();

    const enableResp = await request.post(`${s.web_url}/connections/test-conn/enable`);
    expect(enableResp.status()).toBe(200);
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('tr:has-text("test-conn") span:has-text("Active")')).toBeVisible();
  });

  test('disabled connection rejects agent operations with HTTP 403 + structured body', async ({ request }) => {
    // Disable test-conn (the seeded mock connection that seed_token is
    // bound to). Then hit the API with the real seeded token and assert
    // the sentinel-mapping path: 403 with body {"error":"disabled",...}.
    //
    // The earlier version of this test used a fake token, which made
    // authMiddleware short-circuit at 401 and masked any regression in
    // the disable gate. Using s.seed_token forces auth to succeed so
    // the 403 we observe is genuinely from the GetConnector status
    // gate (T015).
    try {
      const disableResp = await request.post(`${s.web_url}/connections/test-conn/disable`);
      expect(disableResp.ok()).toBe(true);

      const resp = await request.post(`${s.api_url}/api/v1/connections/test-conn/ops/list_emails`, {
        headers: { Authorization: `Bearer ${s.seed_token}` },
        data: '{}',
      });
      expect(resp.status()).toBe(403);

      const body = await resp.json();
      expect(body.error).toBe('disabled');
      expect(body.message).toBeTruthy();
    } finally {
      // Always re-enable so subsequent test cases see a clean state,
      // even if the assertions above failed mid-flight.
      await request.post(`${s.web_url}/connections/test-conn/enable`);
    }
  });

  test('reauth_required connection returns 403 with reauth_required code', async ({ request }) => {
    // Companion to the disabled test: drive the same path but with the
    // reauth_required sentinel. Both surfaces use the same mapper
    // (writeReauthError / connectionStateError), so this is the sister
    // assertion that catches a regression in the other branch.
    //
    // testserver/main.go seeds a `reauth-conn` row already in
    // status='reauth_required' for exactly this case. Bind it to the
    // seed role first so the auth/role gate doesn't mask the status-
    // gate failure.
    const role = await request.get(`${s.web_url}/api/roles/${s.seed_role_id}`);
    void role;
    // The seed_token's role binds test-conn only; we want the seeded
    // reauth-conn instead. Easiest: PATCH the role's bindings via the
    // admin update endpoint. The testserver does not expose a CSRF-
    // safe REST update, so we add reauth-conn through the seed role's
    // bindings page directly.
    await request.post(`${s.web_url}/roles/${s.seed_role_id}/update`, {
      form: {
        name: 'seed-role',
        bindings: JSON.stringify([
          { connection_id: 'test-conn', policy_ids: [s.read_only_policy_id] },
          { connection_id: 'reauth-conn', policy_ids: [s.read_only_policy_id] },
        ]),
      },
    });

    const resp = await request.post(`${s.api_url}/api/v1/connections/reauth-conn/ops/list_emails`, {
      headers: { Authorization: `Bearer ${s.seed_token}` },
      data: '{}',
    });
    expect(resp.status()).toBe(403);

    const body = await resp.json();
    expect(body.error).toBe('reauth_required');
    expect(body.connection_id).toBe('reauth-conn');
    expect(body.reauth_url).toBe('/connections/reauth-conn/reauth');
    expect(body.message).toBeTruthy();
  });

  // The admin UI MUST never show two contradictory status badges for
  // the same connection. Seeded `reauth-conn` is in
  // status='reauth_required' — its row must show exactly one badge
  // ("Reauth required") and never an "Active" badge in the same row.
  test('reauth_required row shows exactly one status badge', async ({ page }) => {
    await page.goto(`${s.web_url}/connections`);

    const row = page.locator('tr:has-text("reauth-conn")');
    await expect(row).toBeVisible();

    // Exactly one "Reauth required" pill in this row.
    const reauthBadges = row.locator('span:has-text("Reauth required")');
    expect(await reauthBadges.count()).toBe(1);

    // Zero "Active" pills in the same row — the canonical lifecycle
    // signal is the status enum, not the legacy needs_reauth boolean.
    const activeBadges = row.locator('span:has-text("Active")');
    expect(await activeBadges.count()).toBe(0);
  });

  // A stored OAuth client secret MUST never be re-rendered to the
  // operator. The configure form (visible when no creds are stored)
  // accepts the values; after save, the install button + a "Reset"
  // link replace it. Driving the round-trip via the configure handler
  // is sufficient — the server normalises storage (encrypted
  // _oauth_app:slack row) regardless of how the form was submitted.
  test('OAuth flow: configure → install button → reset cycle', async ({ page, request }) => {
    // Initial state: no creds → configure form is visible.
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('form[action="/connections/slack/oauth/configure"]')).toBeVisible();

    // Submit valid creds through the configure form.
    const saveResp = await request.post(`${s.web_url}/connections/slack/oauth/configure`, {
      form: {
        client_id: '1234567890.0987654321',
        client_secret: '0123456789abcdef0123456789abcdef',
      },
    });
    expect(saveResp.ok()).toBe(true);

    // After save: install button + reset link present, configure form
    // gone (a "set" indicator). The plaintext secret is never rendered
    // back — the configure form's input is gone entirely.
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('form[action="/connections/slack/oauth/start"]')).toBeVisible();
    await expect(page.locator('form[action="/connections/slack/oauth/clear"]')).toBeVisible();
    await expect(page.locator('form[action="/connections/slack/oauth/configure"]')).toHaveCount(0);
    // Plaintext secret bytes must not appear anywhere on the page.
    expect(await page.content()).not.toContain('0123456789abcdef0123456789abcdef');

    // Reset round-trip.
    const clearResp = await request.post(`${s.web_url}/connections/slack/oauth/clear`);
    expect(clearResp.ok()).toBe(true);
    await page.goto(`${s.web_url}/connections`);
    await expect(page.locator('form[action="/connections/slack/oauth/configure"]')).toBeVisible();
  });

  // A reserved `_oauth_app:slack` row MUST NOT appear in the per-tenant
  // connections list, MUST NOT appear in the role-binding connection
  // picker. Defence-in-depth on top of the SQL filter in Service.List
  // + the writer-side rejection in roles.
  test('reserved _oauth_app row is hidden from connections list and role picker', async ({ page, request }) => {
    // Ensure the encrypted row exists (recreate after any prior clear).
    await request.post(`${s.web_url}/connections/slack/oauth/configure`, {
      form: {
        client_id: '1234567890.0987654321',
        client_secret: '0123456789abcdef0123456789abcdef',
      },
    });

    // Connections list never shows the reserved id.
    await page.goto(`${s.web_url}/connections`);
    const reservedRow = page.locator('tr:has-text("oauth_app__slack")');
    expect(await reservedRow.count()).toBe(0);

    // Role edit page (use the seeded role) — connection-picker dropdown
    // is built from the same List() that filters reserved rows. The
    // dropdown's <option> set MUST NOT include oauth_app__slack.
    await page.goto(`${s.web_url}/roles/${s.seed_role_id}/edit`);
    // The picker is rendered dynamically via JS — wait for at least one
    // <select.binding-conn> to be present, then grep its option values.
    await page.locator('select.binding-conn').first().waitFor();
    const optionTexts = await page.locator('select.binding-conn option').allInnerTexts();
    for (const opt of optionTexts) {
      expect(opt).not.toContain('oauth_app__slack');
    }

    // Cleanup: clear OAuth creds so subsequent tests see a clean state.
    await request.post(`${s.web_url}/connections/slack/oauth/clear`);
  });
});
