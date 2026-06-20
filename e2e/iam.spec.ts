import { test, expect } from '@playwright/test';
import { startTestServer, stopTestServer, apiCall, loginOperator, ServerInfo } from './helpers';

// This suite runs the WHOLE harness on the new IAM engine (SIEVE_IAM=1 enables
// iam_enabled and migrates the seeded legacy role/policy into Cedar at startup).
// It proves Sieve runs on IAM end to end: the agent API is governed by the
// migrated Cedar policy, and the IAM admin page reflects + explains it.

let s: ServerInfo;

test.beforeAll(async () => {
  s = await startTestServer({ SIEVE_IAM: '1' });
});

test.afterAll(async () => {
  stopTestServer(s);
});

test.describe('Sieve running on the IAM engine', () => {
  // The seed token's read-only role is migrated to Cedar; the agent path is
  // decided by the IAM engine. Read ops allowed, write ops denied — same
  // behavior as the legacy engine, now proven on IAM.
  test('agent API is governed by the migrated IAM policy', async () => {
    const allowed = await apiCall(
      s.api_url, 'POST', '/api/v1/connections/test-conn/ops/list_emails', s.seed_token, {},
    );
    expect(allowed.status).toBe(200);

    const denied = await apiCall(
      s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', s.seed_token,
      { to: 'x@example.com', subject: 's', body: 'b' },
    );
    expect(denied.status).toBe(403);
  });

  test('unauthorized connection is denied under IAM', async () => {
    // second-conn is not in the seed role → connection not allowed.
    const resp = await apiCall(
      s.api_url, 'POST', '/api/v1/connections/second-conn/ops/list_emails', s.seed_token, {},
    );
    expect(resp.status).toBe(403);
  });

  test('IAM admin page shows the engine enabled and lists the migrated policy', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);
    await expect(page.locator('body')).toContainText('mig:seed-role');
    await expect(page.locator('body')).toContainText(/enabled/i);
  });

  test('decision explorer agrees with the agent path (deny on send_email)', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);
    await page.selectOption('select[name="role_id"]', s.seed_role_id);
    await page.selectOption('#ex-conn', 'test-conn');
    await page.fill('#ex-op', 'send_email');
    await page.locator('form[action="/iam/explore"] button[type="submit"]').click();
    await expect(page.locator('body')).toContainText(/deny/i);
  });

  test('decision explorer allows a read op', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);
    await page.selectOption('select[name="role_id"]', s.seed_role_id);
    await page.selectOption('#ex-conn', 'test-conn');
    await page.fill('#ex-op', 'list_emails');
    await page.locator('form[action="/iam/explore"] button[type="submit"]').click();
    await expect(page.locator('body')).toContainText(/allow/i);
  });

  test('visual builder: create a role + an allow rule, no Cedar typed', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);

    // Create an IAM role by name.
    await page.fill('form[action="/iam/roles"] input[name="name"]', 'pw-builder-role');
    await page.locator('form[action="/iam/roles"] button[type="submit"]').click();
    await expect(page.locator('body')).toContainText('pw-builder-role');

    // Build an allow/read rule for it on the mock connector — entirely via form controls.
    await page.selectOption('#rule-form select[name="role_id"]', { label: 'pw-builder-role' });
    await page.selectOption('#rule-form select[name="effect"]', 'allow');
    await page.selectOption('#rb-connector', 'mock');
    await page.selectOption('#rb-opscope', 'read');
    await page.locator('#rule-form button[type="submit"]').click();

    // The new rule shows up as a human-readable summary (not raw Cedar).
    await expect(page.locator('body')).toContainText('Allow read-only operations on mock');
    await expect(page.locator('body')).toContainText('role: pw-builder-role');
  });

  test('connector-tailored controls render per connector', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);

    // GitHub exposes owner/repo resource scopes.
    await page.selectOption('#rb-connector', 'github');
    await expect(page.locator('#rb-scope-wrap')).toBeVisible();
    await expect(page.locator('#rb-scope')).toContainText('Owner / org');
    await expect(page.locator('#rb-scope')).toContainText('Repository');

    // Anthropic exposes a numeric max-tokens condition.
    await page.selectOption('#rb-connector', 'anthropic');
    await expect(page.locator('#rb-conds-wrap')).toBeVisible();
    await expect(page.locator('#rb-conds')).toContainText('Max tokens');

    // Gmail (google) exposes the recipient-domain condition.
    await page.selectOption('#rb-connector', 'google');
    await expect(page.locator('#rb-conds')).toContainText('Recipient domains');
  });

  test('build a condition rule (anthropic max-tokens) entirely via the UI', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);

    await page.fill('form[action="/iam/roles"] input[name="name"]', 'pw-cond-role');
    await page.locator('form[action="/iam/roles"] button[type="submit"]').click();

    await page.selectOption('#rule-form select[name="role_id"]', { label: 'pw-cond-role' });
    await page.selectOption('#rule-form select[name="effect"]', 'require_approval');
    await page.selectOption('#rb-connector', 'anthropic');
    await page.check('input[name="cond_max_tokens"]');
    await page.selectOption('select[name="cond_max_tokens_op"]', 'lte');
    await page.fill('input[name="cond_max_tokens_val"]', '4096');
    await page.locator('#rule-form button[type="submit"]').click();

    await expect(page.locator('body')).toContainText('Require approval for');
    await expect(page.locator('body')).toContainText('context.param.max_tokens');
  });

  test('edit-in-place: a builder rule reloads into the form and updates on save', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);

    // Create a dedicated role so the rule's summary is unambiguous in the list.
    await page.fill('form[action="/iam/roles"] input[name="name"]', 'pw-edit-role');
    await page.locator('form[action="/iam/roles"] button[type="submit"]').click();
    await expect(page.locator('body')).toContainText('pw-edit-role');

    // Build an allow/read rule on the mock connector via the builder.
    await page.selectOption('#rule-form select[name="role_id"]', { label: 'pw-edit-role' });
    await page.selectOption('#rule-form select[name="effect"]', 'allow');
    await page.selectOption('#rb-connector', 'mock');
    await page.selectOption('#rb-opscope', 'read');
    await page.locator('#rule-form button[type="submit"]').click();

    const allowSummary = 'Allow read-only operations on mock (any connection) — role: pw-edit-role';
    await expect(page.locator('body')).toContainText(allowSummary);

    // Click the Edit link in that rule's row.
    const row = page.locator('tr', { hasText: allowSummary });
    await row.getByRole('link', { name: 'Edit' }).click();
    await expect(page).toHaveURL(/\/iam\/policies\/.+\/edit$/);

    // The form is prefilled from the stored spec.
    await expect(page.locator('#rule-form select[name="effect"]')).toHaveValue('allow');
    await expect(page.locator('#rule-form select[name="connector_type"]')).toHaveValue('mock');
    await expect(page.locator('#rule-form select[name="op_scope"]')).toHaveValue('read');
    // role_id is prefilled to the created role (non-empty).
    await expect(page.locator('#rule-form select[name="role_id"]')).not.toHaveValue('');

    // Flip the effect allow -> deny and save. Clear the (auto-generated) name so
    // it regenerates from the new summary, making the list assertion clean.
    await page.selectOption('#rule-form select[name="effect"]', 'deny');
    await page.fill('#rule-form input[name="name"]', '');
    await page.locator('#rule-form button[type="submit"]').click();

    // Back on the list, the summary reflects the change (deny, not allow).
    await expect(page).toHaveURL(/\/iam$/);
    const denySummary = 'Deny read-only operations on mock (any connection) — role: pw-edit-role';
    await expect(page.locator('body')).toContainText(denySummary);
    await expect(page.locator('body')).not.toContainText(allowSummary);
  });

  test('author a custom script guard in the UI; the gateway enforces it', async ({ page }) => {
    await loginOperator(page, s);
    await page.goto(`${s.web_url}/iam`);

    // 1. Author a script_guard in the filter library: deny sends containing "secret".
    await page.fill('#filter-form input[name="name"]', 'ui-block-secret');
    await page.selectOption('#filter-kind', 'script_guard');
    await page.fill('#filter-form textarea[name="script"]',
      'import sys, json\n' +
      'req = json.load(sys.stdin)\n' +
      'b = ((req.get("params") or {}).get("body")) or ""\n' +
      'print(json.dumps({"action": "deny", "reason": "blocked"} if "secret" in b.lower() else {"action": "allow"}))\n');
    await page.locator('#filter-form button[type="submit"]').click();
    await expect(page.locator('body')).toContainText('ui-block-secret');

    // 2. Attach it to an allow-write rule for the seed role on test-conn.
    await page.selectOption('#rule-form select[name="role_id"]', { label: 'seed-role' });
    await page.selectOption('#rule-form select[name="effect"]', 'allow');
    await page.selectOption('#rb-connector', 'mock');
    await page.selectOption('#rb-opscope', 'write');
    await page.selectOption('#rb-connscope', 'specific');
    await page.check('#rule-form input[name="connections"][value="test-conn"]');
    await page.check('#rule-form input[name="filters"][value="ui-block-secret"]');
    await page.locator('#rule-form button[type="submit"]').click();
    await expect(page.locator('body')).toContainText('filters[ui-block-secret]');

    // 3. The agent API now enforces the guard — nothing was hand-written in Cedar.
    const allowed = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', s.seed_token,
      { to: 'a@b.com', subject: 's', body: 'weekly update' });
    expect(allowed.status).toBe(200);
    const blocked = await apiCall(s.api_url, 'POST', '/api/v1/connections/test-conn/ops/send_email', s.seed_token,
      { to: 'a@b.com', subject: 's', body: 'the secret plan' });
    expect(blocked.status).toBe(403);
  });
});
