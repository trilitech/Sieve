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
});
