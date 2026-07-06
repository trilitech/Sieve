import { spawn, ChildProcess } from 'child_process';
import * as readline from 'readline';
import * as path from 'path';

export interface ServerInfo {
  web_url: string;
  api_url: string;
  seed_token: string;
  seed_token_id: string;
  seed_role_id: string;
  read_only_policy_id: string;
  operator_credential: string;
  process: ChildProcess;
}

/**
 * Logs the operator in by POSTing the credential to /login. The session +
 * CSRF cookies land in the page's context cookie jar (page.request shares it),
 * so subsequent page.goto admin navigations are authenticated. Required because
 * the testserver wires operator auth and requireOperatorSession fails closed.
 */
export async function loginOperator(page: import('@playwright/test').Page, s: ServerInfo): Promise<void> {
  const resp = await page.request.post(`${s.web_url}/login`, {
    form: { credential: s.operator_credential },
    maxRedirects: 0,
  });
  // 303 redirect to / on success.
  if (resp.status() !== 303 && resp.status() !== 200) {
    throw new Error(`operator login failed: status ${resp.status()}`);
  }
}

/**
 * Starts the Go test server (web UI + API) and returns connection info.
 * extraEnv merges into the child environment (e.g. { SIEVE_IAM: '1' } to run
 * the harness on the new IAM engine).
 */
export async function startTestServer(extraEnv: Record<string, string> = {}): Promise<ServerInfo> {
  const proc = spawn('go', ['run', './e2e/testserver/'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PATH: `${process.env.HOME}/go/bin:${process.env.PATH}`, ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  return new Promise<ServerInfo>((resolve, reject) => {
    const timeout = setTimeout(() => {
      proc.kill();
      reject(new Error('Test server startup timed out'));
    }, 30000);

    const rl = readline.createInterface({ input: proc.stdout! });

    rl.on('line', (line) => {
      try {
        const info = JSON.parse(line);
        clearTimeout(timeout);
        rl.close();
        resolve({ ...info, process: proc });
      } catch {
        // Not JSON yet, keep waiting.
      }
    });

    proc.stderr!.on('data', (data) => {
      const msg = data.toString();
      if (msg.includes('fatal') || msg.includes('panic')) {
        clearTimeout(timeout);
        proc.kill();
        reject(new Error(`Test server error: ${msg}`));
      }
    });

    proc.on('exit', (code) => {
      clearTimeout(timeout);
      if (code !== 0 && code !== null) {
        reject(new Error(`Test server exited with code ${code}`));
      }
    });
  });
}

export function stopTestServer(server: ServerInfo) {
  server.process.kill();
}

/**
 * Call the Sieve API with a bearer token. Returns parsed JSON response.
 */
export async function apiCall(
  apiUrl: string,
  method: string,
  path: string,
  token: string,
  body?: any,
): Promise<{ status: number; body: any }> {
  const url = `${apiUrl}${path}`;
  const opts: RequestInit = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  let respBody: any;
  const text = await resp.text();
  try {
    respBody = JSON.parse(text);
  } catch {
    respBody = text;
  }
  return { status: resp.status, body: respBody };
}
