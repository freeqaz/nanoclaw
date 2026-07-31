import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// --- Mocks ---------------------------------------------------------------

// user_roles lookup. `admins` holds the user ids that resolve to owner/admin;
// `hasUserRoles` toggles the "no permissions module installed" branch.
const dbRef = vi.hoisted(() => ({ hasUserRoles: true, admins: new Set<string>() }));

vi.mock('./db/connection.js', () => ({
  getDb: () => ({
    prepare: () => ({
      get: (userId: string) => (dbRef.admins.has(userId) ? { 1: 1 } : undefined),
    }),
  }),
  hasTable: () => dbRef.hasUserRoles,
}));

const logRef = vi.hoisted(() => ({ calls: [] as unknown[][] }));

vi.mock('./log.js', () => {
  const record =
    (level: string) =>
    (...args: unknown[]) => {
      logRef.calls.push([level, ...args]);
    };
  return {
    log: {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
      fatal: record('fatal'),
    },
  };
});

import { gateCommand, relayTaskCommand } from './command-gate.js';

/** Everything the relay handed to the logger, flattened for substring checks. */
function loggedText(): string {
  return JSON.stringify(logRef.calls);
}

const OWNER = 'signal:+15550001111';
const STRANGER = 'signal:+15559998888';

beforeEach(() => {
  dbRef.hasUserRoles = true;
  dbRef.admins = new Set([OWNER]);
  logRef.calls = [];
});

// --- gateCommand ---------------------------------------------------------

describe('gateCommand /task classification', () => {
  it('returns taskq for an admin and deny for a non-admin', () => {
    expect(gateCommand('/task ls', OWNER, 'ag-1')).toEqual({ action: 'taskq', text: '/task ls' });
    expect(gateCommand('/task ls', STRANGER, 'ag-1')).toEqual({ action: 'deny', command: '/task' });
  });

  it('denies an unidentified sender (null userId) — never relays', () => {
    expect(gateCommand('/task add do a thing', null, 'ag-1')).toEqual({ action: 'deny', command: '/task' });
  });

  it('reads the role scoped to the agent group, not a global env allowlist', () => {
    // The mocked statement resolves purely on user id; the point of this test
    // is that a sender with no role row can never reach the relay.
    dbRef.admins = new Set();
    expect(gateCommand('/task ls', OWNER, 'ag-1').action).toBe('deny');
  });

  it('relays the text verbatim — case and arguments preserved', () => {
    // The command match is lowercased, but manclawd needs the original text:
    // `/task add` bodies are user prose and must not be case-folded.
    const r = gateCommand('/TASK add Fix The Thing', OWNER, 'ag-1');
    expect(r).toEqual({ action: 'taskq', text: '/TASK add Fix The Thing' });
  });

  it('trims leading whitespace before classifying', () => {
    expect(gateCommand('   /task ls', OWNER, 'ag-1')).toEqual({ action: 'taskq', text: '/task ls' });
  });

  it('accepts a bare /task', () => {
    expect(gateCommand('/task', OWNER, 'ag-1')).toEqual({ action: 'taskq', text: '/task' });
  });

  it('unwraps JSON message content', () => {
    expect(gateCommand(JSON.stringify({ text: '/task ls' }), OWNER, 'ag-1')).toEqual({
      action: 'taskq',
      text: '/task ls',
    });
  });

  it('treats a non-breaking space as the argument separator (JS \\s matches it)', () => {
    // Documented, deliberate: the gate still catches it, so the command never
    // lands in agent context. manclawd's cutCommand only accepts ASCII
    // whitespace and answers 400 -- this fails closed on the far side, and a
    // non-admin still lands in `deny` here.
    const nbsp = String.fromCharCode(0x00a0);
    expect(gateCommand(`/task${nbsp}ls`, OWNER, 'ag-1')).toEqual({ action: 'taskq', text: `/task${nbsp}ls` });
    expect(gateCommand(`/task${nbsp}ls`, STRANGER, 'ag-1')).toEqual({ action: 'deny', command: '/task' });
  });

  describe('prefix matching', () => {
    // The command is the first whitespace-delimited token, compared for
    // equality — not a startsWith(). None of these are the task front door.
    const notTask = ['/taskfoo', '/tasks', '/task-list ls', '/task@nanoclaw ls', '/ta sk', '/тask ls'];
    for (const text of notTask) {
      it(`does not treat ${JSON.stringify(text)} as /task`, () => {
        expect(gateCommand(text, OWNER, 'ag-1').action).toBe('pass');
        expect(gateCommand(text, STRANGER, 'ag-1').action).toBe('pass');
      });
    }
  });

  it('leaves the rest of the gate alone', () => {
    expect(gateCommand('hello there', STRANGER, 'ag-1').action).toBe('pass');
    expect(gateCommand('/help', STRANGER, 'ag-1').action).toBe('filter');
    expect(gateCommand('/clear', STRANGER, 'ag-1')).toEqual({ action: 'deny', command: '/clear' });
    expect(gateCommand('/clear', OWNER, 'ag-1').action).toBe('pass');
  });

  it('falls open to allow-all when the permissions module is absent (documented upstream behavior)', () => {
    // user_roles ships in migration 001, so this branch is unreachable on any
    // migrated install. Pinned so a future change is a deliberate one.
    dbRef.hasUserRoles = false;
    expect(gateCommand('/task ls', STRANGER, 'ag-1').action).toBe('taskq');
  });
});

// --- relayTaskCommand ----------------------------------------------------

describe('relayTaskCommand', () => {
  const TOKEN = 'manclaw-secret-token-abc123';
  let tmpDir: string;
  let tokenFile: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nanoclaw-taskq-'));
    tokenFile = path.join(tmpDir, 'token');
    fs.writeFileSync(tokenFile, `${TOKEN}\n`, { mode: 0o600 });
    vi.stubEnv('MANCLAW_TOKEN_FILE', tokenFile);
    vi.stubEnv('MANCLAW_API_URL', 'http://127.0.0.1:8377');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function stubFetch(impl: (url: string, init: RequestInit) => unknown) {
    const spy = vi.fn(impl);
    vi.stubGlobal('fetch', spy);
    return spy;
  }

  function ok(body: unknown) {
    return { ok: true, status: 200, json: async () => body } as unknown as Response;
  }

  it('sends the bearer token and returns manclawd’s reply', async () => {
    const spy = stubFetch(() => ok({ reply: 'queued #7 — do a thing' }));
    const out = await relayTaskCommand('/task add do a thing', 'signal', '+15550001111', OWNER);

    expect(out).toBe('queued #7 — do a thing');
    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://127.0.0.1:8377/api/v1/taskcmd');
    // Guard that the leak tests below are meaningful: the token really is on
    // the wire, so "absent from the return value" is a property, not a tautology.
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
    expect(JSON.parse(init.body as string)).toEqual({
      text: '/task add do a thing',
      channel_type: 'signal',
      platform_id: '+15550001111',
      sender: OWNER,
    });
    expect(out).not.toContain(TOKEN);
    expect(loggedText()).not.toContain(TOKEN);
  });

  it('reports a non-2xx by status only', async () => {
    stubFetch(() => ({ ok: false, status: 503, json: async () => ({ reply: 'nope' }) }) as unknown as Response);
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door error (HTTP 503)');
    expect(out).not.toContain(TOKEN);
    expect(loggedText()).not.toContain(TOKEN);
  });

  it('returns a fixed sentence when the token file is unreadable', async () => {
    vi.stubEnv('MANCLAW_TOKEN_FILE', path.join(tmpDir, 'does-not-exist'));
    const spy = stubFetch(() => ok({ reply: 'should not happen' }));
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door not configured');
    expect(spy).not.toHaveBeenCalled();
  });

  it('returns a fixed sentence when the token file is empty', async () => {
    fs.writeFileSync(tokenFile, '   \n');
    const spy = stubFetch(() => ok({ reply: 'should not happen' }));
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door not configured');
    expect(spy).not.toHaveBeenCalled();
  });

  it('refuses a token with an interior control character instead of handing it to fetch', async () => {
    // undici renders an invalid header value into its own error message
    // (`Headers.append: "Bearer <token>" is an invalid header value.`), which
    // would put the secret in the host log. Reject before that can happen.
    const broken = `mancl${String.fromCharCode(10)}aw-secret`;
    fs.writeFileSync(tokenFile, broken);
    const spy = stubFetch(() => ok({ reply: 'should not happen' }));
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door not configured');
    expect(spy).not.toHaveBeenCalled();
    expect(loggedText()).not.toContain('mancl');
  });

  it('redacts the token if a thrown error ever embeds it', async () => {
    // Defense in depth for the case above: even if some future header value
    // slips through, the logged message must not carry the secret.
    stubFetch(() => {
      throw new TypeError(`Headers.append: "Bearer ${TOKEN}" is an invalid header value.`);
    });
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door unreachable');
    expect(loggedText()).not.toContain(TOKEN);
    expect(loggedText()).toContain('<redacted>');
  });

  it('reports a connection failure as unreachable, with the cause in the log', async () => {
    stubFetch(() => {
      const err = new TypeError('fetch failed');
      (err as Error & { cause?: unknown }).cause = new Error('connect ECONNREFUSED 127.0.0.1:8377');
      throw err;
    });
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door unreachable');
    // "fetch failed" alone is not actionable; the cause is what names the fault.
    expect(loggedText()).toContain('ECONNREFUSED');
    expect(loggedText()).not.toContain(TOKEN);
  });

  it('distinguishes a timeout from a connection failure in both the reply and the log', async () => {
    stubFetch(() => {
      throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
    });
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door timed out after 10s');
    expect(out).not.toBe('taskq front door unreachable');
    expect(loggedText()).toContain('timed out');
    expect(loggedText()).not.toContain(TOKEN);
  });

  it('treats a timeout during the body read as a timeout, not a bad body', async () => {
    stubFetch(
      () =>
        ({
          ok: true,
          status: 200,
          json: async () => {
            throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
          },
        }) as unknown as Response,
    );
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door timed out after 10s');
  });

  it('reports an unparseable 2xx body as an unreadable reply, not as unreachable', async () => {
    stubFetch(
      () =>
        ({
          ok: true,
          status: 200,
          json: async () => {
            throw new SyntaxError('Unexpected token < in JSON at position 0');
          },
        }) as unknown as Response,
    );
    const out = await relayTaskCommand('/task ls', 'signal', '+1555', OWNER);
    expect(out).toBe('taskq front door returned an unreadable reply');
    expect(loggedText()).not.toContain(TOKEN);
  });

  it('guards the reply type', async () => {
    stubFetch(() => ok({ reply: 42 }));
    expect(await relayTaskCommand('/task ls', 'signal', '+1555', OWNER)).toBe('taskq: empty reply');

    stubFetch(() => ok({}));
    expect(await relayTaskCommand('/task ls', 'signal', '+1555', OWNER)).toBe('taskq: empty reply');

    stubFetch(() => ok({ reply: '' }));
    expect(await relayTaskCommand('/task ls', 'signal', '+1555', OWNER)).toBe('taskq: empty reply');
  });

  it('never throws — the router must not fall through to the container on failure', async () => {
    stubFetch(() => {
      throw new Error('boom');
    });
    await expect(relayTaskCommand('/task ls', 'signal', '+1555', OWNER)).resolves.toBeTypeOf('string');
  });
});

// --- router wiring (structural) ------------------------------------------

describe('router taskq branch (structural)', () => {
  // The security property is an ordering one: `/task` is answered and returned
  // from before writeSessionMessage, so it never enters the agent's session
  // context and never wakes a container — the agent holds no queue authority.
  // Driving the real router needs a live session DB + container runtime, so
  // this guards the invariant structurally, matching the container-runner
  // ordering tests.
  const src = fs.readFileSync(path.join(process.cwd(), 'src', 'router.ts'), 'utf-8');

  it('gates before writing to the session', () => {
    expect(src.indexOf('gateCommand(')).toBeGreaterThan(-1);
    expect(src.indexOf('writeSessionMessage(')).toBeGreaterThan(src.indexOf('gateCommand('));
  });

  it('returns out of the taskq branch before writeSessionMessage', () => {
    const branch = src.indexOf("gate.action === 'taskq'");
    const writeSession = src.indexOf('writeSessionMessage(', branch);
    const returned = src.indexOf('return;', branch);
    expect(branch).toBeGreaterThan(-1);
    expect(returned).toBeGreaterThan(-1);
    expect(returned).toBeLessThan(writeSession);
  });

  it('answers via writeOutboundDirect (no container wake)', () => {
    const branch = src.indexOf("gate.action === 'taskq'");
    const segment = src.slice(branch, src.indexOf('return;', branch));
    expect(segment).toContain('writeOutboundDirect(');
    expect(segment).not.toContain('wakeContainer');
  });
});

// --- container userns passthrough (structural) ---------------------------

describe('NANOCLAW_CONTAINER_USERNS (structural)', () => {
  // buildContainerArgs is module-private and needs a container runtime to
  // drive, so guard the two properties that matter: the value is trimmed (an
  // empty/whitespace env var must not emit a bare `--userns`), and it is
  // pushed as its own argv element to a shell-less spawn, so a value with
  // spaces cannot become extra flags.
  const src = fs.readFileSync(path.join(process.cwd(), 'src', 'container-runner.ts'), 'utf-8');

  it('trims the env var and skips the flag when it is empty', () => {
    expect(src).toContain('process.env.NANOCLAW_CONTAINER_USERNS?.trim()');
    expect(src).toMatch(/const userns = process\.env\.NANOCLAW_CONTAINER_USERNS\?\.trim\(\);\s*if \(userns\) \{/);
  });

  it('passes the value as a single argv element', () => {
    expect(src).toContain("args.push('--userns', userns)");
  });

  it('spawns without a shell', () => {
    expect(src).toMatch(/spawn\(CONTAINER_RUNTIME_BIN, args, \{ stdio:/);
    expect(src).not.toContain('shell: true');
  });
});
