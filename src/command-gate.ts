/**
 * Host-side command gate. Classifies inbound slash commands and gates
 * them before they reach the container.
 *
 * - Filtered commands: dropped silently (never reach the container)
 * - Admin commands: checked against user_roles; denied senders get a
 *   "Permission denied" response written directly to messages_out
 * - `/task`: owner/admin-only task-queue front door, relayed over loopback
 *   to manclawd and answered directly — never reaches the container
 * - Normal messages: pass through unchanged
 */
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getDb, hasTable } from './db/connection.js';
import { log } from './log.js';

export type GateResult =
  | { action: 'pass' }
  | { action: 'filter' }
  | { action: 'deny'; command: string }
  | { action: 'taskq'; text: string };

const FILTERED_COMMANDS = new Set(['/help', '/login', '/logout', '/doctor', '/config', '/remote-control']);
const ADMIN_COMMANDS = new Set(['/clear', '/compact', '/context', '/cost', '/files', '/upload-trace']);

/**
 * Classify a message and decide whether it should reach the container.
 * Returns 'pass' for normal messages and authorized admin commands,
 * 'filter' for silently-dropped commands, 'deny' for unauthorized
 * admin commands.
 */
export function gateCommand(content: string, userId: string | null, agentGroupId: string): GateResult {
  let text: string;
  try {
    const parsed = JSON.parse(content);
    text = (parsed.text || '').trim();
  } catch {
    text = content.trim();
  }

  if (!text.startsWith('/')) return { action: 'pass' };

  const command = text.split(/\s/)[0].toLowerCase();

  if (FILTERED_COMMANDS.has(command)) return { action: 'filter' };

  // /task is handled entirely host-side (relayed to manclawd); it never
  // reaches the container, so the agent has no queue authority.
  if (command === '/task') {
    return isAdmin(userId, agentGroupId) ? { action: 'taskq', text } : { action: 'deny', command };
  }

  if (ADMIN_COMMANDS.has(command)) {
    if (isAdmin(userId, agentGroupId)) {
      return { action: 'pass' };
    }
    return { action: 'deny', command };
  }

  // Unknown slash commands pass through (the agent/SDK handles them)
  return { action: 'pass' };
}

function isAdmin(userId: string | null, agentGroupId: string): boolean {
  if (!userId) return false;
  if (!hasTable(getDb(), 'user_roles')) return true; // no permissions module = allow all
  const db = getDb();
  const row = db
    .prepare(
      `SELECT 1 FROM user_roles
       WHERE user_id = ?
         AND (role = 'owner' OR role = 'admin')
         AND (agent_group_id IS NULL OR agent_group_id = ?)
       LIMIT 1`,
    )
    .get(userId, agentGroupId);
  return row != null;
}

/**
 * Relay a `/task ...` command to manclawd's front door and return the text
 * to write back to the chat.
 *
 * Loopback-only, bearer-authed with the manclawd token file. The token must
 * never reach a returned string or a log field — every failure path here
 * returns a fixed, token-free sentence.
 */
export async function relayTaskCommand(
  text: string,
  channelType: string,
  platformId: string,
  sender: string,
): Promise<string> {
  const tokenFile = process.env.MANCLAW_TOKEN_FILE ?? join(homedir(), '.config', 'manclaw', 'token');
  let token: string;
  try {
    token = readFileSync(tokenFile, 'utf8').trim();
  } catch (err) {
    log.warn('taskq token file unreadable', { tokenFile, err: err instanceof Error ? err.message : 'unknown' });
    return 'taskq front door not configured';
  }
  if (!token) {
    log.warn('taskq token file empty', { tokenFile });
    return 'taskq front door not configured';
  }

  const base = process.env.MANCLAW_API_URL ?? 'http://127.0.0.1:8377';
  try {
    const res = await fetch(`${base}/api/v1/taskcmd`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ text, channel_type: channelType, platform_id: platformId, sender }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      log.warn('taskq front door returned an error status', { status: res.status });
      return `taskq front door error (HTTP ${res.status})`;
    }
    const body = (await res.json()) as { reply?: unknown };
    return typeof body.reply === 'string' && body.reply ? body.reply : 'taskq: empty reply';
  } catch (err) {
    log.warn('taskq front door unreachable', { err: err instanceof Error ? err.message : 'unknown' });
    return 'taskq front door unreachable';
  }
}
