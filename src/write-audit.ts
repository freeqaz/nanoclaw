/**
 * manclaw vendor patch: per-spawn write audit.
 *
 * Records what an agent turn actually WROTE to its writable bind mounts, as
 * opposed to what it was permitted to write. Backend-agnostic on purpose: the
 * roots are derived from the `mounts` list nanoclaw already computes, so the
 * same hook covers podman, Docker, or a VM-backed runtime — nothing here
 * knows which runtime is in play.
 *
 * Contract with the external tool:
 *   writeaudit pre|post --run <id> --store <dir> --root <label>=<hostPath> ...
 * It exits 0 even on internal failure, and nothing in this module rethrows,
 * so a broken audit can never fail an agent turn. When the binary is absent
 * (fresh clone that hasn't built it) the hook is silently inert.
 */
import { type ChildProcess, spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { log } from './log.js';
import type { VolumeMount } from './providers/provider-container-registry.js';

const HOME_DIR = process.env.HOME || os.homedir();

/** Audit binary. Its presence is the enable switch; set empty to disable. */
const WRITEAUDIT_BIN = process.env.NANOCLAW_WRITEAUDIT_BIN ?? path.join(HOME_DIR, '.local', 'bin', 'writeaudit');

/**
 * Manifest store. Deliberately outside the project root and outside every
 * mount — same rationale as MOUNT_ALLOWLIST_PATH in config.ts. An agent that
 * could reach its own audit trail could rewrite it.
 */
const WRITEAUDIT_STORE =
  process.env.NANOCLAW_WRITEAUDIT_STORE || path.join(HOME_DIR, '.local', 'state', 'nanoclaw', 'writeaudit');

/** Hard ceiling on one pre/post invocation, so a wedged audit can't wedge a turn. */
const WRITEAUDIT_TIMEOUT_MS = 30_000;

export interface AuditRoot {
  label: string;
  hostPath: string;
}

export interface WriteAuditHandle {
  /** Idempotent, fire-and-forget: runs `post` and emits the diff report. */
  finish(): void;
}

const INERT: WriteAuditHandle = { finish: () => {} };

/**
 * Per-key phase queue. A container restart re-enters spawnContainer from the
 * dying container's `close` handler, so without this the new spawn's `pre`
 * could race the old run's `post` and the old report would pick up the new
 * spawn's freshly composed CLAUDE.md as an agent write.
 */
const phaseQueues = new Map<string, Promise<void>>();

/**
 * The writable surface to audit, derived from the mounts nanoclaw computed.
 *
 * Read-only mounts are dropped: the agent cannot write them. Read-only mounts
 * NESTED inside a writable root (container.json, the composed CLAUDE.md,
 * .claude-fragments) are deliberately NOT excluded from the walk — the tool
 * has no exclude flag, and they cannot produce false positives anyway. They
 * are regenerated at spawn time, before `pre` runs, and are read-only for the
 * container's whole life, so they hash identically in `pre` and `post`.
 *
 * Labels come from the container path, never the host path: the host session
 * dir embeds a session id, so host-derived labels would differ every run and
 * reports could not be compared. Container paths are stable and read the way
 * the agent saw them.
 */
export function auditRootsFromMounts(mounts: VolumeMount[]): AuditRoot[] {
  const roots: AuditRoot[] = [];
  const seen = new Set<string>();
  for (const mount of mounts) {
    if (mount.readonly) continue;
    const hostPath = path.resolve(mount.hostPath);
    if (seen.has(hostPath)) continue;
    seen.add(hostPath);
    roots.push({ label: auditLabel(mount.containerPath), hostPath });
  }
  // Keep only outermost roots — a root nested inside another would be walked
  // twice and double-counted. This is HOST nesting, not container nesting:
  // /workspace/agent sits under /workspace inside the container, but its host
  // path is a sibling of the session dir, so both survive.
  return roots
    .filter((root) => !roots.some((other) => other !== root && isInside(other.hostPath, root.hostPath)))
    .sort((a, b) => a.label.localeCompare(b.label));
}

/**
 * Snapshot the writable surface. Must be awaited immediately before the
 * container is spawned — every host-side write for this spawn has to be on
 * disk already or it lands in the diff as an agent write.
 */
export async function startWriteAudit(runId: string, key: string, mounts: VolumeMount[]): Promise<WriteAuditHandle> {
  let roots: AuditRoot[];
  try {
    if (!WRITEAUDIT_BIN || !fs.existsSync(WRITEAUDIT_BIN)) return INERT;
    roots = auditRootsFromMounts(mounts);
    if (roots.length === 0) return INERT;
    fs.mkdirSync(WRITEAUDIT_STORE, { recursive: true });
  } catch (err) {
    log.debug('Write audit setup failed — skipping', { runId, err });
    return INERT;
  }

  await enqueue(key, () => runPhase('pre', runId, roots));

  let finished = false;
  return {
    finish: () => {
      if (finished) return;
      finished = true;
      void enqueue(key, () => runPhase('post', runId, roots));
    },
  };
}

function enqueue(key: string, work: () => Promise<void>): Promise<void> {
  const next = (phaseQueues.get(key) ?? Promise.resolve()).then(work, work);
  phaseQueues.set(key, next);
  void next.then(() => {
    if (phaseQueues.get(key) === next) phaseQueues.delete(key);
  });
  return next;
}

/** Run one phase. Never rejects — the audit is advisory, the turn is not. */
function runPhase(phase: 'pre' | 'post', runId: string, roots: AuditRoot[]): Promise<void> {
  const args = [phase, '--run', runId, '--store', WRITEAUDIT_STORE];
  for (const root of roots) {
    args.push('--root', `${root.label}=${root.hostPath}`);
  }

  return new Promise<void>((resolve) => {
    let timer: NodeJS.Timeout | undefined;
    let settled = false;
    const settle = (): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve();
    };

    let child: ChildProcess;
    try {
      child = spawn(WRITEAUDIT_BIN, args, { stdio: 'ignore' });
    } catch (err) {
      log.debug('Write audit spawn threw', { phase, runId, err });
      settle();
      return;
    }

    timer = setTimeout(() => {
      log.warn('Write audit timed out — killing', { phase, runId, timeoutMs: WRITEAUDIT_TIMEOUT_MS });
      child.kill('SIGKILL');
      settle();
    }, WRITEAUDIT_TIMEOUT_MS);

    // ENOENT here means the binary vanished between existsSync and spawn.
    child.on('error', (err) => {
      log.debug('Write audit unavailable', { phase, runId, err });
      settle();
    });
    child.on('close', () => {
      log.debug('Write audit phase complete', { phase, runId, roots: roots.length });
      settle();
    });
  });
}

/**
 * Container paths are the label source. Slashes become underscores and
 * anything else outside a conservative set becomes a dash so a label can
 * never contain `=` and break `--root <label>=<hostPath>` parsing.
 */
function auditLabel(containerPath: string): string {
  const flattened = containerPath
    .replace(/^\/+/, '')
    .replace(/\/+/g, '_')
    .replace(/[^A-Za-z0-9._-]/g, '-');
  return flattened || 'root';
}

function isInside(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}
