import fs from 'fs';
import path from 'path';
import { describe, expect, it } from 'vitest';

import { auditRootsFromMounts } from './write-audit.js';

/** The three RW mounts buildMounts() produces for a default (claude) group. */
const DEFAULT_MOUNTS = [
  { hostPath: '/srv/nanoclaw/data/v2-sessions/ag-1/sess-2', containerPath: '/workspace', readonly: false },
  { hostPath: '/srv/nanoclaw/groups/main', containerPath: '/workspace/agent', readonly: false },
  {
    hostPath: '/srv/nanoclaw/groups/main/container.json',
    containerPath: '/workspace/agent/container.json',
    readonly: true,
  },
  { hostPath: '/srv/nanoclaw/container/agent-runner/src', containerPath: '/app/src', readonly: true },
  {
    hostPath: '/srv/nanoclaw/data/v2-sessions/ag-1/.claude-shared',
    containerPath: '/home/node/.claude',
    readonly: false,
  },
];

describe('auditRootsFromMounts', () => {
  it('keeps exactly the writable mounts', () => {
    expect(auditRootsFromMounts(DEFAULT_MOUNTS)).toEqual([
      { label: 'home_node_.claude', hostPath: '/srv/nanoclaw/data/v2-sessions/ag-1/.claude-shared' },
      { label: 'workspace', hostPath: '/srv/nanoclaw/data/v2-sessions/ag-1/sess-2' },
      { label: 'workspace_agent', hostPath: '/srv/nanoclaw/groups/main' },
    ]);
  });

  it('labels from the container path, so no session id or timestamp leaks in', () => {
    const labels = auditRootsFromMounts(DEFAULT_MOUNTS).map((r) => r.label);
    for (const label of labels) {
      expect(label).not.toMatch(/sess-|ag-1|\d{10}/);
    }
  });

  it('keeps /workspace and /workspace/agent apart — they nest in the container, not on the host', () => {
    const labels = auditRootsFromMounts(DEFAULT_MOUNTS).map((r) => r.label);
    expect(labels).toContain('workspace');
    expect(labels).toContain('workspace_agent');
  });

  it('returns nothing when every mount is read-only', () => {
    expect(auditRootsFromMounts(DEFAULT_MOUNTS.filter((m) => m.readonly))).toEqual([]);
  });

  it('drops a root nested inside another writable root on the host', () => {
    const roots = auditRootsFromMounts([
      { hostPath: '/srv/work', containerPath: '/workspace', readonly: false },
      { hostPath: '/srv/work/nested', containerPath: '/workspace/extra/nested', readonly: false },
    ]);
    expect(roots).toEqual([{ label: 'workspace', hostPath: '/srv/work' }]);
  });

  it('dedupes the same host path mounted twice', () => {
    const roots = auditRootsFromMounts([
      { hostPath: '/srv/work', containerPath: '/workspace', readonly: false },
      { hostPath: '/srv/work/', containerPath: '/workspace/extra/again', readonly: false },
    ]);
    expect(roots).toHaveLength(1);
  });

  it('sanitizes a label that would break --root <label>=<hostPath> parsing', () => {
    const [root] = auditRootsFromMounts([
      { hostPath: '/srv/odd', containerPath: '/workspace/extra/a=b c', readonly: false },
    ]);
    expect(root.label).toBe('workspace_extra_a-b-c');
    expect(root.label).not.toContain('=');
  });
});

describe('write-audit hook placement (structural)', () => {
  // The audit's whole value is that the pre-manifest predates any container
  // write. Anything spawned before `startWriteAudit` resolves would have its
  // writes attributed to the host instead of the agent — and any host-side
  // write placed after it would be attributed to the agent. Driving a real
  // spawn needs a container runtime, so guard the ordering structurally,
  // matching the other invariant tests in container-runner.test.ts.
  const src = fs.readFileSync(path.join(process.cwd(), 'src', 'container-runner.ts'), 'utf-8');

  it('awaits startWriteAudit before spawning the container', () => {
    const started = src.indexOf('await startWriteAudit(');
    const spawned = src.indexOf('spawn(CONTAINER_RUNTIME_BIN');
    expect(started).toBeGreaterThan(-1);
    expect(spawned).toBeGreaterThan(started);
  });

  it('takes the pre-snapshot after the heartbeat unlink, which writes into the audited session dir', () => {
    expect(src.indexOf('fs.rmSync(heartbeatPath(')).toBeLessThan(src.indexOf('await startWriteAudit('));
  });

  it('finishes the audit from both the close and the error handler', () => {
    expect(src).toMatch(/container\.on\('close'[\s\S]{0,400}?audit\.finish\(\)/);
    expect(src).toMatch(/container\.on\('error'[\s\S]{0,400}?audit\.finish\(\)/);
  });
});
