import { 
  ToolCallEvent, 
  SessionSummary, 
  MetricsSummary, 
  HealthStatus, 
  AuditRecord, 
  AuditVerifyResult, 
  Policy, 
  BaselineAgent,
  ChallengeItem,
  ScannerSummary,
  IssuedToken,
  BenchmarkResults
} from './types';

const API_BASE = '';

export async function fetchMetrics(): Promise<MetricsSummary> {
  const res = await fetch(`${API_BASE}/api/metrics/summary`);
  if (!res.ok) throw new Error('Failed to fetch metrics');
  return res.json();
}

export async function fetchHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API_BASE}/healthz`);
  if (!res.ok) throw new Error('Failed to fetch healthz');
  return res.json();
}

export async function fetchEvents(limit: number = 50): Promise<ToolCallEvent[]> {
  const res = await fetch(`${API_BASE}/api/events?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch events');
  return res.json();
}

export async function fetchSessions(): Promise<SessionSummary[]> {
  const res = await fetch(`${API_BASE}/api/sessions`);
  if (!res.ok) throw new Error('Failed to fetch sessions');
  return res.json();
}

export async function fetchSessionEvents(sessionId: string): Promise<ToolCallEvent[]> {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/events`);
  if (!res.ok) throw new Error('Failed to fetch session events');
  return res.json();
}

export async function fetchAuditLogs(limit: number = 50): Promise<AuditRecord[]> {
  const res = await fetch(`${API_BASE}/api/audit/logs?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch audit logs');
  return res.json();
}

export async function verifyAuditLedger(): Promise<AuditVerifyResult> {
  const res = await fetch(`${API_BASE}/api/audit/verify`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to verify audit ledger');
  return res.json();
}

export async function fetchPolicies(): Promise<{ active: Policy[]; pending: Policy[] }> {
  const res = await fetch(`${API_BASE}/api/policies`);
  if (!res.ok) throw new Error('Failed to fetch policies');
  return res.json();
}

export async function approvePolicy(policyId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/admin/policies/${policyId}/approve`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to approve policy');
  return res.json();
}

export async function rejectPolicy(policyId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/admin/policies/${policyId}/reject`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reject policy');
  return res.json();
}

export async function fetchBaselines(): Promise<BaselineAgent[]> {
  const res = await fetch(`${API_BASE}/api/baselines`);
  if (!res.ok) throw new Error('Failed to fetch baselines');
  return res.json();
}

export async function promoteBaseline(agentId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/baselines/${agentId}/promote`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to promote baseline');
  return res.json();
}

export async function simulatePolicy(payload: any): Promise<any> {
  const res = await fetch(`${API_BASE}/policy/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Simulation failed');
  return res.json();
}

export function subscribeToEventStream(onEvent: (event: ToolCallEvent) => void): () => void {
  const source = new EventSource(`${API_BASE}/api/events/stream`);
  source.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      onEvent(data);
    } catch (err) {
      // Heartbeat or malformed
    }
  };
  return () => source.close();
}

export async function fetchScannersSummary(): Promise<ScannerSummary> {
  const res = await fetch(`${API_BASE}/api/scanners/summary`);
  if (!res.ok) throw new Error('Failed to fetch scanners summary');
  return res.json();
}

export async function fetchChallenges(): Promise<ChallengeItem[]> {
  const res = await fetch(`${API_BASE}/api/challenges`);
  if (!res.ok) throw new Error('Failed to fetch challenges');
  return res.json();
}

export async function resolveChallenge(
  challengeId: string, 
  action: 'approve' | 'reject', 
  reason?: string
): Promise<any> {
  const res = await fetch(`${API_BASE}/api/challenges/${challengeId}/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, reason }),
  });
  if (!res.ok) throw new Error('Failed to resolve challenge');
  return res.json();
}

export async function quarantineSession(sessionId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/quarantine`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to quarantine session');
  return res.json();
}

export async function issueToken(agentId: string, ttl: number = 3600): Promise<IssuedToken> {
  const res = await fetch(`${API_BASE}/api/tokens/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_id: agentId, ttl_seconds: ttl }),
  });
  if (!res.ok) throw new Error('Failed to issue token');
  return res.json();
}

export async function fetchBenchmarks(): Promise<BenchmarkResults> {
  const res = await fetch(`${API_BASE}/api/benchmarks`);
  if (!res.ok) throw new Error('Failed to fetch benchmarks');
  return res.json();
}
