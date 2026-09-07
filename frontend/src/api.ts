import { 
  ToolCallEvent, 
  SessionSummary, 
  MetricsSummary, 
  HealthStatus, 
  AuditRecord, 
  AuditVerifyResult, 
  Policy, 
  BaselineAgent 
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
