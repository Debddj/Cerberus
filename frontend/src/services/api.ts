import type {
  AgentSummary,
  AnalyticsPayload,
  AuditRecord,
  AuditStatus,
  AuditVerifyResult,
  BaselineAgent,
  BehaviorSummary,
  HealthStatus,
  IncidentRecord,
  MetricsSummary,
  Policy,
  PolicyHistoryEntry,
  SessionSummary,
  SocUser,
  SystemConfig,
  TestingRunResult,
  ToolCallEvent,
} from '../types';
import {
  DEMO_AGENTS,
  DEMO_ANALYTICS,
  DEMO_AUDIT_RECORDS,
  DEMO_AUDIT_STATUS,
  DEMO_BEHAVIOR,
  DEMO_EVENTS,
  DEMO_HEALTH,
  DEMO_INCIDENTS,
  DEMO_METRICS,
  DEMO_POLICIES,
  DEMO_SYSTEM_CONFIG,
  simulateOfflineTestingRun,
} from './mockAdapter';

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) || '';

export interface ApiResult<T> {
  data: T;
  source: 'live' | 'offline-demo';
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const token = localStorage.getItem('cerberus_soc_token');
  const headers = new Headers(init?.headers || {});
  if (!headers.has('Content-Type') && init?.body) {
    headers.set('Content-Type', 'application/json');
  }
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      msg = body.detail || body.message || msg;
    } catch {
      // ignore json parse error
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

export async function loginSoc(
  username: string,
  password: string
): Promise<{
  authenticated: boolean;
  token: string;
  user: SocUser;
  source: 'live' | 'offline-demo';
}> {
  try {
    const res = await requestJson<{
      authenticated: boolean;
      token: string;
      user: SocUser;
    }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    return { ...res, source: 'live' };
  } catch (err) {
    const message = err instanceof Error ? err.message : '';
    if (message.startsWith('HTTP 401')) {
      throw err;
    }
    // Backend unreachable: allow explicit offline demo login for local preview
    if (username.trim() === 'admin' && password === 'cerberus-soc') {
      return {
        authenticated: true,
        token: 'offline-demo-token',
        user: {
          username: 'admin',
          display_name: 'SOC Lead Analyst (Offline Preview)',
          role: 'Demo Administrator',
        },
        source: 'offline-demo',
      };
    }
    throw err;
  }
}

export async function checkSocSession(): Promise<{
  authenticated: boolean;
  user?: SocUser;
}> {
  const token = localStorage.getItem('cerberus_soc_token');
  if (!token) return { authenticated: false };
  if (token === 'offline-demo-token') {
    return {
      authenticated: true,
      user: {
        username: 'admin',
        display_name: 'SOC Lead Analyst (Offline Preview)',
        role: 'Demo Administrator',
      },
    };
  }
  try {
    return await requestJson<{ authenticated: boolean; user?: SocUser }>('/api/auth/session');
  } catch {
    return { authenticated: false };
  }
}

export async function fetchMetrics(): Promise<ApiResult<MetricsSummary>> {
  try {
    const data = await requestJson<MetricsSummary>('/api/metrics/summary');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_METRICS, source: 'offline-demo' };
  }
}

export async function fetchHealth(): Promise<ApiResult<HealthStatus>> {
  try {
    const data = await requestJson<HealthStatus>('/healthz');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_HEALTH, source: 'offline-demo' };
  }
}

export async function fetchEvents(limit = 100): Promise<ApiResult<ToolCallEvent[]>> {
  try {
    const data = await requestJson<ToolCallEvent[]>(`/api/events?limit=${limit}`);
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_EVENTS, source: 'offline-demo' };
  }
}

export async function fetchAgents(): Promise<ApiResult<AgentSummary[]>> {
  try {
    const data = await requestJson<AgentSummary[]>('/api/agents');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_AGENTS, source: 'offline-demo' };
  }
}

export async function registerAgent(payload: {
  agent_id: string;
  agent_type: string;
  mcp_servers: string[];
  authorized_tools: string[];
  enforce_scope: boolean;
  issue_token: boolean;
  description?: string;
}): Promise<AgentSummary & { token?: string | null }> {
  return requestJson('/api/agents', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function suspendAgent(agentId: string): Promise<{ agent_id: string; status: string }> {
  return requestJson(`/api/agents/${encodeURIComponent(agentId)}/suspend`, { method: 'POST' });
}

export async function activateAgent(agentId: string): Promise<{ agent_id: string; status: string }> {
  return requestJson(`/api/agents/${encodeURIComponent(agentId)}/activate`, { method: 'POST' });
}

export async function issueAgentToken(
  agentId: string,
  ttlSeconds = 3600
): Promise<{ agent_id: string; token: string; ttl_seconds: number }> {
  return requestJson(`/api/agents/${encodeURIComponent(agentId)}/token?ttl_seconds=${ttlSeconds}`, {
    method: 'POST',
  });
}

export async function deleteAgent(agentId: string): Promise<{ agent_id: string; deleted: boolean }> {
  return requestJson(`/api/agents/${encodeURIComponent(agentId)}`, { method: 'DELETE' });
}

export async function fetchAgentBaseline(agentId: string): Promise<BaselineAgent | null> {
  try {
    return await requestJson<BaselineAgent>(`/api/agents/${encodeURIComponent(agentId)}/baseline`);
  } catch {
    return null;
  }
}

export async function fetchSessions(): Promise<SessionSummary[]> {
  try {
    return await requestJson<SessionSummary[]>('/api/sessions');
  } catch {
    return [];
  }
}

export async function fetchBehaviorSummary(): Promise<ApiResult<BehaviorSummary>> {
  try {
    const data = await requestJson<BehaviorSummary>('/api/behavior');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_BEHAVIOR, source: 'offline-demo' };
  }
}

export async function fetchPolicies(): Promise<ApiResult<{ active: Policy[]; pending: Policy[] }>> {
  try {
    const data = await requestJson<{ active: Policy[]; pending: Policy[] }>('/api/policies');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_POLICIES, source: 'offline-demo' };
  }
}

export async function createPolicy(payload: {
  name: string;
  code: string;
  push_to_opa: boolean;
}): Promise<{ saved: boolean; name: string; opa_pushed: boolean; opa_error?: string | null }> {
  return requestJson('/api/policies', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updatePolicy(
  policyName: string,
  payload: { code: string; push_to_opa: boolean }
): Promise<{ saved: boolean; name: string; opa_pushed: boolean; opa_error?: string | null }> {
  return requestJson(`/api/policies/${encodeURIComponent(policyName)}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export async function togglePolicy(policyName: string): Promise<{ name: string; enabled: boolean }> {
  return requestJson(`/api/policies/${encodeURIComponent(policyName)}/toggle`, { method: 'POST' });
}

export async function fetchPolicyHistory(): Promise<PolicyHistoryEntry[]> {
  try {
    return await requestJson<PolicyHistoryEntry[]>('/api/policies/history');
  } catch {
    return [];
  }
}

export async function approvePolicy(policyId: string): Promise<{ status: string; policy_id: string }> {
  return requestJson(`/admin/policies/${encodeURIComponent(policyId)}/approve`, { method: 'POST' });
}

export async function rejectPolicy(policyId: string): Promise<{ status: string; policy_id: string }> {
  return requestJson(`/admin/policies/${encodeURIComponent(policyId)}/reject`, { method: 'POST' });
}

export async function simulatePolicy(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  return requestJson('/policy/simulate', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchBaselines(): Promise<BaselineAgent[]> {
  try {
    return await requestJson<BaselineAgent[]>('/api/baselines');
  } catch {
    return [];
  }
}

export async function promoteBaseline(agentId: string): Promise<{
  agent_id: string;
  active_snapshot_id: string;
  snapshots_count: number;
}> {
  return requestJson(`/baselines/${encodeURIComponent(agentId)}/promote`, { method: 'POST' });
}

export async function fetchIncidents(): Promise<ApiResult<IncidentRecord[]>> {
  try {
    const data = await requestJson<IncidentRecord[]>('/api/incidents');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_INCIDENTS, source: 'offline-demo' };
  }
}

export async function quarantineSession(sessionId: string): Promise<{ session_id: string; quarantined: boolean }> {
  return requestJson(`/api/incidents/${encodeURIComponent(sessionId)}/quarantine`, { method: 'POST' });
}

export async function fetchAuditLogs(limit = 100): Promise<ApiResult<AuditRecord[]>> {
  try {
    const data = await requestJson<AuditRecord[]>(`/api/audit/logs?limit=${limit}`);
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_AUDIT_RECORDS, source: 'offline-demo' };
  }
}

export async function fetchAuditStatus(): Promise<ApiResult<AuditStatus>> {
  try {
    const data = await requestJson<AuditStatus>('/api/audit/status');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_AUDIT_STATUS, source: 'offline-demo' };
  }
}

export async function verifyAuditLedger(): Promise<AuditVerifyResult> {
  return requestJson('/api/audit/verify', { method: 'POST' });
}

export function getAuditExportUrl(): string {
  return `${API_BASE}/api/audit/export`;
}

export async function runTestingScenario(
  scenarioId: string,
  agentId?: string
): Promise<TestingRunResult> {
  try {
    return await requestJson<TestingRunResult>('/api/testing/run', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: scenarioId, agent_id: agentId }),
    });
  } catch {
    return simulateOfflineTestingRun(scenarioId);
  }
}

export async function fetchTestingHistory(): Promise<TestingRunResult[]> {
  try {
    return await requestJson<TestingRunResult[]>('/api/testing/history');
  } catch {
    return [];
  }
}

export async function fetchAnalytics(): Promise<ApiResult<AnalyticsPayload>> {
  try {
    const data = await requestJson<AnalyticsPayload>('/api/analytics');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_ANALYTICS, source: 'offline-demo' };
  }
}

export async function fetchSystemConfig(): Promise<ApiResult<SystemConfig>> {
  try {
    const data = await requestJson<SystemConfig>('/api/system/config');
    return { data, source: 'live' };
  } catch {
    return { data: DEMO_SYSTEM_CONFIG, source: 'offline-demo' };
  }
}

export async function updateSystemConfig(
  patch: Partial<SystemConfig>
): Promise<SystemConfig> {
  return requestJson('/api/system/config', {
    method: 'PUT',
    body: JSON.stringify(patch),
  });
}

export async function sendMcpToolCall(payload: {
  agent_id: string;
  session_id: string;
  tool_name: string;
  tool_server?: string;
  arguments: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  return requestJson('/mcp', {
    method: 'POST',
    headers: {
      'X-Agent-ID': payload.agent_id,
      'X-Session-ID': payload.session_id,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method: 'tools/call',
      params: {
        name: payload.tool_name,
        server: payload.tool_server || 'sandbox-server',
        arguments: payload.arguments,
      },
    }),
  });
}

export function subscribeToEventStream(
  onEvent: (event: ToolCallEvent) => void,
  onStatusChange?: (connected: boolean) => void
): () => void {
  const source = new EventSource(`${API_BASE}/api/events/stream`);
  source.onopen = () => onStatusChange?.(true);
  source.onerror = () => onStatusChange?.(false);
  source.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data) as ToolCallEvent;
      onStatusChange?.(true);
      onEvent(data);
    } catch {
      // ignore heartbeat
    }
  };
  return () => source.close();
}

