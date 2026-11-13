export interface ToolCallEvent {
  event_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  tool_server: string;
  parameters: Record<string, any>;
  parameter_size_bytes?: number;
  parameter_entropy?: number;
  destination_domain?: string | null;
  timestamp: string | number;
  time_since_previous_ms?: number | null;
  session_duration_ms?: number | null;
  sequence_position: number;
  risk_score?: number | null;
  risk_factors: string[];
  decision?: 'allow' | 'flag' | 'block' | 'quarantine' | null;
  decision_reason?: string | null;
  redacted_fields: string[];
  trust_level?: 'verified' | 'unverified';
}

export interface SessionSummary {
  session_id: string;
  agent_id: string;
  total_events: number;
  latest_risk_score: number;
  latest_decision?: 'allow' | 'flag' | 'block' | 'quarantine';
  trust_level: 'verified' | 'unverified';
}

export interface MetricsSummary {
  active_agents: number;
  active_sessions: number;
  unverified_agents: number;
  mode: string;
  fail_closed: boolean;
  require_signed_identity: boolean;
  rate_limit_per_minute: number;
}

export interface HealthStatus {
  status: string;
  version: string;
  mode: string;
  opa_url: string;
  fail_closed: boolean;
  active_unverified_agents: number;
  unverified_agents: string[];
  storage: {
    status: string;
    backend: string;
    [key: string]: any;
  };
}

export interface AuditRecord {
  index: number;
  prev_hash: string;
  hash: string;
  event: ToolCallEvent;
}

export interface AuditVerifyResult {
  is_valid: boolean;
  total_entries: number;
  error?: string | null;
  log_path: string;
}

export interface Policy {
  name?: string;
  policy_id?: string;
  path?: string;
  type: 'active' | 'pending';
  code?: string;
  created_at?: string;
  status?: string;
  agent_id?: string;
  tool_name?: string;
  risk_score?: number;
  factors?: string[];
}

export interface BaselineSnapshot {
  snapshot_id: string;
  created_at: string;
  calls_in_snapshot: number;
  is_active: boolean;
}

export interface BaselineAgent {
  agent_id: string;
  active_snapshot_id: string;
  snapshots_count: number;
  known_tools: string[];
  known_destinations: string[];
  snapshots: BaselineSnapshot[];
}
