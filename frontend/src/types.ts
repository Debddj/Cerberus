export interface ModelScores {
  rule: number;
  markov: number;
  isolation: number;
  transformer: number;
}

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
  decision?: 'allow' | 'flag' | 'challenge' | 'block' | 'quarantine' | null;
  decision_reason?: string | null;
  redacted_fields: string[];
  trust_level?: 'verified' | 'unverified';
  model_scores?: ModelScores;
  owasp_tags?: string[];
  rule_fired?: string | null;
}

export interface SessionSummary {
  session_id: string;
  agent_id: string;
  total_events: number;
  latest_risk_score: number;
  latest_decision?: 'allow' | 'flag' | 'challenge' | 'block' | 'quarantine';
  trust_level: 'verified' | 'unverified';
  is_quarantined?: boolean;
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

export interface ChallengeItem {
  challenge_id: string;
  event_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  tool_server: string;
  risk_score: number;
  risk_factors: string[];
  timestamp: number;
  expires_at: number;
  timeout_seconds?: number;
  step_up_token?: string;
  webhook_dispatched?: boolean;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  parameters?: Record<string, any>;
  resolved_by?: string;
  resolution_reason?: string;
  resolved_at?: number;
}

export interface SchemaPin {
  server_url: string;
  tool_name: string;
  description_hash: string;
  schema_hash: string;
  first_seen: string;
  last_verified: string;
  pin_version: number;
  old_description?: string;
  new_description?: string;
}

export interface ScannerSummary {
  scope_matrix: Record<string, string[]>;
  scope_mode: string;
  shadow_registry: Record<string, string>;
  redactions: Record<string, number>;
  schema_pins: SchemaPin[];
}

export interface IssuedToken {
  status: string;
  agent_id: string;
  ttl_seconds: number;
  token: string;
  created_at: number;
  expires_at?: number;
}

export interface BenchmarkResults {
  standard_attack_tpr: number;
  evasion_attack_tpr: number;
  false_positive_rate: number;
  latency_overhead_ms: {
    p50: number;
    p95: number;
    p99: number;
  };
  ablation_study?: {
    model: string;
    std_tpr: number;
    evasion_tpr: number;
    fpr: number;
  }[];
  ci_intervals?: {
    metric: string;
    point_estimate: string;
    ci_95: string;
    sample_size: string;
  }[];
}

// ── Industry-Grade Security Feature Interfaces ──────────────────────────────

export interface TaintProvenanceNode {
  step: number;
  session_id: string;
  tool_name: string;
  tool_server: string;
  action: 'source' | 'propagated' | 'egress_blocked' | 'sink' | string;
  timestamp: string;
  matched_tag_ids: string[];
  matched_parameters: string[];
  details?: string;
}

export interface TaintAlert {
  timestamp: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  reason: string;
  alert_type: string;
  factors: string[];
}

export interface CanaryTokenRecord {
  token: string;
  raw_token?: string;
  token_type: string;
  created_at: string;
  description: string;
  metadata?: Record<string, any>;
  status?: 'ARMED' | 'TRIPPED';
}

export interface CanaryAlert {
  timestamp: string;
  alert_type: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  destination?: string;
  token_type: string;
  matched_token: string;
  location?: string;
  snippet?: string;
}

export interface DLPQuotaUsage {
  agent_id: string;
  current_window_bytes: number;
  max_bytes: number;
  bytes_used_pct: number;
  unique_destinations_count: number;
  max_destinations: number;
  destinations: string[];
  window_seconds: number;
  window_expires_in_seconds?: number;
}

export interface DLPQuotaSummary {
  max_bytes_per_window: number;
  window_seconds: number;
  max_destinations_per_window: number;
  agents: Record<string, DLPQuotaUsage>;
}

export interface DLPAlert {
  timestamp: string;
  alert_type: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  findings?: {
    category: string;
    snippet: string;
    path: string;
  }[];
  violation_type?: string;
  bytes_requested?: number;
  quota_limit?: number;
  reason?: string;
}

export interface ResponseViolation {
  session_id: string;
  risk_score: number;
  reason: string;
  sanitized: boolean;
  match_count: number;
  adjudicated: boolean;
  adjudicator_verdict?: string | null;
  confidence?: number;
  original_payload?: string;
  sanitized_payload?: string;
}

export interface ResponseInspectionSummary {
  flagged_sessions_count: number;
  flagged_sessions: string[];
  total_violations: number;
  recent_violations: ResponseViolation[];
}
