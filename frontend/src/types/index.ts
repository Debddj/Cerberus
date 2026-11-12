export type DecisionType = 'allow' | 'flag' | 'block' | 'quarantine';

export interface ToolCallEvent {
  event_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  tool_server: string;
  parameters: Record<string, unknown>;
  parameter_size_bytes?: number;
  parameter_entropy?: number;
  destination_domain?: string | null;
  timestamp: number | string;
  time_since_previous_ms?: number | null;
  session_duration_ms?: number | null;
  sequence_position: number;
  risk_score?: number | null;
  risk_factors: string[];
  decision?: DecisionType | null;
  decision_reason?: string | null;
  redacted_fields: string[];
  trust_level?: 'verified' | 'unverified';
}

export interface AgentSummary {
  agent_id: string;
  agent_type?: string;
  status?: 'active' | 'flagged' | 'quarantined' | 'suspended';
  total_events: number;
  is_warm: boolean;
  active_snapshot: string | null;
  snapshots_count: number;
  known_tools: string[];
  authorized_tools?: string[];
  mcp_servers?: string[];
  current_risk_score?: number;
  last_activity?: number | string | null;
  trust_level: 'verified' | 'unverified';
}

export interface SessionSummary {
  session_id: string;
  agent_id: string;
  total_events: number;
  latest_risk_score: number;
  latest_decision?: DecisionType;
  trust_level: 'verified' | 'unverified';
}

export interface LatencyStats {
  p50: number;
  p95: number;
  p99: number;
  avg?: number;
  samples?: number;
}

export interface MetricsSummary {
  active_agents: number;
  active_sessions: number;
  unverified_agents: number;
  total_tool_calls?: number;
  allow_count?: number;
  flag_count?: number;
  block_count?: number;
  quarantine_count?: number;
  quarantined_sessions?: number;
  uptime_seconds?: number;
  latency_ms?: LatencyStats | null;
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
    [key: string]: unknown;
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

export interface AuditStatus {
  encrypt_logs: boolean;
  fernet_active: boolean;
  log_path: string;
  log_exists: boolean;
  total_entries: number;
  chain_head_hash: string;
  last_verified_at?: number | null;
  log_max_bytes: number;
  backup_count: number;
}

export interface Policy {
  name?: string;
  policy_id?: string;
  path?: string;
  type: 'active' | 'pending';
  enabled?: boolean;
  code?: string;
  created_at?: string;
  status?: string;
  agent_id?: string;
  tool_name?: string;
  risk_score?: number;
  factors?: string[];
}

export interface PolicyHistoryEntry {
  timestamp: string;
  action: string;
  policy_name: string;
  opa_pushed: boolean;
  detail: string;
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

export interface ScoreBreakdown {
  event_id: string;
  agent_id: string;
  session_id: string;
  tool_name: string;
  rule_score: number;
  markov_score: number;
  isolation_score: number;
  transformer_score: number;
  composite_score: number;
  tier_exited: number;
  decision: DecisionType;
  rule_factors: string[];
  markov_factors: string[];
  isolation_factors: string[];
  transformer_factors: string[];
  duration_ms: number;
  timestamp: number;
}

export interface BehaviorSummary {
  ensemble_weights: {
    rule: number;
    markov: number;
    isolation: number;
    transformer: number;
  };
  thresholds: {
    flag: number;
    block: number;
    quarantine: number;
  };
  markov: {
    tools: string[];
    counts: Record<string, Record<string, number>>;
    probabilities: Record<string, Record<string, number>>;
  };
  isolation_forest: {
    is_fitted: boolean;
    warm_threshold_calls: number;
    agent_observation_counts: Record<string, number>;
    scaler_stats: Record<string, { count: number; mean: number; M2: number }>;
  };
  transformer: {
    is_fitted: boolean;
    vocab: Record<string, number>;
    baseline_reconstruction_error: number;
    embedding_dim: number;
    hidden_dim: number;
    sequence_count: number;
  };
  rule_engine: {
    rules: Array<{
      id: string;
      name: string;
      floor: number;
      description: string;
    }>;
    recent_triggers: Array<{
      event_id: string;
      agent_id: string;
      tool_name: string;
      rule_score: number;
      factors: string[];
      timestamp: number;
    }>;
  };
  recent_breakdowns: ScoreBreakdown[];
}

export interface IncidentTimelineStep {
  step: string;
  sequence_position: number;
  event_id: string;
  tool_name: string;
  tool_server: string;
  parameters: Record<string, unknown>;
  destination_domain?: string | null;
  risk_score: number;
  decision: DecisionType;
  decision_reason?: string | null;
  risk_factors: string[];
  timestamp: string;
  breakdown?: ScoreBreakdown | null;
}

export interface IncidentRecord {
  incident_id: string;
  session_id: string;
  agent_id: string;
  severity: 'critical' | 'high' | 'medium';
  detection_time: string;
  peak_risk_score: number;
  enforcement_decision: DecisionType;
  quarantined: boolean;
  trifecta_detected: boolean;
  trifecta_breakdown: {
    private_data: string[];
    untrusted_content: string[];
    external_egress: string[];
  };
  triggered_rules: string[];
  total_calls: number;
  narrative: string;
  timeline: IncidentTimelineStep[];
}

export interface TestingStepResult {
  event_id: string;
  tool_name: string;
  tool_server: string;
  destination_domain?: string | null;
  risk_score: number;
  decision: DecisionType;
  decision_reason?: string | null;
  risk_factors: string[];
  duration_ms: number;
  breakdown?: Partial<ScoreBreakdown>;
}

export interface TestingRunResult {
  run_id: string;
  scenario_id: string;
  scenario_name: string;
  category: string;
  session_id: string;
  agent_id: string;
  execution_mode: 'live_backend_engine' | 'offline_simulation';
  executed_at: string;
  duration_ms: number;
  peak_risk_score: number;
  final_decision: DecisionType;
  threats_detected: string[];
  steps: TestingStepResult[];
}

export interface AnalyticsPayload {
  live_telemetry: {
    total_calls: number;
    decision_counts: Record<DecisionType, number>;
    risk_histogram: Array<{ bucket: string; count: number }>;
    measured_latency_ms: LatencyStats | null;
    measurement_status: 'live' | 'pending_measurement';
  };
  evaluation_benchmark: {
    timestamp?: number;
    summary?: {
      standard_tpr: number;
      evasion_tpr: number;
      overall_fpr: number;
      archetype_fpr: Record<string, number>;
      latency: LatencyStats;
    };
    standard_scenarios?: Record<
      string,
      { detected: boolean; detection_call_num: number | null; risk_score: number; reason: string }
    >;
    evasion_scenarios?: Record<
      string,
      {
        detected: boolean;
        detection_call_num: number | null;
        risk_score: number;
        status?: string;
        analysis?: string;
      }
    >;
    scorer_comparison?: Record<
      string,
      { avg_tpr_std: number; avg_tpr_evasion: number; avg_fpr: number }
    >;
  } | null;
  ablation_study: Array<{
    name: string;
    desc: string;
    tp: number;
    fn: number;
    fp: number;
    tn: number;
    tpr: number;
    fpr: number;
    precision: number;
    recall: number;
    f1: number;
    p50_ms: number;
    p95_ms: number;
    p99_ms: number;
  }> | null;
  ensemble_weights: {
    rule: number;
    markov: number;
    isolation: number;
    transformer: number;
  };
}

export interface SystemConfig {
  mode: 'enforce' | 'audit';
  fail_closed: boolean;
  require_signed_identity: boolean;
  rate_limit_per_minute: number;
  risk_flag_threshold: number;
  risk_block_threshold: number;
  risk_quarantine_threshold: number;
  scope_enforcement_mode: 'learn' | 'strict';
  trifecta_override: boolean;
  encrypt_logs: boolean;
  opa_url: string;
  opa_connected: boolean;
  uptime_seconds: number;
}

export interface SocUser {
  username: string;
  display_name: string;
  role: string;
}

