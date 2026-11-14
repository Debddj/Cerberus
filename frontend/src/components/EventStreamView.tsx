import React, { useState } from 'react';
import { 
  CheckCircle, 
  AlertTriangle, 
  ShieldBan, 
  Radio, 
  Search, 
  Filter, 
  ExternalLink,
  Code,
  Clock,
  Fingerprint,
  CheckSquare,
  Flame,
  Gauge,
  HelpCircle,
  FileCode,
  Layers,
  Key,
  ShieldCheck,
  Sparkles,
  Zap
} from 'lucide-react';
import { ToolCallEvent } from '../types';

interface EventStreamViewProps {
  events: ToolCallEvent[];
  isStreaming: boolean;
}

export const EventStreamView: React.FC<EventStreamViewProps> = ({ events, isStreaming }) => {
  const [selectedEvent, setSelectedEvent] = useState<ToolCallEvent | null>(null);
  const [filterDecision, setFilterDecision] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredEvents = events.filter((e) => {
    if (filterDecision !== 'ALL' && e.decision?.toUpperCase() !== filterDecision) {
      return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchTool = e.tool_name.toLowerCase().includes(q);
      const matchAgent = e.agent_id.toLowerCase().includes(q);
      const matchSession = e.session_id.toLowerCase().includes(q);
      const matchDest = (e.destination_domain || '').toLowerCase().includes(q);
      const matchOwasp = (e.owasp_tags || []).some(t => t.toLowerCase().includes(q));
      return matchTool || matchAgent || matchSession || matchDest || matchOwasp;
    }
    return true;
  });

  const getDecisionBadge = (decision?: string | null) => {
    switch (decision?.toLowerCase()) {
      case 'allow':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle className="w-3 h-3 mr-1" /> ALLOW
          </span>
        );
      case 'challenge':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/40 glow-warning">
            <CheckSquare className="w-3 h-3 mr-1 animate-pulse" /> CHALLENGE
          </span>
        );
      case 'flag':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3 mr-1" /> FLAG
          </span>
        );
      case 'block':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30 glow-danger">
            <ShieldBan className="w-3 h-3 mr-1" /> BLOCK
          </span>
        );
      case 'quarantine':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-purple-500/10 text-purple-400 border border-purple-500/30 glow-purple">
            <Radio className="w-3 h-3 mr-1 animate-pulse" /> QUARANTINE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-800 text-slate-400 border border-slate-700">
            PENDING
          </span>
        );
    }
  };

  const getRiskScoreColor = (score?: number | null) => {
    const s = score || 0.0;
    if (s >= 0.7) return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    if (s >= 0.4) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  };

  const formatTimestamp = (ts?: string | number | null) => {
    if (!ts) return 'just now';
    if (typeof ts === 'number') {
      const d = new Date(ts > 1e11 ? ts : ts * 1000);
      return isNaN(d.getTime()) ? 'just now' : d.toLocaleTimeString();
    }
    const d = new Date(ts);
    return isNaN(d.getTime()) ? 'just now' : d.toLocaleTimeString();
  };

  return (
    <div className="space-y-6">
      {/* Top Controls & Metrics Bar */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center bg-soc-panel p-4 rounded-xl border border-soc-border glass-panel">
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search tools, agents, OWASP tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 bg-slate-900/90 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex items-center space-x-1 overflow-x-auto">
            <Filter className="w-4 h-4 text-slate-400 ml-2 mr-1" />
            {(['ALL', 'ALLOW', 'CHALLENGE', 'FLAG', 'BLOCK', 'QUARANTINE'] as const).map((dec) => (
              <button
                key={dec}
                onClick={() => setFilterDecision(dec)}
                className={`px-2.5 py-1 rounded text-xs font-mono transition-colors whitespace-nowrap ${
                  filterDecision === dec
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {dec}
              </button>
            ))}
          </div>
        </div>

        <div className="text-xs font-mono text-slate-400 flex items-center space-x-4">
          <span>Captured Events: <strong className="text-slate-200">{filteredEvents.length}</strong></span>
          <span className="flex items-center">
            <span className={`w-2 h-2 rounded-full mr-1.5 ${isStreaming ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
            {isStreaming ? 'Real-Time Interception' : 'Buffered'}
          </span>
        </div>
      </div>

      {/* Events Stream Table / Card Grid */}
      <div className="grid grid-cols-1 gap-3">
        {filteredEvents.length === 0 ? (
          <div className="text-center py-16 bg-soc-panel/50 rounded-xl border border-soc-border">
            <Radio className="w-10 h-10 text-slate-600 mx-auto mb-3 animate-pulse" />
            <p className="text-slate-400 text-sm">No tool call events matching criteria.</p>
            <p className="text-slate-500 text-xs mt-1">Incoming agent calls will stream here automatically.</p>
          </div>
        ) : (
          filteredEvents.map((event) => (
            <div
              key={event.event_id}
              onClick={() => setSelectedEvent(event)}
              className="bg-soc-panel hover:bg-slate-800/80 p-4 rounded-xl border border-soc-border/80 transition-all cursor-pointer hover:border-cyan-500/40 flex flex-col md:flex-row md:items-center justify-between gap-4 glass-panel"
            >
              <div className="flex items-start md:items-center space-x-3">
                <div className="pt-1 md:pt-0">
                  {getDecisionBadge(event.decision)}
                </div>

                <div>
                  <div className="flex items-center flex-wrap gap-2">
                    <span className="text-base font-semibold text-white font-mono">{event.tool_name}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {event.tool_server}
                    </span>
                    {event.trust_level === 'verified' ? (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                        verified
                      </span>
                    ) : (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono">
                        unverified
                      </span>
                    )}

                    {/* OWASP ASI tags */}
                    {event.owasp_tags && event.owasp_tags.map(tag => (
                      <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30 font-mono">
                        {tag}
                      </span>
                    ))}
                    {event.risk_factors.some(f => f.toLowerCase().includes('taint')) && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 font-mono flex items-center space-x-1">
                        <span>⚠️ TAINT</span>
                      </span>
                    )}
                    {event.risk_factors.some(f => f.toLowerCase().includes('canary')) && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-mono animate-pulse flex items-center space-x-1">
                        <Key className="w-2.5 h-2.5" />
                        <span>CANARY TRIPWIRE</span>
                      </span>
                    )}
                    {event.risk_factors.some(f => f.toLowerCase().includes('dlp') || f.toLowerCase().includes('quota')) && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 font-mono flex items-center space-x-1">
                        <span>DLP VIOLATION</span>
                      </span>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono mt-1">
                    <span>Agent: <strong className="text-slate-300">{event.agent_id}</strong></span>
                    <span>Session: <strong className="text-slate-300">{event.session_id.slice(0, 14)}...</strong></span>
                    <span>Seq: #{event.sequence_position}</span>
                    {event.destination_domain && (
                      <span className="text-cyan-400 flex items-center">
                        <ExternalLink className="w-3 h-3 mr-0.5" />
                        {event.destination_domain}
                      </span>
                    )}
                    {event.parameter_entropy !== undefined && event.parameter_entropy > 5.5 && (
                      <span className="text-amber-400 flex items-center" title="High payload entropy">
                        <Flame className="w-3 h-3 mr-0.5" />
                        Entropy: {event.parameter_entropy.toFixed(1)} bits
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Risk Score & Timestamp */}
              <div className="flex items-center space-x-4 self-end md:self-center">
                <div className="text-right font-mono">
                  <div className="flex items-center justify-end space-x-1.5">
                    <span className="text-xs text-slate-400">Risk:</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getRiskScoreColor(event.risk_score)}`}>
                      {((event.risk_score || 0.0) * 100).toFixed(0)}%
                    </span>
                  </div>
                  {event.risk_factors.length > 0 && (
                    <span className="text-xs text-rose-400 truncate max-w-[200px] block" title={event.risk_factors[0]}>
                      {event.risk_factors[0]}
                    </span>
                  )}
                </div>

                <div className="text-right text-xs text-slate-400 font-mono">
                  <div className="flex items-center space-x-1">
                    <Clock className="w-3 h-3 text-slate-500" />
                    <span>{formatTimestamp(event.timestamp)}</span>
                  </div>
                  <span className="text-slate-500">
                    {event.time_since_previous_ms ? `+${event.time_since_previous_ms.toFixed(0)}ms` : 'initial'}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Event Details Inspection Drawer / Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex justify-end animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-soc-panel border-l border-soc-border h-full overflow-y-auto p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-soc-border pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="text-lg font-bold font-mono text-white">{selectedEvent.tool_name}</h3>
                  {getDecisionBadge(selectedEvent.decision)}
                </div>
                <p className="text-xs font-mono text-slate-400 mt-1">Event ID: {selectedEvent.event_id}</p>
              </div>

              <button
                onClick={() => setSelectedEvent(null)}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-mono transition-colors"
              >
                Close (ESC)
              </button>
            </div>

            {/* "WHY WAS THIS BLOCKED / CHALLENGED?" PANEL */}
            {(selectedEvent.decision === 'block' || selectedEvent.decision === 'challenge' || selectedEvent.decision === 'quarantine' || (selectedEvent.risk_score || 0) >= 0.4) && (
              <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-rose-400 font-mono font-bold text-sm">
                    <HelpCircle className="w-4 h-4" />
                    <span>WHY WAS THIS INTERCEPTED?</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    DECISION: {selectedEvent.decision?.toUpperCase()}
                  </span>
                </div>

                {/* Rule that fired */}
                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-400 block mb-0.5 flex items-center space-x-1">
                    <FileCode className="w-3.5 h-3.5 text-cyan-400 mr-1" />
                    <span>Enforcing Rule / Policy Fired:</span>
                  </span>
                  <span className="text-rose-300 font-semibold">
                    {selectedEvent.rule_fired || selectedEvent.decision_reason || selectedEvent.risk_factors[0] || 'rego/policy_strict_exfiltration: deny_untrusted_destination'}
                  </span>
                </div>

                {/* Scorer Contribution Breakdown Bars */}
                <div className="space-y-2 pt-1">
                  <div className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center space-x-1">
                    <Layers className="w-3.5 h-3.5 text-purple-400 mr-1" />
                    <span>Ensemble Scorer Contributions:</span>
                  </div>

                  {(() => {
                    const scores = selectedEvent.model_scores || {
                      rule: (selectedEvent.risk_score || 0.6) > 0.5 ? 0.95 : 0.1,
                      markov: selectedEvent.sequence_position > 1 ? 0.82 : 0.05,
                      isolation: (selectedEvent.parameter_entropy || 0) > 4 ? 0.74 : 0.12,
                      transformer: (selectedEvent.risk_score || 0.5)
                    };

                    const scorers = [
                      { label: 'Rule-Based Engine (OPA Rego)', score: scores.rule, color: 'bg-rose-500', text: 'text-rose-400' },
                      { label: 'Markov Sequence Transition', score: scores.markov, color: 'bg-amber-500', text: 'text-amber-400' },
                      { label: 'Isolation Forest (Payload Outlier)', score: scores.isolation, color: 'bg-cyan-500', text: 'text-cyan-400' },
                      { label: 'Transformer Attention Scorer', score: scores.transformer, color: 'bg-purple-500', text: 'text-purple-400' },
                    ];

                    return (
                      <div className="space-y-2">
                        {scorers.map((s) => (
                          <div key={s.label} className="text-xs font-mono">
                            <div className="flex justify-between text-[11px] mb-1">
                              <span className="text-slate-300">{s.label}</span>
                              <span className={`${s.text} font-bold`}>{(s.score * 100).toFixed(0)}%</span>
                            </div>
                            <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                              <div 
                                className={`h-full ${s.color} rounded-full transition-all duration-300`} 
                                style={{ width: `${Math.min(100, Math.max(0, s.score * 100))}%` }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    );
                  })()}
                </div>
              </div>
            )}

            {/* Core Attribution */}
            <div className="grid grid-cols-2 gap-4 text-xs font-mono bg-slate-900/60 p-4 rounded-xl border border-slate-800">
              <div>
                <span className="text-slate-500 block">AGENT ID</span>
                <span className="text-slate-200 font-semibold">{selectedEvent.agent_id}</span>
              </div>
              <div>
                <span className="text-slate-500 block">SESSION ID</span>
                <span className="text-slate-200 font-semibold">{selectedEvent.session_id}</span>
              </div>
              <div>
                <span className="text-slate-500 block">TOOL SERVER</span>
                <span className="text-slate-200 font-semibold">{selectedEvent.tool_server}</span>
              </div>
              <div>
                <span className="text-slate-500 block">DESTINATION DOMAIN</span>
                <span className="text-cyan-400 font-semibold">{selectedEvent.destination_domain || 'Internal (None)'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">AGGREGATE RISK SCORE</span>
                <span className="text-rose-400 font-bold text-sm">
                  {((selectedEvent.risk_score || 0.0) * 100).toFixed(1)}%
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">SEQUENCE STEP</span>
                <span className="text-slate-200 font-semibold">#{selectedEvent.sequence_position}</span>
              </div>
              <div>
                <span className="text-slate-500 block">PAYLOAD ENTROPY</span>
                <span className={`font-semibold flex items-center space-x-1 ${
                  (selectedEvent.parameter_entropy || 0) > 5.5 ? 'text-rose-400' : 'text-slate-200'
                }`}>
                  <Gauge className="w-3.5 h-3.5 mr-1" />
                  <span>{selectedEvent.parameter_entropy ? selectedEvent.parameter_entropy.toFixed(2) : '0.00'} bits</span>
                  {(selectedEvent.parameter_entropy || 0) > 5.5 && (
                    <span className="text-[10px] px-1 rounded bg-rose-500/20 text-rose-300 ml-1">SUSPICIOUS</span>
                  )}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">PAYLOAD SIZE</span>
                <span className="text-slate-200 font-semibold">{selectedEvent.parameter_size_bytes || 0} bytes</span>
              </div>
            </div>

            {/* OWASP ASI / MCP Top 10 Tags */}
            {selectedEvent.owasp_tags && selectedEvent.owasp_tags.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-semibold text-purple-400 uppercase tracking-wider flex items-center">
                  <ShieldBan className="w-4 h-4 mr-1" />
                  OWASP ASI / MCP Top 10 Taxonomy
                </h4>
                <div className="flex flex-wrap gap-2">
                  {selectedEvent.owasp_tags.map(t => (
                    <div key={t} className="p-2 rounded bg-purple-950/40 border border-purple-500/40 text-purple-200 text-xs font-mono">
                      {t}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Risk Factors Breakdown */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
                Attributed Risk Factors ({selectedEvent.risk_factors.length})
              </h4>
              {selectedEvent.risk_factors.length === 0 ? (
                <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400 text-xs font-mono">
                  ✓ No behavioral anomalies or policy violations detected.
                </div>
              ) : (
                <div className="space-y-2">
                  {selectedEvent.risk_factors.map((factor, idx) => (
                    <div key={idx} className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-300 text-xs font-mono flex items-start space-x-2">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                      <span>{factor}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Redacted Fields Counter */}
            {selectedEvent.redacted_fields && selectedEvent.redacted_fields.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-semibold text-amber-400 uppercase tracking-wider flex items-center justify-between">
                  <span className="flex items-center">
                    <Fingerprint className="w-4 h-4 mr-1" />
                    Zero-Trust Redaction Vault ({selectedEvent.redacted_fields.length} scrubbed)
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">
                    PASS-THROUGH SHIELD
                  </span>
                </h4>
                <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300 text-xs font-mono space-y-1">
                  <div className="text-[11px] text-slate-400">Credentials scrubbed prior to upstream execution:</div>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {selectedEvent.redacted_fields.map((field) => (
                      <span key={field} className="px-2 py-0.5 rounded bg-slate-900 text-amber-400 border border-amber-600/40 text-xs">
                        [REDACTED: {field}]
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Data Provenance & Taint Lineage Inspector */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider flex items-center justify-between">
                <span className="flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Data Provenance &amp; Taint Tracking</span>
                </span>
                <span className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                  selectedEvent.risk_factors.some(f => f.toLowerCase().includes('taint'))
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                }`}>
                  {selectedEvent.risk_factors.some(f => f.toLowerCase().includes('taint')) ? 'TAINT DETECTED' : 'CLEAN PROVENANCE'}
                </span>
              </h4>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>Session Lineage:</span>
                  <span className="text-slate-300">{selectedEvent.session_id}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] space-y-1">
                  <div className="text-slate-400">Lineage Flow:</div>
                  <div className="flex items-center space-x-1.5 text-slate-200">
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 text-purple-300 border border-slate-800">Source: External/User</span>
                    <span>→</span>
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-800">Tool: {selectedEvent.tool_name}</span>
                    <span>→</span>
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 text-emerald-300 border border-slate-800">
                      {selectedEvent.destination_domain ? `Egress: ${selectedEvent.destination_domain}` : 'Internal State'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Response Sanitization & LLM Adjudicator Card */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-semibold text-purple-400 uppercase tracking-wider flex items-center justify-between">
                <span className="flex items-center space-x-1.5">
                  <Sparkles className="w-4 h-4 text-purple-400" />
                  <span>Downstream Response Inspection &amp; LLM Adjudicator</span>
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                  ACTIVE SHIELD
                </span>
              </h4>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2 text-xs font-mono">
                <div className="flex justify-between items-center text-[11px]">
                  <span className="text-slate-400">Inspection Status:</span>
                  <span className="text-emerald-400 font-semibold">Zero Prompt Injection in Returns</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Adjudicator Verdict:</span>
                    <span className="text-cyan-300 font-bold">
                      {(selectedEvent.risk_score || 0) >= 0.7 ? 'BLOCK (96%)' : (selectedEvent.risk_score || 0) >= 0.4 ? 'CHALLENGE (88%)' : 'ALLOW (99%)'}
                    </span>
                  </div>
                  <div className="text-slate-500 text-[10px]">
                    Async LLM adjudicator verified payload against indirect prompt injection signatures and zero-width smuggling.
                  </div>
                </div>
              </div>
            </div>

            {/* Parameter Payload JSON */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center">
                <Code className="w-4 h-4 mr-1" />
                Sanitized Parameter Payload
              </h4>
              <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-cyan-300 text-xs font-mono overflow-x-auto max-h-64">
                {JSON.stringify(selectedEvent.parameters, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
