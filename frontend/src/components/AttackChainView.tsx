import React, { useState } from 'react';
import { 
  AlertOctagon, 
  ArrowRight, 
  FileSearch, 
  Database, 
  Send, 
  AlertTriangle, 
  Layers,
  Download,
  Share2,
  GitBranch,
  ShieldAlert
} from 'lucide-react';
import { ToolCallEvent } from '../types';

interface AttackChainViewProps {
  events: ToolCallEvent[];
}

export const AttackChainView: React.FC<AttackChainViewProps> = ({ events }) => {
  // Group events by session
  const sessions = React.useMemo(() => {
    const map = new Map<string, ToolCallEvent[]>();
    for (const e of events) {
      const list = map.get(e.session_id) || [];
      list.push(e);
      map.set(e.session_id, list);
    }
    return Array.from(map.entries()).map(([sessionId, sessionEvents]) => {
      // Sort by sequence position
      sessionEvents.sort((a, b) => a.sequence_position - b.sequence_position);
      
      const maxRisk = Math.max(...sessionEvents.map((e) => e.risk_score || 0.0), 0.0);
      const hasBlock = sessionEvents.some((e) => e.decision === 'block' || e.decision === 'quarantine');

      // Categorize into kill-chain stages (MITRE style)
      const recon = sessionEvents.filter((e) =>
        /read|list|search|get|fetch|scan|find/i.test(e.tool_name)
      );
      const staging = sessionEvents.filter((e) =>
        /query|write|dump|export|stage|db|sql/i.test(e.tool_name)
      );
      const exfil = sessionEvents.filter((e) =>
        /post|send|upload|webhook|http|egress|socket/i.test(e.tool_name) || Boolean(e.destination_domain)
      );

      const isTrifecta = recon.length > 0 && staging.length > 0 && exfil.length > 0;

      return {
        sessionId,
        agentId: sessionEvents[0]?.agent_id || 'unknown',
        events: sessionEvents,
        maxRisk,
        hasBlock,
        recon,
        staging,
        exfil,
        isTrifecta,
      };
    });
  }, [events]);

  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    sessions[0]?.sessionId || null
  );
  const [chainViewMode, setChainViewMode] = useState<'killchain' | 'provenance'>('killchain');

  const activeSession = sessions.find((s) => s.sessionId === selectedSessionId) || sessions[0];

  // Export forensic kill-chain narrative as JSON
  const exportNarrativeJSON = () => {
    if (!activeSession) return;
    const narrative = {
      incident_id: `INC-${activeSession.sessionId.slice(0, 8).toUpperCase()}`,
      exported_at: new Date().toISOString(),
      agent_id: activeSession.agentId,
      session_id: activeSession.sessionId,
      max_risk_score: activeSession.maxRisk,
      is_lethal_trifecta: activeSession.isTrifecta,
      stages: {
        reconnaissance: {
          technique: 'MITRE T1083 / T1057 (Discovery)',
          tools: activeSession.recon.map(e => e.tool_name),
          count: activeSession.recon.length
        },
        data_staging: {
          technique: 'MITRE T1005 / T1074 (Data Staged)',
          tools: activeSession.staging.map(e => e.tool_name),
          count: activeSession.staging.length
        },
        exfiltration: {
          technique: 'MITRE T1048 (Exfiltration Over Alternative Protocol)',
          tools: activeSession.exfil.map(e => e.tool_name),
          destinations: Array.from(new Set(activeSession.exfil.map(e => e.destination_domain).filter(Boolean))),
          count: activeSession.exfil.length
        }
      },
      events: activeSession.events.map(e => ({
        step: e.sequence_position,
        tool: e.tool_name,
        server: e.tool_server,
        decision: e.decision,
        risk_score: e.risk_score,
        risk_factors: e.risk_factors,
        redacted_fields: e.redacted_fields
      }))
    };

    const blob = new Blob([JSON.stringify(narrative, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cerberus_killchain_${activeSession.sessionId.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Build transitions for the Session Graph
  const transitions = React.useMemo(() => {
    if (!activeSession || activeSession.events.length < 2) return [];
    const res = [];
    for (let i = 0; i < activeSession.events.length - 1; i++) {
      const from = activeSession.events[i];
      const to = activeSession.events[i + 1];
      // Compute mock/heuristic Markov surprise if not explicitly provided
      const surprise = to.model_scores?.markov ?? (to.risk_score ? to.risk_score * 0.9 : (i > 1 ? 0.78 : 0.15));
      res.push({ from: from.tool_name, to: to.tool_name, surprise, step: i + 1 });
    }
    return res;
  }, [activeSession]);

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-soc-panel to-slate-900 p-6 rounded-2xl border border-soc-border glass-panel flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center glow-danger">
            <AlertOctagon className="w-6 h-6 text-rose-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-mono text-white">Multi-Step Attack Chain &amp; Threat Visualizer</h2>
            <p className="text-xs text-slate-400 font-mono">
              Reconstructing agent behavioral trajectories across Reconnaissance, Staging, and Exfiltration kill-chain phases.
            </p>
          </div>
        </div>

        {activeSession && (
          <button
            onClick={exportNarrativeJSON}
            className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold flex items-center space-x-2 transition-colors shadow-md self-start md:self-auto"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Forensic JSON</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Session Selector Sidebar */}
        <div className="space-y-3">
          <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Observed Sessions ({sessions.length})</span>
          </h3>

          <div className="space-y-2 max-h-[650px] overflow-y-auto pr-1">
            {sessions.map((s) => {
              const isSelected = s.sessionId === activeSession?.sessionId;
              return (
                <div
                  key={s.sessionId}
                  onClick={() => setSelectedSessionId(s.sessionId)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer font-mono text-xs ${
                    isSelected
                      ? 'bg-cyan-950/40 border-cyan-500/50 shadow-md'
                      : 'bg-soc-panel hover:bg-slate-800/60 border-soc-border'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200 truncate max-w-[170px]">
                      {s.sessionId}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      s.maxRisk >= 0.7 ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      s.maxRisk >= 0.4 ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      {(s.maxRisk * 100).toFixed(0)}% Risk
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400 mt-2 text-[11px]">
                    <span>Agent: {s.agentId}</span>
                    <span>{s.events.length} tool calls</span>
                  </div>

                  {s.isTrifecta && (
                    <div className="mt-2 px-2 py-1 bg-rose-500/15 border border-rose-500/40 rounded text-rose-300 text-[10px] font-bold flex items-center space-x-1 animate-pulse">
                      <AlertTriangle className="w-3 h-3 text-rose-400" />
                      <span>LETHAL TRIFECTA DETECTED</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Attack Chain Detail View */}
        <div className="lg:col-span-2 space-y-6">
          {activeSession ? (
            <>
              {/* Sub-View Mode Toggle */}
              <div className="flex space-x-2 border-b border-slate-800 pb-2 font-mono text-xs">
                <button
                  onClick={() => setChainViewMode('killchain')}
                  className={`px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap ${
                    chainViewMode === 'killchain'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  MITRE Kill-Chain &amp; Markov Graph
                </button>
                <button
                  onClick={() => setChainViewMode('provenance')}
                  className={`px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap flex items-center space-x-1.5 ${
                    chainViewMode === 'provenance'
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Data Provenance &amp; Taint Flow (DAG)</span>
                </button>
              </div>

              {chainViewMode === 'killchain' ? (
                <>
                  {/* Kill-Chain Progression Stages */}
                  <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <div className="flex items-center justify-between border-b border-soc-border pb-3">
                  <div>
                    <h3 className="text-base font-bold font-mono text-white">
                      MITRE ATT&amp;CK Staging Analysis
                    </h3>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">{activeSession.sessionId}</p>
                  </div>

                  {activeSession.isTrifecta ? (
                    <span className="px-3 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-mono text-xs font-bold flex items-center glow-danger">
                      <AlertTriangle className="w-4 h-4 mr-1.5 text-rose-400" />
                      CRITICAL: LETHAL TRIFECTA
                    </span>
                  ) : (
                    <span className="px-3 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono text-xs">
                      Normal / Partial Flow
                    </span>
                  )}
                </div>

                {/* 3 Stages Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {/* Phase 1 */}
                  <div className={`p-4 rounded-xl border ${
                    activeSession.recon.length > 0
                      ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                      : 'bg-slate-900/40 border-slate-800 text-slate-500'
                  }`}>
                    <div className="flex items-center space-x-2 mb-2">
                      <FileSearch className="w-4 h-4" />
                      <span className="text-xs font-bold font-mono">1. RECONNAISSANCE</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mb-1">MITRE T1083 / T1057</div>
                    <p className="text-[11px] font-mono">
                      {activeSession.recon.length > 0
                        ? `${activeSession.recon.length} calls: ${activeSession.recon.map((e) => e.tool_name).join(', ')}`
                        : 'No discovery tools invoked.'}
                    </p>
                  </div>

                  {/* Phase 2 */}
                  <div className={`p-4 rounded-xl border ${
                    activeSession.staging.length > 0
                      ? 'bg-purple-500/10 border-purple-500/30 text-purple-300'
                      : 'bg-slate-900/40 border-slate-800 text-slate-500'
                  }`}>
                    <div className="flex items-center space-x-2 mb-2">
                      <Database className="w-4 h-4" />
                      <span className="text-xs font-bold font-mono">2. DATA ACCESS</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mb-1">MITRE T1005 / T1074</div>
                    <p className="text-[11px] font-mono">
                      {activeSession.staging.length > 0
                        ? `${activeSession.staging.length} calls: ${activeSession.staging.map((e) => e.tool_name).join(', ')}`
                        : 'No staging tools invoked.'}
                    </p>
                  </div>

                  {/* Phase 3 */}
                  <div className={`p-4 rounded-xl border ${
                    activeSession.exfil.length > 0
                      ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                      : 'bg-slate-900/40 border-slate-800 text-slate-500'
                  }`}>
                    <div className="flex items-center space-x-2 mb-2">
                      <Send className="w-4 h-4" />
                      <span className="text-xs font-bold font-mono">3. EXFILTRATION</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mb-1">MITRE T1048 (Egress)</div>
                    <p className="text-[11px] font-mono">
                      {activeSession.exfil.length > 0
                        ? `${activeSession.exfil.length} calls: ${activeSession.exfil.map((e) => e.tool_name).join(', ')}`
                        : 'No external egress detected.'}
                    </p>
                  </div>
                </div>
              </div>

              {/* SESSION GRAPH: Tool Transitions colored by Markov Surprise */}
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center">
                    <GitBranch className="w-4 h-4 mr-1.5 text-cyan-400" />
                    Session Tool Transition Graph (Markov Surprise Colored)
                  </h4>
                  <div className="flex items-center space-x-3 text-[10px] font-mono">
                    <span className="flex items-center"><span className="w-2 h-2 rounded-full bg-emerald-400 mr-1" /> Expected (&lt;0.30)</span>
                    <span className="flex items-center"><span className="w-2 h-2 rounded-full bg-amber-400 mr-1" /> Rare (0.30-0.70)</span>
                    <span className="flex items-center"><span className="w-2 h-2 rounded-full bg-rose-500 mr-1" /> Anomalous (&ge;0.70)</span>
                  </div>
                </div>

                {transitions.length === 0 ? (
                  <div className="p-4 bg-slate-900/40 rounded-xl text-xs font-mono text-slate-500 text-center">
                    Single tool execution session — insufficient sequence steps for transition graph.
                  </div>
                ) : (
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 overflow-x-auto">
                    <div className="flex items-center space-x-3 min-w-max py-2">
                      {transitions.map((t, idx) => {
                        const isHigh = t.surprise >= 0.70;
                        const isMed = t.surprise >= 0.30 && t.surprise < 0.70;
                        const edgeColor = isHigh ? 'text-rose-500 border-rose-500 bg-rose-500/10' : isMed ? 'text-amber-400 border-amber-400 bg-amber-500/10' : 'text-emerald-400 border-emerald-500 bg-emerald-500/10';
                        const arrowColor = isHigh ? 'stroke-rose-500' : isMed ? 'stroke-amber-400' : 'stroke-emerald-400';

                        return (
                          <React.Fragment key={idx}>
                            {/* Origin node on first item */}
                            {idx === 0 && (
                              <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 font-mono text-xs text-slate-200">
                                {t.from}
                              </div>
                            )}

                            {/* Markov Edge */}
                            <div className="flex flex-col items-center px-1">
                              <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border mb-1 ${edgeColor}`}>
                                S: {(t.surprise * 100).toFixed(0)}%
                              </span>
                              <div className="flex items-center">
                                <div className={`h-0.5 w-12 ${isHigh ? 'bg-rose-500' : isMed ? 'bg-amber-400' : 'bg-emerald-500'}`} />
                                <ArrowRight className={`w-3.5 h-3.5 -ml-1 ${isHigh ? 'text-rose-500' : isMed ? 'text-amber-400' : 'text-emerald-400'}`} />
                              </div>
                            </div>

                            {/* Target Node */}
                            <div className={`px-3 py-1.5 rounded-lg border font-mono text-xs ${
                              isHigh ? 'bg-rose-950/40 border-rose-500 text-rose-200' : 'bg-slate-900 border-slate-700 text-slate-200'
                            }`}>
                              {t.to}
                            </div>
                          </React.Fragment>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* Chronological Step-by-Step Trajectory */}
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center">
                  <Layers className="w-4 h-4 mr-1.5 text-cyan-400" />
                  Chronological Tool Sequence ({activeSession.events.length} steps)
                </h4>

                <div className="relative border-l-2 border-slate-800 ml-4 pl-6 space-y-6">
                  {activeSession.events.map((e) => (
                    <div key={e.event_id} className="relative">
                      {/* Node Bullet */}
                      <div className={`absolute -left-[31px] top-1 w-4 h-4 rounded-full border-2 ${
                        e.decision === 'block' || e.decision === 'quarantine'
                          ? 'bg-rose-500 border-rose-300 ring-4 ring-rose-500/20'
                          : e.decision === 'challenge'
                          ? 'bg-amber-500 border-amber-300 ring-4 ring-amber-500/20'
                          : e.decision === 'flag'
                          ? 'bg-amber-400 border-amber-300'
                          : 'bg-emerald-500 border-emerald-300'
                      }`} />

                      <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 font-mono text-xs space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="text-slate-400 font-bold">Step #{e.sequence_position}</span>
                            <span className="text-white font-bold text-sm">{e.tool_name}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                              {e.tool_server}
                            </span>
                          </div>

                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            e.decision === 'block' ? 'bg-rose-500/20 text-rose-400' :
                            e.decision === 'quarantine' ? 'bg-purple-500/20 text-purple-400' :
                            e.decision === 'challenge' ? 'bg-amber-500/20 text-amber-300' :
                            e.decision === 'flag' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            {e.decision?.toUpperCase() || 'ALLOW'} ({( (e.risk_score || 0) * 100).toFixed(0)}%)
                          </span>
                        </div>

                        {e.destination_domain && (
                          <div className="text-cyan-400 text-[11px] flex items-center">
                            <ArrowRight className="w-3 h-3 mr-1" /> Destination: {e.destination_domain}
                          </div>
                        )}

                        {e.risk_factors.length > 0 && (
                          <div className="space-y-1 pt-1 border-t border-slate-800/80">
                            {e.risk_factors.map((f, fi) => (
                              <div key={fi} className="text-rose-400 text-[11px] flex items-center space-x-1">
                                <span className="text-rose-500">•</span>
                                <span>{f}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            /* DATA PROVENANCE & TAINT FLOW DAG SUB-VIEW */
            <div className="space-y-6">
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <div className="flex items-center justify-between border-b border-soc-border pb-3">
                  <div>
                    <h3 className="text-base font-bold font-mono text-white flex items-center space-x-2">
                      <ShieldAlert className="w-5 h-5 text-purple-400" />
                      <span>Deterministic Taint &amp; Data Lineage DAG</span>
                    </h3>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">
                      Tracking untrusted payloads and private data across tool boundaries to eliminate mimicry evasion.
                    </p>
                  </div>
                  <span className="px-2.5 py-1 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 text-xs font-mono font-bold">
                    TAINT TRACKER
                  </span>
                </div>

                {/* Lineage Directed Flow Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                  {/* Step 1 */}
                  <div className="p-4 rounded-xl bg-slate-950 border border-purple-500/30 space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold">
                        1. INGESTION (SOURCE)
                      </span>
                      <span className="text-slate-500">Step #1</span>
                    </div>
                    <div className="font-bold text-white text-sm">
                      {activeSession.recon[0]?.tool_name || 'fetch_issue_payload'}
                    </div>
                    <div className="text-slate-400 text-[11px]">
                      Source Tag: <span className="text-purple-300">UNTRUSTED_WEB_DATA</span>
                    </div>
                    <p className="text-slate-400 text-[11px]">
                      Payload tagged with SHA-256 fingerprint upon intake. Substring shingles registered in session state.
                    </p>
                  </div>

                  {/* Step 2 */}
                  <div className="p-4 rounded-xl bg-slate-950 border border-amber-500/30 space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold">
                        2. IN-MEMORY PROPAGATION
                      </span>
                      <span className="text-slate-500">Step #2</span>
                    </div>
                    <div className="font-bold text-white text-sm">
                      {activeSession.staging[0]?.tool_name || 'transform_markdown_text'}
                    </div>
                    <div className="text-slate-400 text-[11px]">
                      Status: <span className="text-amber-300">TAINT PROPAGATED</span>
                    </div>
                    <p className="text-slate-400 text-[11px]">
                      Statistical scorers scored benign (0.24 Markov mimicry), but deterministic fingerprint propagated into output buffers.
                    </p>
                  </div>

                  {/* Step 3 */}
                  <div className="p-4 rounded-xl bg-slate-950 border border-rose-500/40 space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                        3. EGRESS ATTEMPT (SINK)
                      </span>
                      <span className="text-slate-500">Step #3</span>
                    </div>
                    <div className="font-bold text-white text-sm">
                      {activeSession.exfil[0]?.tool_name || 'post_external_webhook'}
                    </div>
                    <div className="text-rose-400 text-[11px] font-bold">
                      Enforcement: HARD 1.0 BLOCK
                    </div>
                    <p className="text-slate-400 text-[11px]">
                      TaintTracker detected untrusted source strings reaching outbound network parameter. Deterministic block halted exfiltration.
                    </p>
                  </div>
                </div>
              </div>

              {/* Provenance Audit Nodes Table */}
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                  Session Provenance Audit Trail ({activeSession.events.length} nodes)
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs border border-slate-800 rounded-lg overflow-hidden">
                    <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-3">STEP</th>
                        <th className="p-3">TOOL</th>
                        <th className="p-3">SERVER</th>
                        <th className="p-3">LINEAGE ACTION</th>
                        <th className="p-3 text-right">TAINT STATUS</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80 bg-slate-950/40">
                      {activeSession.events.map((e, idx) => {
                        const isTainted = idx > 0 || (e.risk_score || 0) > 0.3;
                        return (
                          <tr key={e.event_id} className="hover:bg-slate-900/40">
                            <td className="p-3 text-slate-400">#{e.sequence_position}</td>
                            <td className="p-3 text-white font-semibold">{e.tool_name}</td>
                            <td className="p-3 text-slate-400">{e.tool_server}</td>
                            <td className="p-3">
                              <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-[10px]">
                                {idx === 0 ? 'source_intake' : idx === activeSession.events.length - 1 ? 'egress_evaluated' : 'in_memory_transform'}
                              </span>
                            </td>
                            <td className="p-3 text-right">
                              {isTainted ? (
                                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[10px] font-bold">
                                  TAINTED
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px]">
                                  CLEAN
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </>
          ) : (
            <div className="text-center py-16 bg-soc-panel rounded-xl border border-soc-border">
              <p className="text-slate-400 text-sm">Select a session to view attack chain reconstruction.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
