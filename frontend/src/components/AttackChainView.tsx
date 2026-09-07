import React, { useState } from 'react';
import { 
  AlertOctagon, 
  ShieldAlert, 
  ArrowRight, 
  FileSearch, 
  Database, 
  Send, 
  Terminal,
  AlertTriangle,
  Clock,
  Layers
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

      // Categorize into kill-chain stages
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

  const activeSession = sessions.find((s) => s.sessionId === selectedSessionId) || sessions[0];

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-soc-panel to-slate-900 p-6 rounded-2xl border border-soc-border glass-panel">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center glow-danger">
            <AlertOctagon className="w-6 h-6 text-rose-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-mono text-white">Multi-Step Attack Chain & Threat Visualizer</h2>
            <p className="text-xs text-slate-400 font-mono">
              Reconstructing agent behavioral trajectories across Reconnaissance, Staging, and Exfiltration kill-chain phases.
            </p>
          </div>
        </div>
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
                    <div className="mt-2 px-2 py-1 bg-rose-500/15 border border-rose-500/40 rounded text-rose-300 text-[10px] font-bold flex items-center space-x-1">
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
              {/* Kill-Chain Progression Stages */}
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <div className="flex items-center justify-between border-b border-soc-border pb-3">
                  <div>
                    <h3 className="text-base font-bold font-mono text-white">
                      Session Kill-Chain Analysis
                    </h3>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">{activeSession.sessionId}</p>
                  </div>

                  {activeSession.isTrifecta ? (
                    <span className="px-3 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-mono text-xs font-bold flex items-center glow-danger">
                      <AlertTriangle className="w-4 h-4 mr-1.5 text-rose-400" />
                      CRITICAL: TRIFECTA PATTERN
                    </span>
                  ) : (
                    <span className="px-3 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono text-xs">
                      Partial Chain
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
                    <p className="text-[11px] font-mono">
                      {activeSession.exfil.length > 0
                        ? `${activeSession.exfil.length} calls: ${activeSession.exfil.map((e) => e.tool_name).join(', ')}`
                        : 'No external egress detected.'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Chronological Step-by-Step Trajectory */}
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center">
                  <Layers className="w-4 h-4 mr-1.5 text-cyan-400" />
                  Chronological Tool Sequence ({activeSession.events.length} steps)
                </h4>

                <div className="relative border-l-2 border-slate-800 ml-4 pl-6 space-y-6">
                  {activeSession.events.map((e, index) => (
                    <div key={e.event_id} className="relative">
                      {/* Node Bullet */}
                      <div className={`absolute -left-[31px] top-1 w-4 h-4 rounded-full border-2 ${
                        e.decision === 'block' || e.decision === 'quarantine'
                          ? 'bg-rose-500 border-rose-300 ring-4 ring-rose-500/20'
                          : e.decision === 'flag'
                          ? 'bg-amber-500 border-amber-300 ring-4 ring-amber-500/20'
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
            <div className="text-center py-16 bg-soc-panel rounded-xl border border-soc-border">
              <p className="text-slate-400 text-sm">Select a session to view attack chain reconstruction.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
