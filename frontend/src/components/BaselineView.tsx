import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  RefreshCw, 
  Layers, 
  ShieldCheck, 
  GitCommit, 
  Clock, 
  Zap,
  Flame
} from 'lucide-react';
import { BaselineAgent } from '../types';
import { fetchBaselines, promoteBaseline } from '../api';

export const BaselineView: React.FC = () => {
  const [baselines, setBaselines] = useState<BaselineAgent[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<BaselineAgent | null>(null);
  const [promoteStatus, setPromoteStatus] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await fetchBaselines();
      setBaselines(data);
      if (data.length > 0 && !selectedAgent) {
        setSelectedAgent(data[0]);
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handlePromote = async (agentId: string) => {
    try {
      setPromoteStatus(`Triggering online refit for ${agentId}...`);
      const res = await promoteBaseline(agentId);
      setPromoteStatus(`Successfully promoted ${agentId} to snapshot ${res.active_snapshot_id}!`);
      await loadData();
    } catch (err: any) {
      setPromoteStatus(`Promotion failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-soc-panel to-slate-900 p-6 rounded-2xl border border-soc-border glass-panel flex justify-between items-center">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center glow-purple">
            <Activity className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-mono text-white">Online Behavioral Baselines & Drift Monitor</h2>
            <p className="text-xs text-slate-400 font-mono">
              Ensemble adaptation with per-agent Isolation Forest, Markov transition matrices, and Boiling-Frog TVD stability gating.
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {promoteStatus && (
        <div className="p-3 bg-purple-950/40 border border-purple-500/40 rounded-xl text-purple-300 text-xs font-mono flex items-center justify-between">
          <span>{promoteStatus}</span>
          <button onClick={() => setPromoteStatus(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agent Baselines List */}
        <div className="space-y-3">
          <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
            Agent Baselines ({baselines.length})
          </h3>

          {baselines.length === 0 ? (
            <div className="p-6 bg-soc-panel rounded-xl border border-soc-border text-center text-xs font-mono text-slate-500">
              No baselines created yet. Call tools to build baseline models.
            </div>
          ) : (
            baselines.map((b) => {
              const isSelected = selectedAgent?.agent_id === b.agent_id;
              return (
                <div
                  key={b.agent_id}
                  onClick={() => setSelectedAgent(b)}
                  className={`p-4 rounded-xl border cursor-pointer font-mono text-xs transition-all ${
                    isSelected
                      ? 'bg-purple-950/30 border-purple-500/50 shadow-md'
                      : 'bg-soc-panel hover:bg-slate-800/60 border-soc-border'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm">{b.agent_id}</span>
                    <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30 text-[10px]">
                      {b.active_snapshot_id || 'initial'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400 mt-2 text-[11px]">
                    <span>{b.snapshots_count} versioned snapshots</span>
                    <span>{b.known_tools.length} known tools</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Baseline Inspector */}
        <div className="lg:col-span-2 space-y-6">
          {selectedAgent ? (
            <>
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border pb-4">
                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="text-base font-bold font-mono text-white">{selectedAgent.agent_id}</h3>
                      <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30 font-mono text-xs">
                        Active: {selectedAgent.active_snapshot_id}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">
                      Per-Agent Behavioral Anomaly Profile
                    </p>
                  </div>

                  {/* Manual Refit Promotion Button */}
                  <button
                    onClick={() => handlePromote(selectedAgent.agent_id)}
                    className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-mono font-bold transition-all shadow-md glow-purple"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Trigger Refit & Promote</span>
                  </button>
                </div>

                {/* Vocabulary Badges */}
                <div className="space-y-3">
                  <div>
                    <span className="text-xs font-mono text-slate-400 block mb-1">
                      Learned Normal Tools ({selectedAgent.known_tools.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedAgent.known_tools.map((t) => (
                        <span key={t} className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-mono text-xs">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  {selectedAgent.known_destinations.length > 0 && (
                    <div>
                      <span className="text-xs font-mono text-slate-400 block mb-1">
                        Learned Normal Destinations ({selectedAgent.known_destinations.length})
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAgent.known_destinations.map((d) => (
                          <span key={d} className="px-2 py-0.5 rounded bg-slate-800 text-emerald-300 border border-slate-700 font-mono text-xs">
                            {d}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Boiling-Frog Guard Box */}
                <div className="p-4 bg-slate-900/80 rounded-xl border border-purple-500/20 text-xs font-mono space-y-2">
                  <div className="flex items-center space-x-2 text-purple-300 font-bold">
                    <Flame className="w-4 h-4 text-purple-400" />
                    <span>Boiling-Frog Stability Gate Active</span>
                  </div>
                  <p className="text-slate-400 leading-relaxed text-[11px]">
                    Cerberus rejects baseline shifts exceeding a <strong>Total Variation Distance (TVD) of 0.40</strong> between snapshots. Any session containing flagged or quarantined calls is permanently excluded from model retraining.
                  </p>
                </div>
              </div>

              {/* Snapshot Timeline */}
              <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-3">
                <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center">
                  <GitCommit className="w-4 h-4 mr-1.5 text-purple-400" />
                  Snapshot Version History ({selectedAgent.snapshots.length})
                </h4>

                <div className="space-y-2">
                  {selectedAgent.snapshots.map((s) => (
                    <div
                      key={s.snapshot_id}
                      className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 font-mono text-xs flex items-center justify-between"
                    >
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-200">{s.snapshot_id}</span>
                        {s.is_active && (
                          <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">
                            CURRENT ACTIVE
                          </span>
                        )}
                      </div>

                      <div className="flex items-center space-x-4 text-slate-400 text-[11px]">
                        <span>{s.calls_in_snapshot} training observations</span>
                        <span>{new Date(s.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="p-8 bg-soc-panel rounded-xl border border-soc-border text-center text-slate-400 font-mono text-sm">
              Select an agent to inspect behavioral baselines.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
