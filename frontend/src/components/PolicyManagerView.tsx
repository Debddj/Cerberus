import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  CheckCircle, 
  XCircle, 
  Play, 
  Code, 
  Layers, 
  FileText, 
  Sparkles,
  RefreshCw,
  AlertCircle
} from 'lucide-react';
import { Policy } from '../types';
import { fetchPolicies, approvePolicy, rejectPolicy, simulatePolicy } from '../api';

export const PolicyManagerView: React.FC = () => {
  const [policies, setPolicies] = useState<{ active: Policy[]; pending: Policy[] }>({
    active: [],
    pending: [],
  });
  const [loading, setLoading] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null);
  const [actionStatus, setActionStatus] = useState<string | null>(null);

  // Simulation Sandbox State
  const [simToolName, setSimToolName] = useState('http_post');
  const [simAgentId, setSimAgentId] = useState('agent-alpha');
  const [simDestDomain, setSimDestDomain] = useState('evil-exfil.com');
  const [simRiskScore, setSimRiskScore] = useState(0.85);
  const [simSchemaDrift, setSimSchemaDrift] = useState(false);
  const [simTrifecta, setSimTrifecta] = useState(true);
  const [simResult, setSimResult] = useState<any>(null);
  const [simulating, setSimulating] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await fetchPolicies();
      setPolicies(data);
      if (data.pending.length > 0 && !selectedPolicy) {
        setSelectedPolicy(data.pending[0]);
      } else if (data.active.length > 0 && !selectedPolicy) {
        setSelectedPolicy(data.active[0]);
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

  const handleApprove = async (policyId: string) => {
    try {
      setActionStatus('Approving & pushing to OPA...');
      await approvePolicy(policyId);
      setActionStatus(`Policy ${policyId} approved & activated in OPA!`);
      await loadData();
    } catch (err: any) {
      setActionStatus(`Approval failed: ${err.message}`);
    }
  };

  const handleReject = async (policyId: string) => {
    try {
      setActionStatus('Rejecting policy...');
      await rejectPolicy(policyId);
      setActionStatus(`Policy ${policyId} rejected.`);
      await loadData();
    } catch (err: any) {
      setActionStatus(`Rejection failed: ${err.message}`);
    }
  };

  const handleRunSimulation = async () => {
    setSimulating(true);
    try {
      const payload = {
        event: {
          event_id: `sim-${Date.now()}`,
          session_id: 'session-sim',
          agent_id: simAgentId,
          tool_name: simToolName,
          tool_server: 'upstream-sim',
          parameters: { target: simDestDomain, data: 'exfil_payload' },
          destination_domain: simDestDomain,
          risk_score: simRiskScore,
          timestamp: Date.now() / 1000,
          sequence_position: 1,
          risk_factors: ['Simulated Sandbox Event'],
          redacted_fields: [],
        },
        static_scan: {
          schema_drift: simSchemaDrift,
          lethal_trifecta: simTrifecta,
          out_of_scope: false,
        },
      };
      const res = await simulatePolicy(payload);
      setSimResult(res);
    } catch (err: any) {
      setSimResult({ error: err.message });
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-soc-panel to-slate-900 p-6 rounded-2xl border border-soc-border glass-panel flex justify-between items-center">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center glow-cyan">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-mono text-white">Closed-Loop Policy Engine & Rego Sandbox</h2>
            <p className="text-xs text-slate-400 font-mono">
              Inspect active OPA packages, review auto-synthesized defensive rules, and dry-run policy simulations.
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

      {actionStatus && (
        <div className="p-3 bg-cyan-950/40 border border-cyan-500/40 rounded-xl text-cyan-300 text-xs font-mono flex items-center justify-between">
          <span>{actionStatus}</span>
          <button onClick={() => setActionStatus(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policy List Sidebar */}
        <div className="space-y-4">
          {/* Pending Auto-Synthesized Section */}
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-semibold text-amber-400 uppercase tracking-wider flex items-center justify-between">
              <span className="flex items-center">
                <Sparkles className="w-3.5 h-3.5 mr-1" />
                Pending Auto-Synthesized ({policies.pending.length})
              </span>
            </h3>

            {policies.pending.length === 0 ? (
              <div className="p-4 bg-soc-panel rounded-xl border border-soc-border text-center text-xs font-mono text-slate-500">
                No policies pending human review.
              </div>
            ) : (
              policies.pending.map((p) => {
                const isSelected = selectedPolicy?.policy_id === p.policy_id;
                return (
                  <div
                    key={p.policy_id}
                    onClick={() => setSelectedPolicy(p)}
                    className={`p-3 rounded-xl border cursor-pointer font-mono text-xs transition-all ${
                      isSelected
                        ? 'bg-amber-950/30 border-amber-500/50 shadow-md'
                        : 'bg-soc-panel hover:bg-slate-800/60 border-soc-border'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-amber-300">{p.policy_id}</span>
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 text-[10px] border border-amber-500/30">
                        PENDING
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300 mt-1">Tool: <strong>{p.tool_name}</strong> (Agent: {p.agent_id})</p>
                    <p className="text-[10px] text-slate-500 mt-1">Risk at trigger: {((p.risk_score || 0) * 100).toFixed(0)}%</p>
                  </div>
                );
              })
            )}
          </div>

          {/* Active Policies Section */}
          <div className="space-y-2 pt-4 border-t border-soc-border">
            <h3 className="text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider flex items-center">
              <Layers className="w-3.5 h-3.5 mr-1" />
              Active Rego Bundles ({policies.active.length})
            </h3>

            {policies.active.map((p) => {
              const isSelected = selectedPolicy?.name === p.name;
              return (
                <div
                  key={p.path || p.name}
                  onClick={() => setSelectedPolicy(p)}
                  className={`p-3 rounded-xl border cursor-pointer font-mono text-xs transition-all ${
                    isSelected
                      ? 'bg-cyan-950/30 border-cyan-500/50 shadow-md'
                      : 'bg-soc-panel hover:bg-slate-800/60 border-soc-border'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{p.name}</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] border border-emerald-500/30">
                      ACTIVE
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 mt-1 font-mono truncate">{p.path}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Policy Code Inspector & Actions */}
        <div className="lg:col-span-2 space-y-6">
          {selectedPolicy ? (
            <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border pb-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-base font-bold font-mono text-white">
                      {selectedPolicy.policy_id || selectedPolicy.name}
                    </h3>
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                      selectedPolicy.type === 'pending'
                        ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                        : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      {selectedPolicy.type.toUpperCase()}
                    </span>
                  </div>
                  {selectedPolicy.agent_id && (
                    <p className="text-xs font-mono text-slate-400 mt-1">
                      Auto-generated against agent <strong className="text-slate-200">{selectedPolicy.agent_id}</strong>
                    </p>
                  )}
                </div>

                {/* Approve / Reject Buttons for Pending Policies */}
                {selectedPolicy.type === 'pending' && selectedPolicy.policy_id && (
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => handleApprove(selectedPolicy.policy_id!)}
                      className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold transition-all shadow-md glow-cyan"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      <span>Approve & Push to OPA</span>
                    </button>
                    <button
                      onClick={() => handleReject(selectedPolicy.policy_id!)}
                      className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-rose-600/80 hover:bg-rose-500 text-white text-xs font-mono font-bold transition-all"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>
                  </div>
                )}
              </div>

              {/* Rego Code View */}
              <div className="space-y-2">
                <span className="text-xs font-mono text-slate-400">Rego Policy Specification:</span>
                <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-emerald-300 text-xs font-mono overflow-x-auto max-h-[350px]">
                  {selectedPolicy.code || '# Rego policy content loaded from storage'}
                </pre>
              </div>
            </div>
          ) : (
            <div className="p-8 bg-soc-panel rounded-xl border border-soc-border text-center text-slate-400 font-mono text-sm">
              Select a policy to view Rego specification and actions.
            </div>
          )}

          {/* Interactive Policy Simulation Playground */}
          <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
            <div className="flex items-center space-x-2 border-b border-soc-border pb-3">
              <Play className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold font-mono text-white">Policy Dry-Run Simulator</h3>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Target Tool</label>
                <input
                  type="text"
                  value={simToolName}
                  onChange={(e) => setSimToolName(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Agent ID</label>
                <input
                  type="text"
                  value={simAgentId}
                  onChange={(e) => setSimAgentId(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Destination Domain</label>
                <input
                  type="text"
                  value={simDestDomain}
                  onChange={(e) => setSimDestDomain(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Simulated Risk: {(simRiskScore * 100).toFixed(0)}%</label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={simRiskScore}
                  onChange={(e) => setSimRiskScore(parseFloat(e.target.value))}
                  className="w-full"
                />
              </div>

              <div className="flex items-center space-x-2 pt-4">
                <input
                  type="checkbox"
                  id="chkTrifecta"
                  checked={simTrifecta}
                  onChange={(e) => setSimTrifecta(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                />
                <label htmlFor="chkTrifecta" className="text-slate-300">Lethal Trifecta Scan</label>
              </div>

              <div className="flex items-center space-x-2 pt-4">
                <input
                  type="checkbox"
                  id="chkSchema"
                  checked={simSchemaDrift}
                  onChange={(e) => setSimSchemaDrift(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                />
                <label htmlFor="chkSchema" className="text-slate-300">Schema Drift Flag</label>
              </div>
            </div>

            <button
              onClick={handleRunSimulation}
              disabled={simulating}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition-all glow-cyan"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{simulating ? 'Evaluating Against OPA...' : 'Run Simulation'}</span>
            </button>

            {/* Simulation Result */}
            {simResult && (
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono space-y-2">
                <span className="text-slate-400 block">Simulation Verdict:</span>
                <pre className="text-cyan-300 overflow-x-auto max-h-48">
                  {JSON.stringify(simResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
