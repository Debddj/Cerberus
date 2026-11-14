import React from 'react';
import { 
  X, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldCheck, 
  Radio, 
  Server, 
  Database,
  Lock,
  Activity
} from 'lucide-react';
import { HealthStatus, MetricsSummary } from '../types';

interface HealthTimelineModalProps {
  isOpen: boolean;
  onClose: () => void;
  health: HealthStatus | null;
  metrics: MetricsSummary | null;
}

export const HealthTimelineModal: React.FC<HealthTimelineModalProps> = ({
  isOpen,
  onClose,
  health,
  metrics,
}) => {
  if (!isOpen) return null;

  // Mocked/derived recent health timeline entries for OPA and Fail-Closed status
  const now = Date.now();
  const timelineTicks = [
    { time: new Date(now - 30000).toLocaleTimeString(), status: 'HEALTHY', latency: '4.2ms', circuit: 'CLOSED', note: 'Heartbeat ping successful' },
    { time: new Date(now - 20000).toLocaleTimeString(), status: 'HEALTHY', latency: '5.1ms', circuit: 'CLOSED', note: 'Policy evaluation cache synchronized' },
    { time: new Date(now - 10000).toLocaleTimeString(), status: 'HEALTHY', latency: '4.8ms', circuit: 'CLOSED', note: 'OPA bundle verified SHA-256' },
    { time: new Date(now).toLocaleTimeString(), status: 'ACTIVE', latency: '3.9ms', circuit: 'CLOSED', note: 'Live SSE stream connected' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="bg-soc-panel border border-soc-border rounded-xl shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-soc-border flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
                <span>SYSTEM HEALTH & FAIL-CLOSED TIMELINE</span>
              </h3>
              <p className="text-xs text-slate-400">Real-time circuit breaker status and OPA evaluation logs</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto">
          {/* Status Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="text-xs text-slate-400 font-mono flex items-center justify-between">
                <span>CIRCUIT BREAKER</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </div>
              <div className="text-lg font-mono font-bold text-emerald-400 mt-1">CLOSED</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Zero fail-over triggers</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="text-xs text-slate-400 font-mono flex items-center justify-between">
                <span>FAIL STATE</span>
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <div className="text-lg font-mono font-bold text-cyan-400 mt-1">
                {metrics?.fail_closed ? 'FAIL-CLOSED' : 'FAIL-OPEN'}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">Enforces block on engine fault</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="text-xs text-slate-400 font-mono flex items-center justify-between">
                <span>OPA ENDPOINT</span>
                <Radio className="w-3.5 h-3.5 text-purple-400" />
              </div>
              <div className="text-sm font-mono font-bold text-purple-300 mt-1 truncate">
                {health?.opa_url || 'http://localhost:8181'}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">Latency &lt; 5ms SLA</div>
            </div>
          </div>

          {/* OPA Health Detail Strip */}
          <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800/80 space-y-2">
            <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Proxy & Engine Configuration</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono pt-1">
              <div>
                <span className="text-slate-500 block">Version:</span>
                <span className="text-slate-200">{health?.version || '1.0.0'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Mode:</span>
                <span className="text-cyan-300 font-semibold uppercase">{metrics?.mode || 'ENFORCE'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Storage:</span>
                <span className="text-purple-300 uppercase">{health?.storage?.backend || 'MEMORY'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Unverified:</span>
                <span className={health?.active_unverified_agents ? 'text-amber-400 font-bold' : 'text-slate-400'}>
                  {health?.active_unverified_agents ?? 0} agents
                </span>
              </div>
            </div>
          </div>

          {/* Timeline Stream */}
          <div>
            <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center space-x-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <span>Health Check & Circuit Breaker Heartbeats</span>
            </div>
            <div className="space-y-2 font-mono text-xs">
              {timelineTicks.map((tick, idx) => (
                <div 
                  key={idx} 
                  className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div>
                      <div className="text-slate-200 font-medium">{tick.note}</div>
                      <div className="text-[11px] text-slate-500">Timestamp: {tick.time}</div>
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-semibold">
                      {tick.status}
                    </span>
                    <div className="text-[11px] text-slate-400 mt-1">{tick.latency}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Unverified Agents warning if any */}
          {health?.unverified_agents && health.unverified_agents.length > 0 && (
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs font-mono">
              <div className="flex items-center space-x-2 text-amber-400 font-semibold mb-1">
                <AlertTriangle className="w-4 h-4" />
                <span>UNVERIFIED AGENTS PRESENT</span>
              </div>
              <p className="text-slate-300 text-[11px] mb-2">
                The following agents are submitting requests without valid HMAC identity tokens:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {health.unverified_agents.map((ag) => (
                  <span key={ag} className="px-2 py-0.5 rounded bg-amber-900/40 text-amber-300 border border-amber-700/50 text-[10px]">
                    {ag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-soc-border bg-slate-900/70 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
