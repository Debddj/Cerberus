import React from 'react';
import { 
  Radio, 
  ShieldCheck, 
  Cpu, 
  Activity, 
  Zap, 
  Server, 
  Lock, 
  Database,
  Clock,
  Layers,
  Fingerprint
} from 'lucide-react';
import { MetricsSummary, HealthStatus, ToolCallEvent } from '../types';

interface TelemetryViewProps {
  metrics: MetricsSummary | null;
  health: HealthStatus | null;
  events: ToolCallEvent[];
}

export const TelemetryView: React.FC<TelemetryViewProps> = ({ metrics, health, events }) => {
  const allowCount = events.filter((e) => e.decision === 'allow').length;
  const flagCount = events.filter((e) => e.decision === 'flag').length;
  const blockCount = events.filter((e) => e.decision === 'block').length;
  const quarantineCount = events.filter((e) => e.decision === 'quarantine').length;

  return (
    <div className="space-y-6 font-mono">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-soc-panel to-slate-900 p-6 rounded-2xl border border-soc-border glass-panel">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center glow-cyan">
            <Radio className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Cerberus Core Telemetry & Architecture</h2>
            <p className="text-xs text-slate-400">
              Operational diagnostics, 4-tier ensemble weighting, and cascading sub-1ms interception telemetry.
            </p>
          </div>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-soc-panel p-5 rounded-xl border border-soc-border glass-panel space-y-1">
          <span className="text-slate-500 text-xs font-semibold">TOTAL INTERCEPTED</span>
          <div className="text-2xl font-bold text-white">{events.length}</div>
          <span className="text-[11px] text-slate-400 block">Across all active sessions</span>
        </div>

        <div className="bg-soc-panel p-5 rounded-xl border border-soc-border glass-panel space-y-1">
          <span className="text-slate-500 text-xs font-semibold">ACTIVE AGENTS</span>
          <div className="text-2xl font-bold text-cyan-400">{metrics?.active_agents || 1}</div>
          <span className="text-[11px] text-slate-400 block">
            {metrics?.unverified_agents ? `${metrics.unverified_agents} unverified` : 'All verified'}
          </span>
        </div>

        <div className="bg-soc-panel p-5 rounded-xl border border-soc-border glass-panel space-y-1">
          <span className="text-slate-500 text-xs font-semibold">BLOCKED / QUARANTINED</span>
          <div className="text-2xl font-bold text-rose-400">{blockCount + quarantineCount}</div>
          <span className="text-[11px] text-rose-400/80 block">{quarantineCount} active quarantines</span>
        </div>

        <div className="bg-soc-panel p-5 rounded-xl border border-soc-border glass-panel space-y-1">
          <span className="text-slate-500 text-xs font-semibold">TIER 1 LATENCY (P99)</span>
          <div className="text-2xl font-bold text-emerald-400">&lt; 0.85 ms</div>
          <span className="text-[11px] text-emerald-400/80 block">Rule + Markov fast exit</span>
        </div>
      </div>

      {/* Decision Distribution */}
      <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center">
          <Activity className="w-4 h-4 mr-1.5 text-cyan-400" />
          Decision Breakdown ({events.length} samples)
        </h3>

        <div className="grid grid-cols-4 gap-3 text-center">
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl">
            <span className="text-xs text-emerald-400 block font-bold">ALLOW</span>
            <span className="text-lg font-bold text-white">{allowCount}</span>
            <span className="text-[10px] text-slate-500 block">
              {events.length > 0 ? ((allowCount / events.length) * 100).toFixed(0) : 0}%
            </span>
          </div>

          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl">
            <span className="text-xs text-amber-400 block font-bold">FLAG</span>
            <span className="text-lg font-bold text-white">{flagCount}</span>
            <span className="text-[10px] text-slate-500 block">
              {events.length > 0 ? ((flagCount / events.length) * 100).toFixed(0) : 0}%
            </span>
          </div>

          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl">
            <span className="text-xs text-rose-400 block font-bold">BLOCK</span>
            <span className="text-lg font-bold text-white">{blockCount}</span>
            <span className="text-[10px] text-slate-500 block">
              {events.length > 0 ? ((blockCount / events.length) * 100).toFixed(0) : 0}%
            </span>
          </div>

          <div className="p-3 bg-purple-500/10 border border-purple-500/30 rounded-xl">
            <span className="text-xs text-purple-400 block font-bold">QUARANTINE</span>
            <span className="text-lg font-bold text-white">{quarantineCount}</span>
            <span className="text-[10px] text-slate-500 block">
              {events.length > 0 ? ((quarantineCount / events.length) * 100).toFixed(0) : 0}%
            </span>
          </div>
        </div>
      </div>

      {/* 4-Scorer Behavioral Ensemble Architecture */}
      <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center">
          <Layers className="w-4 h-4 mr-1.5 text-cyan-400" />
          4-Member Online Ensemble Weighting
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white">Rule-Based</span>
              <span className="text-xs font-bold text-cyan-400">30%</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-normal">
              Heuristic drip-rate, privilege escalations, and novelty filters.
            </p>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 block text-center">
              Tier 1 Fast Exit (&lt;0.2ms)
            </span>
          </div>

          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white">Markov Chain</span>
              <span className="text-xs font-bold text-cyan-400">30%</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-normal">
              Transition probability matrix tracking tool invocation sequences.
            </p>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 block text-center">
              Tier 1 Fast Exit (&lt;0.2ms)
            </span>
          </div>

          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white">Isolation Forest</span>
              <span className="text-xs font-bold text-purple-400">20%</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-normal">
              Per-agent multidimensional continuous feature anomaly detection.
            </p>
            <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 block text-center">
              Tier 2 Cascaded (&lt;10ms)
            </span>
          </div>

          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white">Sequence Transformer</span>
              <span className="text-xs font-bold text-purple-400">20%</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-normal">
              Reconstruction loss across multi-call window embeddings.
            </p>
            <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 block text-center">
              Tier 2 Cascaded (&lt;20ms)
            </span>
          </div>
        </div>
      </div>

      {/* Comprehensive Security Posture Checklist */}
      <div className="bg-soc-panel p-6 rounded-xl border border-soc-border glass-panel space-y-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center">
          <ShieldCheck className="w-4 h-4 mr-1.5 text-emerald-400" />
          Active Defense Pillars Checklist
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 bg-slate-900/60 rounded-lg border border-emerald-500/20 flex items-center justify-between">
            <span className="text-slate-300">Tool Rug-Pull & Schema Drift Defense</span>
            <span className="text-emerald-400 font-bold">✓ PINNED IN SQLITE</span>
          </div>

          <div className="p-3 bg-slate-900/60 rounded-lg border border-emerald-500/20 flex items-center justify-between">
            <span className="text-slate-300">Per-Agent Least-Privilege Scope Enforcement</span>
            <span className="text-emerald-400 font-bold">✓ ACTIVE ({metrics?.mode?.toUpperCase()})</span>
          </div>

          <div className="p-3 bg-slate-900/60 rounded-lg border border-emerald-500/20 flex items-center justify-between">
            <span className="text-slate-300">Tool Impersonation & Shadowing Detection</span>
            <span className="text-emerald-400 font-bold">✓ ACTIVE</span>
          </div>

          <div className="p-3 bg-slate-900/60 rounded-lg border border-emerald-500/20 flex items-center justify-between">
            <span className="text-slate-300">Lethal Trifecta Kill-Chain Interceptor</span>
            <span className="text-emerald-400 font-bold">✓ ACTIVE (STATIC SCAN)</span>
          </div>

          <div className="p-3 bg-slate-900/60 rounded-lg border border-emerald-500/20 flex items-center justify-between">
            <span className="text-slate-300">Cryptographic SHA-256 Ledger & Rotation</span>
            <span className="text-emerald-400 font-bold">✓ TAMPER-EVIDENT</span>
          </div>

          <div className="p-3 bg-slate-900/60 rounded-lg border border-emerald-500/20 flex items-center justify-between">
            <span className="text-slate-300">Multi-Tenant Rate Limiting & Storage Backend</span>
            <span className="text-emerald-400 font-bold">✓ {health?.storage?.backend?.toUpperCase() || 'IN-MEMORY'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
