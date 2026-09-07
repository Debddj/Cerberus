import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Lock, 
  Unlock, 
  AlertOctagon, 
  RefreshCw, 
  Radio
} from 'lucide-react';
import { MetricsSummary, HealthStatus } from '../types';

interface NavbarProps {
  metrics: MetricsSummary | null;
  health: HealthStatus | null;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isStreaming: boolean;
  onRefresh: () => void;
  loading: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  metrics,
  health,
  activeTab,
  setActiveTab,
  isStreaming,
  onRefresh,
  loading
}) => {
  const tabs = [
    { id: 'events', label: 'Live Events', icon: Activity },
    { id: 'timeline', label: 'Attack Chains', icon: AlertOctagon },
    { id: 'policies', label: 'Policy Engine', icon: ShieldAlert },
    { id: 'baselines', label: 'Baselines & Drift', icon: Activity },
    { id: 'audit', label: 'Audit Ledger', icon: Lock },
    { id: 'telemetry', label: 'Telemetry', icon: Radio },
  ];

  return (
    <header className="border-b border-soc-border glass-panel sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Brand */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center glow-cyan shadow-lg">
              <ShieldAlert className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold tracking-wider text-white font-mono">CERBERUS</span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-mono">
                  v{health?.version || '1.0.0'}
                </span>
              </div>
              <p className="text-xs text-slate-400">Autonomous AI Agent Behavioral Firewall</p>
            </div>
          </div>

          {/* Quick Telemetry Chips */}
          <div className="hidden md:flex items-center space-x-2 text-xs font-mono">
            {/* Live SSE pulse */}
            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700">
              <span className={`w-2 h-2 rounded-full ${isStreaming ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              <span className="text-slate-300">{isStreaming ? 'SSE LIVE' : 'POLLING'}</span>
            </div>

            {/* Mode Chip */}
            <div className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
              MODE: <span className="text-cyan-400 font-semibold">{metrics?.mode?.toUpperCase() || 'ENFORCE'}</span>
            </div>

            {/* Fail-Closed Guard */}
            <div className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
              FAIL: <span className={metrics?.fail_closed ? 'text-emerald-400' : 'text-amber-400'}>
                {metrics?.fail_closed ? 'CLOSED' : 'OPEN'}
              </span>
            </div>

            {/* Auth status */}
            <div className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
              {metrics?.require_signed_identity ? (
                <>
                  <Lock className="w-3 h-3 text-emerald-400" />
                  <span className="text-emerald-400">HMAC SIGNED</span>
                </>
              ) : (
                <>
                  <Unlock className="w-3 h-3 text-amber-400" />
                  <span className="text-amber-400">PERMISSIVE</span>
                </>
              )}
            </div>

            {/* Storage backend */}
            <div className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
              STORAGE: <span className="text-purple-400">{health?.storage?.backend?.toUpperCase() || 'IN-MEMORY'}</span>
            </div>

            {/* Manual refresh */}
            <button
              onClick={onRefresh}
              disabled={loading}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Refresh Data"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-1 overflow-x-auto py-2 border-t border-slate-800/80">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
