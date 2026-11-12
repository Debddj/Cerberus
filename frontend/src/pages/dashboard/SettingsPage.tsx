import React, { useCallback, useEffect, useState } from 'react';
import {
  Bell,
  Lock,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  Sliders,
  UserCheck,
} from 'lucide-react';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { StatusBanner } from '../../components/ui/StatusBanner';
import { useAuth } from '../../context/AuthContext';
import { useTelemetry } from '../../context/TelemetryContext';
import { useToast } from '../../context/ToastContext';
import { fetchSystemConfig, updateSystemConfig } from '../../services/api';
import type { SystemConfig } from '../../types';

export const SettingsPage: React.FC = () => {
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [source, setSource] = useState<'live' | 'offline-demo'>('live');
  const [saving, setSaving] = useState(false);

  const [notifyBlock, setNotifyBlock] = useState(true);
  const [notifyFlag, setNotifyFlag] = useState(true);
  const [notifyQuarantine, setNotifyQuarantine] = useState(true);

  const { user, authMode } = useAuth();
  const { connectionSource, refreshAll } = useTelemetry();
  const { addToast } = useToast();

  const loadConfig = useCallback(async () => {
    const res = await fetchSystemConfig();
    setConfig(res.data);
    setSource(res.source);
  }, []);

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!config) return;
    setSaving(true);
    try {
      const updated = await updateSystemConfig({
        mode: config.mode,
        fail_closed: config.fail_closed,
        require_signed_identity: config.require_signed_identity,
        rate_limit_per_minute: config.rate_limit_per_minute,
        risk_flag_threshold: config.risk_flag_threshold,
        risk_block_threshold: config.risk_block_threshold,
        risk_quarantine_threshold: config.risk_quarantine_threshold,
        scope_enforcement_mode: config.scope_enforcement_mode,
        trifecta_override: config.trifecta_override,
      });
      setConfig(updated);
      await refreshAll();
      addToast({
        title: 'Security configuration updated',
        description: 'Runtime thresholds and enforcement flags applied to FastAPI proxy.',
        variant: 'success',
      });
    } catch (err) {
      addToast({
        title: 'Could not save settings to backend',
        description: err instanceof Error ? err.message : 'Backend unavailable',
        variant: 'danger',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSaveConfig} className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Settings &amp; System Configuration
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Operator profile, HMAC authentication posture, risk thresholds, and live proxy controls
          </p>
        </div>
        <Button type="submit" disabled={saving || source === 'offline-demo'}>
          <Save className="w-4 h-4" />
          {saving ? 'Applying...' : 'Save Configuration'}
        </Button>
      </div>

      <StatusBanner source={source} onRetry={loadConfig} />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* User Profile & Authentication */}
        <Card className="lg:col-span-6 p-6 space-y-4">
          <CardHeader
            title="User Profile & Authentication"
            subtitle="Active SOC operator session and agent identity policy"
            icon={<UserCheck className="w-4 h-4" />}
          />
          <div className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between">
            <div>
              <p className="text-sm font-bold text-[#171638]">{user?.display_name || 'SOC Lead Analyst'}</p>
              <p className="text-xs text-[#666581]">
                Username: <code className="font-mono">{user?.username || 'admin'}</code> ·{' '}
                {user?.role || 'Security Administrator'}
              </p>
            </div>
            <Badge tone={authMode === 'live' ? 'success' : 'warning'}>
              {authMode === 'live' ? 'HMAC Session' : 'Offline Preview'}
            </Badge>
          </div>

          {config && (
            <div className="space-y-3 text-xs pt-2">
              <label className="flex items-center justify-between p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] cursor-pointer">
                <div>
                  <span className="font-bold text-[#171638] block">
                    Require Signed HMAC Agent Identity
                  </span>
                  <span className="text-[#666581]">
                    Reject unauthenticated MCP calls with JSON-RPC error -32001
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={config.require_signed_identity}
                  onChange={(e) =>
                    setConfig({ ...config, require_signed_identity: e.target.checked })
                  }
                  className="w-4 h-4 accent-[#6654E8]"
                />
              </label>

              <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between gap-4">
                <div>
                  <span className="font-bold text-[#171638] block">Rate Limit (Requests/Min)</span>
                  <span className="text-[#666581]">Per-tenant sliding window quota</span>
                </div>
                <input
                  type="number"
                  min={10}
                  max={5000}
                  value={config.rate_limit_per_minute}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      rate_limit_per_minute: parseInt(e.target.value, 10) || 120,
                    })
                  }
                  className="w-24 px-3 py-1.5 rounded-lg border border-[#E3DDF8] font-mono text-right bg-white"
                />
              </div>
            </div>
          )}
        </Card>

        {/* Backend Connection Status */}
        <Card className="lg:col-span-6 p-6 space-y-4">
          <CardHeader
            title="Backend & OPA Connection Status"
            subtitle="Live connectivity to FastAPI gateway and Open Policy Agent"
            icon={<Server className="w-4 h-4" />}
            actions={
              <Button type="button" variant="ghost" size="sm" onClick={loadConfig}>
                <RefreshCw className="w-3.5 h-3.5" />
              </Button>
            }
          />
          <div className="space-y-3 text-xs">
            <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between">
              <span className="font-semibold text-[#171638]">FastAPI Control Plane</span>
              <Badge tone={connectionSource === 'live' ? 'success' : 'danger'} dot>
                {connectionSource === 'live' ? 'Connected' : 'Unreachable'}
              </Badge>
            </div>
            <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#171638] block">Open Policy Agent (OPA)</span>
                <span className="font-mono text-[11px] text-[#666581]">{config?.opa_url}</span>
              </div>
              <Badge tone={config?.opa_connected ? 'success' : 'warning'} dot>
                {config?.opa_connected ? 'Online' : 'Offline (Fail-Closed Active)'}
              </Badge>
            </div>
            <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between">
              <span className="font-semibold text-[#171638]">Audit Encryption at Rest</span>
              <Badge tone={config?.encrypt_logs ? 'success' : 'neutral'}>
                {config?.encrypt_logs ? 'Fernet Enabled' : 'Disabled'}
              </Badge>
            </div>
          </div>
        </Card>

        {/* Security Preferences & Agent Scope */}
        {config && (
          <Card className="lg:col-span-6 p-6 space-y-4">
            <CardHeader
              title="Security Preferences & Agent Scope"
              subtitle="Control enforcement posture, fail-closed circuit breaker, and scope mode"
              icon={<ShieldCheck className="w-4 h-4" />}
            />

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="font-semibold text-[#171638] block mb-1">Firewall Mode</label>
                <select
                  value={config.mode}
                  onChange={(e) =>
                    setConfig({ ...config, mode: e.target.value as 'enforce' | 'audit' })
                  }
                  className="w-full px-3 py-2 rounded-xl border border-[#E3DDF8] bg-white font-semibold"
                >
                  <option value="enforce">Enforce (Block Threats)</option>
                  <option value="audit">Audit (Log Only)</option>
                </select>
              </div>
              <div>
                <label className="font-semibold text-[#171638] block mb-1">
                  Agent Scope Mode
                </label>
                <select
                  value={config.scope_enforcement_mode}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      scope_enforcement_mode: e.target.value as 'learn' | 'strict',
                    })
                  }
                  className="w-full px-3 py-2 rounded-xl border border-[#E3DDF8] bg-white font-semibold"
                >
                  <option value="learn">Learn (Monitor Undeclared)</option>
                  <option value="strict">Strict (Fail-Closed Scope)</option>
                </select>
              </div>
            </div>

            <div className="space-y-2.5 text-xs">
              <label className="flex items-center justify-between p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] cursor-pointer">
                <span className="font-semibold text-[#171638]">
                  Fail-Closed on OPA Outage (Recommended)
                </span>
                <input
                  type="checkbox"
                  checked={config.fail_closed}
                  onChange={(e) => setConfig({ ...config, fail_closed: e.target.checked })}
                  className="w-4 h-4 accent-[#6654E8]"
                />
              </label>
              <label className="flex items-center justify-between p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] cursor-pointer">
                <span className="font-semibold text-[#171638]">
                  Override Lethal Trifecta Static Block
                </span>
                <input
                  type="checkbox"
                  checked={config.trifecta_override}
                  onChange={(e) => setConfig({ ...config, trifecta_override: e.target.checked })}
                  className="w-4 h-4 accent-[#6654E8]"
                />
              </label>
            </div>
          </Card>
        )}

        {/* Risk Thresholds & Notifications */}
        <Card className="lg:col-span-6 p-6 space-y-5">
          <CardHeader
            title="Risk Thresholds & Notifications"
            subtitle="Adjust behavioral ensemble decision cutoffs and SOC alert preferences"
            icon={<Sliders className="w-4 h-4" />}
          />

          {config && (
            <div className="space-y-3 text-xs">
              <div>
                <div className="flex justify-between mb-1">
                  <span className="font-semibold text-[#B7720C]">Flag Threshold</span>
                  <strong className="font-mono">{config.risk_flag_threshold.toFixed(2)}</strong>
                </div>
                <input
                  type="range"
                  min="0.1"
                  max="0.8"
                  step="0.05"
                  value={config.risk_flag_threshold}
                  onChange={(e) =>
                    setConfig({ ...config, risk_flag_threshold: parseFloat(e.target.value) })
                  }
                  className="w-full accent-[#F4AD42]"
                />
              </div>

              <div>
                <div className="flex justify-between mb-1">
                  <span className="font-semibold text-[#C6384D]">Block Threshold</span>
                  <strong className="font-mono">{config.risk_block_threshold.toFixed(2)}</strong>
                </div>
                <input
                  type="range"
                  min="0.4"
                  max="0.95"
                  step="0.05"
                  value={config.risk_block_threshold}
                  onChange={(e) =>
                    setConfig({ ...config, risk_block_threshold: parseFloat(e.target.value) })
                  }
                  className="w-full accent-[#F06478]"
                />
              </div>

              <div>
                <div className="flex justify-between mb-1">
                  <span className="font-semibold text-[#6654E8]">Quarantine Threshold</span>
                  <strong className="font-mono">
                    {config.risk_quarantine_threshold.toFixed(2)}
                  </strong>
                </div>
                <input
                  type="range"
                  min="0.7"
                  max="1.0"
                  step="0.05"
                  value={config.risk_quarantine_threshold}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      risk_quarantine_threshold: parseFloat(e.target.value),
                    })
                  }
                  className="w-full accent-[#6654E8]"
                />
              </div>
            </div>
          )}

          <div className="pt-3 border-t border-[#E3DDF8] space-y-2 text-xs">
            <h4 className="font-bold text-[#171638] flex items-center gap-1.5">
              <Bell className="w-3.5 h-3.5 text-[#6654E8]" /> Notification Preferences
            </h4>
            <div className="flex flex-wrap gap-4">
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={notifyBlock}
                  onChange={(e) => setNotifyBlock(e.target.checked)}
                  className="accent-[#6654E8]"
                />
                Alert on Block
              </label>
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={notifyQuarantine}
                  onChange={(e) => setNotifyQuarantine(e.target.checked)}
                  className="accent-[#6654E8]"
                />
                Alert on Quarantine
              </label>
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={notifyFlag}
                  onChange={(e) => setNotifyFlag(e.target.checked)}
                  className="accent-[#6654E8]"
                />
                Alert on Flag
              </label>
            </div>
          </div>
        </Card>
      </div>
    </form>
  );
};

