import React, { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle2,
  FileCode2,
  History,
  Play,
  Plus,
  RefreshCw,
  Save,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  XCircle,
} from 'lucide-react';
import { Badge, decisionTone } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { Modal } from '../../components/ui/Modal';
import { RegoHighlighter } from '../../components/ui/RegoHighlighter';
import { StatusBanner } from '../../components/ui/StatusBanner';
import { useToast } from '../../context/ToastContext';
import {
  approvePolicy,
  createPolicy,
  fetchPolicies,
  fetchPolicyHistory,
  fetchSystemConfig,
  rejectPolicy,
  simulatePolicy,
  togglePolicy,
  updatePolicy,
} from '../../services/api';
import type { Policy, PolicyHistoryEntry, SystemConfig } from '../../types';

const NEW_POLICY_TEMPLATE = `package cerberus.custom.guardrail

default allow := true

deny if {
    input.tool_name == "http_post"
    input.risk_score >= 0.65
}

reason := "Custom guardrail blocked elevated external POST" if {
    deny
}`;

export const PoliciesPage: React.FC = () => {
  const [policies, setPolicies] = useState<{ active: Policy[]; pending: Policy[] }>({
    active: [],
    pending: [],
  });
  const [source, setSource] = useState<'live' | 'offline-demo'>('live');
  const [selected, setSelected] = useState<Policy | null>(null);
  const [editorCode, setEditorCode] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [saving, setSaving] = useState(false);

  const [history, setHistory] = useState<PolicyHistoryEntry[]>([]);
  const [sysConfig, setSysConfig] = useState<SystemConfig | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState('custom_egress.rego');
  const [newCode, setNewCode] = useState(NEW_POLICY_TEMPLATE);

  const [simOpen, setSimOpen] = useState(false);
  const [simTool, setSimTool] = useState('http_post');
  const [simAgent, setSimAgent] = useState('OpsAgent-04');
  const [simDomain, setSimDomain] = useState('evil-collector.io');
  const [simRisk, setSimRisk] = useState(0.85);
  const [simTrifecta, setSimTrifecta] = useState(true);
  const [simSchemaDrift, setSimSchemaDrift] = useState(false);
  const [simResult, setSimResult] = useState<Record<string, unknown> | null>(null);
  const [simulating, setSimulating] = useState(false);

  const { addToast } = useToast();

  const loadAll = useCallback(async () => {
    const [polRes, histData, cfgRes] = await Promise.all([
      fetchPolicies(),
      fetchPolicyHistory(),
      fetchSystemConfig(),
    ]);
    setPolicies(polRes.data);
    setSource(polRes.source);
    setHistory(histData);
    setSysConfig(cfgRes.data);

    setSelected((prev) => {
      const all = [...polRes.data.pending, ...polRes.data.active];
      if (!prev) return all[0] || null;
      return (
        all.find(
          (p) =>
            (prev.policy_id && p.policy_id === prev.policy_id) ||
            (prev.name && p.name === prev.name)
        ) || all[0] || null
      );
    });
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  useEffect(() => {
    setEditorCode(selected?.code || '');
    setIsEditing(false);
  }, [selected?.name, selected?.policy_id]);

  const handleSaveEdit = async () => {
    if (!selected?.name) return;
    setSaving(true);
    try {
      const res = await updatePolicy(selected.name, { code: editorCode, push_to_opa: true });
      addToast({
        title: res.opa_pushed
          ? `Policy '${res.name}' saved & pushed to OPA`
          : `Policy '${res.name}' saved on disk (OPA offline)`,
        description: res.opa_error || 'Confirmed by FastAPI policy manager.',
        variant: res.opa_pushed ? 'success' : 'warning',
      });
      setIsEditing(false);
      await loadAll();
    } catch (err) {
      addToast({
        title: 'Save failed — policy NOT applied',
        description: err instanceof Error ? err.message : 'Backend error',
        variant: 'danger',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (name: string) => {
    try {
      const res = await togglePolicy(name);
      addToast({
        title: `${res.name} ${res.enabled ? 'enabled' : 'disabled'}`,
        variant: 'info',
      });
      await loadAll();
    } catch (err) {
      addToast({
        title: 'Toggle failed',
        description: err instanceof Error ? err.message : 'Backend error',
        variant: 'danger',
      });
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await createPolicy({ name: newName, code: newCode, push_to_opa: true });
      addToast({
        title: res.opa_pushed
          ? `Created '${res.name}' & synced to OPA`
          : `Created '${res.name}' locally (OPA offline)`,
        description: res.opa_error || undefined,
        variant: res.opa_pushed ? 'success' : 'warning',
      });
      setCreateOpen(false);
      await loadAll();
    } catch (err) {
      addToast({
        title: 'Failed to create policy',
        description: err instanceof Error ? err.message : 'Invalid Rego or backend error',
        variant: 'danger',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleApprove = async (policyId: string) => {
    try {
      await approvePolicy(policyId);
      addToast({ title: `Approved policy ${policyId}`, variant: 'success' });
      await loadAll();
    } catch (err) {
      addToast({
        title: 'Approval failed',
        description: err instanceof Error ? err.message : 'Backend unavailable',
        variant: 'danger',
      });
    }
  };

  const handleReject = async (policyId: string) => {
    try {
      await rejectPolicy(policyId);
      addToast({ title: `Rejected policy ${policyId}`, variant: 'info' });
      await loadAll();
    } catch (err) {
      addToast({
        title: 'Rejection failed',
        description: err instanceof Error ? err.message : 'Backend unavailable',
        variant: 'danger',
      });
    }
  };

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      const res = await simulatePolicy({
        event: {
          event_id: `sim-${Date.now()}`,
          session_id: 'dry-run-session',
          agent_id: simAgent,
          tool_name: simTool,
          tool_server: 'upstream-sim',
          parameters: { destination: simDomain },
          destination_domain: simDomain,
          risk_score: simRisk,
          sequence_position: 1,
          risk_factors: ['Dry-Run Simulation'],
          redacted_fields: [],
        },
        static_scan: {
          schema_drift: simSchemaDrift,
          lethal_trifecta: simTrifecta,
          out_of_scope: false,
        },
      });
      setSimResult(res);
    } catch (err) {
      setSimResult({
        error: err instanceof Error ? err.message : 'Backend unreachable for OPA dry-run',
      });
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Policy Management (OPA / Rego)
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Author Rego guardrails, approve auto-synthesized least-privilege rules, and dry-run
            policy decisions
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button variant="outline" size="sm" onClick={() => setSimOpen(true)}>
            <Play className="w-3.5 h-3.5 text-[#6654E8]" />
            Test Policy
          </Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" />
            New Policy
          </Button>
        </div>
      </div>

      <StatusBanner source={source} onRetry={loadAll} />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar: Pending + Active Policies */}
        <div className="lg:col-span-4 space-y-5">
          <Card className="p-4 space-y-2.5">
            <h2 className="text-xs font-bold uppercase tracking-wider text-[#B7720C] flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              Pending Approval ({policies.pending.length})
            </h2>
            {policies.pending.length === 0 ? (
              <p className="text-xs text-[#666581] py-3 text-center">
                No synthesized policies awaiting review.
              </p>
            ) : (
              policies.pending.map((p) => {
                const active = selected?.policy_id === p.policy_id;
                return (
                  <button
                    key={p.policy_id}
                    onClick={() => setSelected(p)}
                    className={`w-full text-left p-3 rounded-xl border transition-all ${
                      active
                        ? 'bg-[#FFFBF2] border-[#F4AD42]'
                        : 'bg-[#FAF8FF] border-[#E3DDF8] hover:bg-[#F3F0FF]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#171638]">
                        {p.policy_id}
                      </span>
                      <Badge tone="warning">Pending</Badge>
                    </div>
                    <p className="text-[11px] text-[#666581] mt-1">
                      {p.tool_name} · {p.agent_id}
                    </p>
                  </button>
                );
              })
            )}
          </Card>

          <Card className="p-4 space-y-2.5">
            <h2 className="text-xs font-bold uppercase tracking-wider text-[#6654E8] flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              Active Rego Bundles ({policies.active.length})
            </h2>
            <div className="space-y-2">
              {policies.active.map((p) => {
                const active = selected?.name === p.name;
                return (
                  <button
                    key={p.path || p.name}
                    onClick={() => setSelected(p)}
                    className={`w-full text-left p-3 rounded-xl border transition-all ${
                      active
                        ? 'bg-[#EAE6FF] border-[#6654E8]'
                        : 'bg-[#FAF8FF] border-[#E3DDF8] hover:bg-[#F3F0FF]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-bold text-[#171638] truncate">
                        {p.name}
                      </span>
                      <Badge tone={p.enabled !== false ? 'success' : 'neutral'}>
                        {p.enabled !== false ? 'Active' : 'Disabled'}
                      </Badge>
                    </div>
                    <p className="text-[11px] font-mono text-[#666581] truncate mt-0.5">{p.path}</p>
                  </button>
                );
              })}
            </div>
          </Card>
        </div>

        {/* Center/Right: Rego Code Editor + Status Panel */}
        <div className="lg:col-span-8 space-y-6">
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
            <Card className="xl:col-span-8 p-5 space-y-4">
              {selected ? (
                <>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <FileCode2 className="w-4 h-4 text-[#6654E8]" />
                      <h3 className="text-base font-bold font-mono text-[#171638]">
                        {selected.policy_id || selected.name}
                      </h3>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {selected.type === 'pending' && selected.policy_id ? (
                        <>
                          <Button
                            size="sm"
                            variant="success"
                            onClick={() => handleApprove(selected.policy_id!)}
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" /> Approve &amp; Push
                          </Button>
                          <Button
                            size="sm"
                            variant="danger"
                            onClick={() => handleReject(selected.policy_id!)}
                          >
                            <XCircle className="w-3.5 h-3.5" /> Reject
                          </Button>
                        </>
                      ) : selected.name ? (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleToggle(selected.name!)}
                          >
                            {selected.enabled !== false ? 'Disable' : 'Enable'}
                          </Button>
                          {isEditing ? (
                            <Button size="sm" onClick={handleSaveEdit} disabled={saving}>
                              <Save className="w-3.5 h-3.5" />
                              {saving ? 'Saving...' : 'Save & Sync OPA'}
                            </Button>
                          ) : (
                            <Button size="sm" onClick={() => setIsEditing(true)}>
                              Edit Rego
                            </Button>
                          )}
                        </>
                      ) : null}
                    </div>
                  </div>

                  <RegoHighlighter
                    code={isEditing ? editorCode : selected.code || ''}
                    editable={isEditing}
                    onChange={setEditorCode}
                    filename={selected.name || `${selected.policy_id}.rego`}
                  />
                </>
              ) : (
                <p className="text-xs text-[#666581] py-12 text-center">
                  Select a policy bundle to inspect or edit Rego rules.
                </p>
              )}
            </Card>

            {/* Policy Status Card matching collage */}
            <Card className="xl:col-span-4 p-5 space-y-4">
              <h3 className="text-sm font-bold text-[#171638]">Policy Status</h3>
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between">
                  <span className="text-[#666581]">Bundle State</span>
                  <Badge tone={selected?.enabled !== false ? 'success' : 'warning'} dot>
                    {selected?.type === 'pending'
                      ? 'Pending Review'
                      : selected?.enabled !== false
                        ? 'Active'
                        : 'Disabled'}
                  </Badge>
                </div>

                <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between">
                  <span className="text-[#666581]">OPA Sidecar</span>
                  <Badge tone={sysConfig?.opa_connected ? 'success' : 'warning'} dot>
                    {sysConfig?.opa_connected ? 'Connected' : 'Unreachable'}
                  </Badge>
                </div>

                <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between">
                  <span className="text-[#666581]">Enforcement</span>
                  <Badge tone={sysConfig?.fail_closed !== false ? 'primary' : 'warning'}>
                    {sysConfig?.fail_closed !== false ? 'Fail-Closed' : 'Fail-Open'}
                  </Badge>
                </div>

                <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] space-y-1">
                  <span className="text-[#666581] block">Risk Thresholds</span>
                  <p className="font-mono font-semibold text-[#171638]">
                    Flag ≥ {sysConfig?.risk_flag_threshold ?? 0.4} · Block ≥{' '}
                    {sysConfig?.risk_block_threshold ?? 0.7} · Quarantine ≥{' '}
                    {sysConfig?.risk_quarantine_threshold ?? 0.9}
                  </p>
                </div>
              </div>
            </Card>
          </div>

          {/* Policy History */}
          <Card className="p-5 space-y-3">
            <CardHeader
              title="Policy Audit History"
              subtitle="Confirmed edits, creations, and approvals"
              icon={<History className="w-4 h-4" />}
              actions={
                <Button variant="ghost" size="sm" onClick={loadAll}>
                  <RefreshCw className="w-3.5 h-3.5" />
                </Button>
              }
            />
            {history.length === 0 ? (
              <p className="text-xs text-[#666581] py-4 text-center">
                No policy changes recorded in this session yet.
              </p>
            ) : (
              <div className="space-y-2">
                {history.slice(0, 8).map((h, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                  >
                    <div>
                      <strong className="text-[#6654E8] uppercase">{h.action}</strong>{' '}
                      <span className="text-[#171638] font-bold">{h.policy_name}</span>
                      <span className="text-[#666581] ml-2">— {h.detail}</span>
                    </div>
                    <Badge tone={h.opa_pushed ? 'success' : 'neutral'}>
                      {h.opa_pushed ? 'OPA Synced' : 'Disk Only'}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Create Policy Modal */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create Custom Rego Policy"
        subtitle="Saved under policies/custom/ and pushed to OPA when reachable"
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="text-xs font-semibold text-[#171638] block mb-1">
              Policy Filename (.rego)
            </label>
            <input
              type="text"
              required
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm font-mono"
            />
          </div>
          <RegoHighlighter code={newCode} editable onChange={setNewCode} filename={newName} />
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={saving}>
              {saving ? 'Saving...' : 'Create Policy'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Dry-Run Simulation Modal */}
      <Modal
        open={simOpen}
        onClose={() => setSimOpen(false)}
        title="Dry-Run Policy Simulator"
        subtitle="Evaluate synthetic tool call telemetry against POST /policy/simulate"
        maxWidth="max-w-2xl"
      >
        <div className="space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="font-semibold block mb-1">Tool Name</label>
              <input
                type="text"
                value={simTool}
                onChange={(e) => setSimTool(e.target.value)}
                className="w-full px-3 py-2 rounded-xl border border-[#E3DDF8] font-mono"
              />
            </div>
            <div>
              <label className="font-semibold block mb-1">Agent ID</label>
              <input
                type="text"
                value={simAgent}
                onChange={(e) => setSimAgent(e.target.value)}
                className="w-full px-3 py-2 rounded-xl border border-[#E3DDF8] font-mono"
              />
            </div>
            <div>
              <label className="font-semibold block mb-1">Destination Domain</label>
              <input
                type="text"
                value={simDomain}
                onChange={(e) => setSimDomain(e.target.value)}
                className="w-full px-3 py-2 rounded-xl border border-[#E3DDF8] font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-center">
            <div>
              <label className="font-semibold block mb-1">
                Risk Score: {(simRisk * 100).toFixed(0)}%
              </label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={simRisk}
                onChange={(e) => setSimRisk(parseFloat(e.target.value))}
                className="w-full accent-[#6654E8]"
              />
            </div>
            <label className="inline-flex items-center gap-2 font-medium cursor-pointer">
              <input
                type="checkbox"
                checked={simTrifecta}
                onChange={(e) => setSimTrifecta(e.target.checked)}
                className="accent-[#6654E8]"
              />
              Lethal Trifecta Flag
            </label>
            <label className="inline-flex items-center gap-2 font-medium cursor-pointer">
              <input
                type="checkbox"
                checked={simSchemaDrift}
                onChange={(e) => setSimSchemaDrift(e.target.checked)}
                className="accent-[#6654E8]"
              />
              Schema Drift Flag
            </label>
          </div>

          <Button onClick={handleSimulate} disabled={simulating}>
            <ShieldAlert className="w-4 h-4" />
            {simulating ? 'Evaluating...' : 'Run Dry-Run Simulation'}
          </Button>

          {simResult && (
            <div className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] space-y-2">
              {typeof simResult.final_decision === 'string' && (
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[#171638]">Verdict</span>
                  <Badge tone={decisionTone(simResult.final_decision)}>
                    {simResult.final_decision.toUpperCase()}
                  </Badge>
                </div>
              )}
              <pre className="font-mono text-[11px] text-[#171638] overflow-x-auto max-h-56">
                {JSON.stringify(simResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};

