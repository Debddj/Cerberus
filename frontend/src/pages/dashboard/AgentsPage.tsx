import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Bot,
  Check,
  Copy,
  KeyRound,
  MoreHorizontal,
  PauseCircle,
  PlayCircle,
  Plus,
  Search,
  Server,
  Trash2,
  Zap,
} from 'lucide-react';
import { Badge, decisionTone } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card } from '../../components/ui/Card';
import { ConfirmDialog } from '../../components/ui/ConfirmDialog';
import { Drawer } from '../../components/ui/Drawer';
import { EmptyState } from '../../components/ui/EmptyState';
import { Modal } from '../../components/ui/Modal';
import { StatusBanner } from '../../components/ui/StatusBanner';
import { useToast } from '../../context/ToastContext';
import {
  activateAgent,
  deleteAgent,
  fetchAgentBaseline,
  fetchAgents,
  issueAgentToken,
  promoteBaseline,
  registerAgent,
  suspendAgent,
} from '../../services/api';
import type { AgentSummary, BaselineAgent } from '../../types';

function formatActivityTime(val?: number | string | null): string {
  if (!val) return 'Never';
  const ms = typeof val === 'number' ? (val > 1e12 ? val : val * 1000) : Date.parse(val);
  if (Number.isNaN(ms)) return 'Recent';
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export const AgentsPage: React.FC = () => {
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [source, setSource] = useState<'live' | 'offline-demo'>('live');
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'risk' | 'calls' | 'name'>('risk');

  const [registerOpen, setRegisterOpen] = useState(false);
  const [newAgentId, setNewAgentId] = useState('');
  const [newType, setNewType] = useState('Coding');
  const [newServers, setNewServers] = useState('file-server, github-server');
  const [newTools, setNewTools] = useState('read_file, search_code, run_tests');
  const [enforceScope, setEnforceScope] = useState(true);
  const [issueTokenOnReg, setIssueTokenOnReg] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const [issuedTokenInfo, setIssuedTokenInfo] = useState<{ agentId: string; token: string } | null>(
    null
  );
  const [copiedToken, setCopiedToken] = useState(false);

  const [selectedAgent, setSelectedAgent] = useState<AgentSummary | null>(null);
  const [agentBaseline, setAgentBaseline] = useState<BaselineAgent | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AgentSummary | null>(null);

  const { addToast } = useToast();

  const loadAgents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchAgents();
      setAgents(res.data);
      setSource(res.source);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAgents();
  }, [loadAgents]);

  const filteredAgents = useMemo(() => {
    return agents
      .filter((a) => {
        if (statusFilter !== 'all' && (a.status || 'active') !== statusFilter) return false;
        if (search.trim()) {
          const q = search.toLowerCase();
          return (
            a.agent_id.toLowerCase().includes(q) ||
            (a.agent_type || '').toLowerCase().includes(q) ||
            (a.mcp_servers || []).some((s) => s.toLowerCase().includes(q))
          );
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'risk') return (b.current_risk_score || 0) - (a.current_risk_score || 0);
        if (sortBy === 'calls') return b.total_events - a.total_events;
        return a.agent_id.localeCompare(b.agent_id);
      });
  }, [agents, search, statusFilter, sortBy]);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await registerAgent({
        agent_id: newAgentId.trim(),
        agent_type: newType,
        mcp_servers: newServers
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        authorized_tools: newTools
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        enforce_scope: enforceScope,
        issue_token: issueTokenOnReg,
      });
      addToast({
        title: `Agent '${res.agent_id}' registered`,
        description: 'Least-privilege scope registered in ScopeAnalyzer.',
        variant: 'success',
      });
      setRegisterOpen(false);
      setNewAgentId('');
      if (res.token) {
        setIssuedTokenInfo({ agentId: res.agent_id, token: res.token });
      }
      await loadAgents();
    } catch (err) {
      addToast({
        title: 'Failed to register agent',
        description: err instanceof Error ? err.message : 'Backend unavailable',
        variant: 'danger',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleSuspend = async (agent: AgentSummary) => {
    try {
      if (agent.status === 'suspended') {
        await activateAgent(agent.agent_id);
        addToast({ title: `Reactivated ${agent.agent_id}`, variant: 'success' });
      } else {
        await suspendAgent(agent.agent_id);
        addToast({
          title: `Suspended ${agent.agent_id}`,
          description: 'All future MCP tool calls from this agent will be blocked.',
          variant: 'warning',
        });
      }
      await loadAgents();
    } catch (err) {
      addToast({
        title: 'Action failed',
        description: err instanceof Error ? err.message : 'Backend error',
        variant: 'danger',
      });
    }
  };

  const handleIssueToken = async (agentId: string) => {
    try {
      const res = await issueAgentToken(agentId);
      setIssuedTokenInfo({ agentId: res.agent_id, token: res.token });
    } catch (err) {
      addToast({
        title: 'Token issuance failed',
        description: err instanceof Error ? err.message : 'Backend error',
        variant: 'danger',
      });
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await deleteAgent(deleteTarget.agent_id);
      addToast({ title: `Disconnected ${deleteTarget.agent_id}`, variant: 'info' });
      setDeleteTarget(null);
      if (selectedAgent?.agent_id === deleteTarget.agent_id) setSelectedAgent(null);
      await loadAgents();
    } catch (err) {
      addToast({
        title: 'Disconnect failed',
        description: err instanceof Error ? err.message : 'Backend error',
        variant: 'danger',
      });
    }
  };

  const openInspector = async (agent: AgentSummary) => {
    setSelectedAgent(agent);
    const base = await fetchAgentBaseline(agent.agent_id);
    setAgentBaseline(base);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">Agents</h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Manage registered autonomous agents, MCP server scopes, HMAC identities, and baseline health
          </p>
        </div>
        <Button onClick={() => setRegisterOpen(true)}>
          <Plus className="w-4 h-4" />
          Register Agent
        </Button>
      </div>

      <StatusBanner source={source} onRetry={loadAgents} />

      {/* Search, Filter & Sort Controls */}
      <Card className="p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-[#8C7BFA] absolute left-3.5 top-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by agent ID, type, or MCP server..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-sm focus:outline-none focus:border-[#6654E8]"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {(['all', 'active', 'flagged', 'quarantined', 'suspended'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold capitalize transition-all ${
                statusFilter === st
                  ? 'cerberus-gradient-btn text-white'
                  : 'bg-[#F3F0FF] text-[#666581] hover:text-[#171638]'
              }`}
            >
              {st}
            </button>
          ))}

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'risk' | 'calls' | 'name')}
            className="px-3 py-1.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-xs font-semibold text-[#171638]"
            aria-label="Sort agents"
          >
            <option value="risk">Sort: Risk Score</option>
            <option value="calls">Sort: Total Calls</option>
            <option value="name">Sort: Agent ID</option>
          </select>
        </div>
      </Card>

      {/* Agents Table */}
      {loading && agents.length === 0 ? (
        <Card className="p-10 text-center text-sm text-[#666581]">Loading registered agents...</Card>
      ) : filteredAgents.length === 0 ? (
        <EmptyState
          title="No Matching Agents"
          description="Register a new autonomous agent or send MCP requests through POST /mcp to observe agents automatically."
          action={
            <Button onClick={() => setRegisterOpen(true)}>
              <Plus className="w-4 h-4" /> Register New Agent
            </Button>
          }
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#FAF8FF] border-b border-[#E3DDF8] text-[#666581]">
                <tr>
                  <th className="px-5 py-3.5 font-semibold">Agent Name</th>
                  <th className="px-4 py-3.5 font-semibold">Type</th>
                  <th className="px-4 py-3.5 font-semibold">Status</th>
                  <th className="px-4 py-3.5 font-semibold">MCP Servers</th>
                  <th className="px-4 py-3.5 font-semibold">Baseline</th>
                  <th className="px-4 py-3.5 font-semibold">Risk</th>
                  <th className="px-4 py-3.5 font-semibold">Last Activity</th>
                  <th className="px-5 py-3.5 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F3F0FF]">
                {filteredAgents.map((agent) => {
                  const status = agent.status || 'active';
                  return (
                    <tr
                      key={agent.agent_id}
                      onClick={() => openInspector(agent)}
                      className="hover:bg-[#FAF8FF] cursor-pointer transition-colors"
                    >
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-xl bg-[#EAE6FF] text-[#6654E8] flex items-center justify-center shrink-0">
                            <Bot className="w-4 h-4" />
                          </div>
                          <div>
                            <p className="font-bold text-[#171638] text-sm">{agent.agent_id}</p>
                            <p className="text-[11px] font-mono text-[#666581]">
                              {agent.trust_level === 'verified' ? 'HMAC Verified' : 'Unverified'} ·{' '}
                              {agent.total_events} calls
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 font-medium text-[#666581]">
                        {agent.agent_type || 'Autonomous'}
                      </td>
                      <td className="px-4 py-3.5">
                        <Badge tone={decisionTone(status)} dot className="capitalize">
                          {status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3.5 font-mono text-[#666581]">
                        {(agent.mcp_servers || []).length > 0
                          ? agent.mcp_servers!.slice(0, 2).join(', ')
                          : 'upstream-server'}
                      </td>
                      <td className="px-4 py-3.5">
                        <Badge tone={agent.is_warm ? 'primary' : 'neutral'}>
                          {agent.is_warm ? `Warm (${agent.active_snapshot || 'snap'})` : 'Learning'}
                        </Badge>
                      </td>
                      <td className="px-4 py-3.5 font-mono font-bold text-[#171638]">
                        {(agent.current_risk_score || 0).toFixed(2)}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-[#666581]">
                        {formatActivityTime(agent.last_activity)}
                      </td>
                      <td
                        className="px-5 py-3.5 text-right"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="inline-flex items-center gap-1">
                          <button
                            onClick={() => openInspector(agent)}
                            className="p-1.5 rounded-lg hover:bg-[#EAE6FF] text-[#6654E8]"
                            title="Inspect agent details"
                          >
                            <MoreHorizontal className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleIssueToken(agent.agent_id)}
                            className="p-1.5 rounded-lg hover:bg-[#EAE6FF] text-[#6654E8]"
                            title="Issue HMAC token"
                          >
                            <KeyRound className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleToggleSuspend(agent)}
                            className="p-1.5 rounded-lg hover:bg-[#F4AD42]/15 text-[#B7720C]"
                            title={status === 'suspended' ? 'Reactivate agent' : 'Suspend agent'}
                          >
                            {status === 'suspended' ? (
                              <PlayCircle className="w-4 h-4" />
                            ) : (
                              <PauseCircle className="w-4 h-4" />
                            )}
                          </button>
                          <button
                            onClick={() => setDeleteTarget(agent)}
                            className="p-1.5 rounded-lg hover:bg-[#F06478]/15 text-[#C6384D]"
                            title="Disconnect agent"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Register Agent Modal */}
      <Modal
        open={registerOpen}
        onClose={() => setRegisterOpen(false)}
        title="Register Autonomous Agent"
        subtitle="Declare permitted tool scopes and optionally issue an HMAC-SHA256 identity token"
      >
        <form onSubmit={handleRegister} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-semibold text-[#171638] block mb-1">Agent ID</label>
              <input
                type="text"
                required
                value={newAgentId}
                onChange={(e) => setNewAgentId(e.target.value)}
                placeholder="coding-agent-02"
                className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-[#171638] block mb-1">Archetype</label>
              <select
                value={newType}
                onChange={(e) => setNewType(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm bg-white"
              >
                <option value="Coding">Coding</option>
                <option value="Data">Data</option>
                <option value="Support">Support</option>
                <option value="Web">Web Research</option>
                <option value="System">System Ops</option>
              </select>
            </div>
          </div>

          <div>
            <label className="text-xs font-semibold text-[#171638] block mb-1">
              Connected MCP Servers (comma-separated)
            </label>
            <input
              type="text"
              value={newServers}
              onChange={(e) => setNewServers(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm font-mono"
            />
          </div>

          <div>
            <label className="text-xs font-semibold text-[#171638] block mb-1">
              Authorized Tools Scope (comma-separated)
            </label>
            <input
              type="text"
              value={newTools}
              onChange={(e) => setNewTools(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm font-mono"
            />
          </div>

          <div className="flex flex-wrap gap-4 pt-1 text-xs">
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={enforceScope}
                onChange={(e) => setEnforceScope(e.target.checked)}
                className="accent-[#6654E8]"
              />
              Strict Fail-Closed Tool Scope
            </label>
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={issueTokenOnReg}
                onChange={(e) => setIssueTokenOnReg(e.target.checked)}
                className="accent-[#6654E8]"
              />
              Issue HMAC-SHA256 Identity Token
            </label>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => setRegisterOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting ? 'Registering...' : 'Register Agent'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Issued Token Modal */}
      <Modal
        open={Boolean(issuedTokenInfo)}
        onClose={() => setIssuedTokenInfo(null)}
        title="Agent HMAC-SHA256 Identity Token"
        subtitle={`Agent: ${issuedTokenInfo?.agentId || ''}`}
      >
        {issuedTokenInfo && (
          <div className="space-y-4">
            <p className="text-xs text-[#666581]">
              Pass this signed token in the <code className="font-mono">Authorization: Bearer</code>{' '}
              or <code className="font-mono">X-Cerberus-Signature</code> header on MCP requests.
            </p>
            <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] font-mono text-xs break-all text-[#171638]">
              {issuedTokenInfo.token}
            </div>
            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                onClick={async () => {
                  await navigator.clipboard.writeText(issuedTokenInfo.token);
                  setCopiedToken(true);
                  setTimeout(() => setCopiedToken(false), 1800);
                }}
              >
                {copiedToken ? <Check className="w-4 h-4 text-[#22B982]" /> : <Copy className="w-4 h-4" />}
                {copiedToken ? 'Copied' : 'Copy Token'}
              </Button>
              <Button onClick={() => setIssuedTokenInfo(null)}>Done</Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Agent Detail Inspector Drawer */}
      <Drawer
        open={Boolean(selectedAgent)}
        onClose={() => setSelectedAgent(null)}
        title={selectedAgent?.agent_id || ''}
        subtitle={`${selectedAgent?.agent_type || 'Autonomous'} Agent · ${
          selectedAgent?.trust_level === 'verified' ? 'HMAC Verified' : 'Unverified'
        }`}
      >
        {selectedAgent && (
          <div className="space-y-6 text-xs">
            <div className="grid grid-cols-2 gap-3 bg-[#FAF8FF] border border-[#E3DDF8] rounded-2xl p-4">
              <div>
                <span className="text-[#666581] block">Status</span>
                <Badge tone={decisionTone(selectedAgent.status || 'active')} className="mt-1 capitalize">
                  {selectedAgent.status || 'active'}
                </Badge>
              </div>
              <div>
                <span className="text-[#666581] block">Current Risk Score</span>
                <strong className="text-base font-mono text-[#171638]">
                  {(selectedAgent.current_risk_score || 0).toFixed(2)}
                </strong>
              </div>
              <div>
                <span className="text-[#666581] block">Baseline Snapshot</span>
                <strong className="font-mono text-[#6654E8]">
                  {selectedAgent.active_snapshot || 'Initial / Warming'}
                </strong>
              </div>
              <div>
                <span className="text-[#666581] block">Total Events</span>
                <strong className="font-mono text-[#171638]">{selectedAgent.total_events}</strong>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-bold text-[#171638] flex items-center gap-1.5">
                <Server className="w-4 h-4 text-[#6654E8]" /> Connected MCP Servers
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {(selectedAgent.mcp_servers || ['upstream-server']).map((srv) => (
                  <Badge key={srv} tone="neutral">
                    {srv}
                  </Badge>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-bold text-[#171638]">
                Authorized / Known Tools ({selectedAgent.authorized_tools?.length || selectedAgent.known_tools.length})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {Array.from(
                  new Set([...(selectedAgent.authorized_tools || []), ...selectedAgent.known_tools])
                ).map((tool) => (
                  <span
                    key={tool}
                    className="px-2.5 py-1 rounded-lg bg-[#EAE6FF] text-[#5240D6] font-mono font-medium"
                  >
                    {tool}
                  </span>
                ))}
              </div>
            </div>

            {agentBaseline && agentBaseline.snapshots.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-bold text-[#171638]">Baseline Snapshots</h4>
                <div className="space-y-2">
                  {agentBaseline.snapshots.map((snap) => (
                    <div
                      key={snap.snapshot_id}
                      className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between font-mono"
                    >
                      <span>{snap.snapshot_id}</span>
                      <span className="text-[#666581]">{snap.calls_in_snapshot} calls</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex flex-wrap gap-2 pt-3 border-t border-[#E3DDF8]">
              <Button
                size="sm"
                onClick={async () => {
                  try {
                    const res = await promoteBaseline(selectedAgent.agent_id);
                    addToast({
                      title: 'Online Refit Completed',
                      description: `Active snapshot: ${res.active_snapshot_id || 'updated'}`,
                      variant: 'success',
                    });
                    await loadAgents();
                  } catch {
                    addToast({ title: 'Refit requires active backend', variant: 'warning' });
                  }
                }}
              >
                <Zap className="w-3.5 h-3.5" />
                Promote Baseline Snapshot
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleToggleSuspend(selectedAgent)}
              >
                {selectedAgent.status === 'suspended' ? 'Reactivate Agent' : 'Suspend Agent'}
              </Button>
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Disconnect Agent?"
        description={`Are you sure you want to remove '${deleteTarget?.agent_id}' from the active registry?`}
        confirmLabel="Disconnect Agent"
      />
    </div>
  );
};

