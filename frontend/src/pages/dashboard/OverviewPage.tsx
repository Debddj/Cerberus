import React, { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  Clock,
  HeartPulse,
  Lock,
  Send,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
} from 'lucide-react';
import { Badge, decisionTone, formatDecisionLabel } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { Modal } from '../../components/ui/Modal';
import { useTelemetry } from '../../context/TelemetryContext';
import { useToast } from '../../context/ToastContext';
import { sendMcpToolCall } from '../../services/api';

const PIE_COLORS = {
  allow: '#22B982',
  flag: '#F4AD42',
  block: '#F06478',
  quarantine: '#6654E8',
};

function toTimestampMs(ts: number | string): number {
  if (typeof ts === 'number') {
    return ts > 1e12 ? ts : ts * 1000;
  }
  const parsed = Date.parse(ts);
  return Number.isNaN(parsed) ? Date.now() : parsed;
}

export const OverviewPage: React.FC = () => {
  const [timeWindow, setTimeWindow] = useState<'1h' | '24h' | '7d'>('24h');
  const [probeOpen, setProbeOpen] = useState(false);
  const [probeTool, setProbeTool] = useState('read_file');
  const [probeAgent, setProbeAgent] = useState('DevAgent-01');
  const [probeDest, setProbeDest] = useState('');
  const [sendingProbe, setSendingProbe] = useState(false);

  const navigate = useNavigate();
  const { metrics, health, events, refreshAll } = useTelemetry();
  const { addToast } = useToast();

  const stats = useMemo(() => {
    const allow = metrics?.allow_count ?? events.filter((e) => e.decision === 'allow').length;
    const flag = metrics?.flag_count ?? events.filter((e) => e.decision === 'flag').length;
    const block = metrics?.block_count ?? events.filter((e) => e.decision === 'block').length;
    const quarantine =
      metrics?.quarantine_count ?? events.filter((e) => e.decision === 'quarantine').length;
    const total = metrics?.total_tool_calls ?? events.length;
    const allowedPct = total > 0 ? ((allow / total) * 100).toFixed(1) : '100.0';

    return {
      activeAgents: metrics?.active_agents ?? 0,
      totalCalls: total,
      flagged: flag,
      blocked: block,
      quarantinedSessions: metrics?.quarantined_sessions ?? quarantine,
      allow,
      quarantine,
      allowedPct,
    };
  }, [metrics, events]);

  const activitySeries = useMemo(() => {
    const now = Date.now();
    const bucketCount = 8;
    const windowMs =
      timeWindow === '1h' ? 3600_000 : timeWindow === '24h' ? 86400_000 : 7 * 86400_000;
    const stepMs = windowMs / bucketCount;

    const buckets = Array.from({ length: bucketCount }, (_, i) => {
      const t = new Date(now - (bucketCount - 1 - i) * stepMs);
      const label =
        timeWindow === '7d'
          ? t.toLocaleDateString(undefined, { weekday: 'short' })
          : t.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
      return { label, total: 0, alerts: 0 };
    });

    for (const ev of events) {
      const ms = toTimestampMs(ev.timestamp);
      const delta = now - ms;
      if (delta < 0 || delta > windowMs) continue;
      const idx = Math.min(
        bucketCount - 1,
        Math.max(0, bucketCount - 1 - Math.floor(delta / stepMs))
      );
      buckets[idx].total += 1;
      if (ev.decision && ev.decision !== 'allow') {
        buckets[idx].alerts += 1;
      }
    }
    return buckets;
  }, [events, timeWindow]);

  const distributionData = useMemo(
    () =>
      [
        { name: 'Allowed', value: stats.allow, color: PIE_COLORS.allow },
        { name: 'Flagged', value: stats.flagged, color: PIE_COLORS.flag },
        { name: 'Blocked', value: stats.blocked, color: PIE_COLORS.block },
        { name: 'Quarantined', value: stats.quarantine, color: PIE_COLORS.quarantine },
      ].filter((d) => d.value > 0),
    [stats]
  );

  const recentIncidents = useMemo(
    () =>
      events
        .filter((e) => e.decision === 'block' || e.decision === 'quarantine' || e.decision === 'flag')
        .slice(0, 5),
    [events]
  );

  const agentSummaryRows = useMemo(() => {
    const map = new Map<string, { agentId: string; calls: number; maxRisk: number; lastDecision: string }>();
    for (const ev of events) {
      const cur = map.get(ev.agent_id) || {
        agentId: ev.agent_id,
        calls: 0,
        maxRisk: 0,
        lastDecision: ev.decision || 'allow',
      };
      cur.calls += 1;
      cur.maxRisk = Math.max(cur.maxRisk, ev.risk_score || 0);
      map.set(ev.agent_id, cur);
    }
    return Array.from(map.values()).slice(0, 5);
  }, [events]);

  const handleSendProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    setSendingProbe(true);
    try {
      const args: Record<string, unknown> =
        probeTool === 'http_post'
          ? { url: `https://${probeDest || 'api.github.com'}/hook`, data: 'status_ping' }
          : { path: probeDest || 'src/main.py' };
      const res = await sendMcpToolCall({
        agent_id: probeAgent,
        session_id: `soc-probe-${Date.now().toString(36)}`,
        tool_name: probeTool,
        arguments: args,
      });
      const blocked = Boolean((res as { error?: unknown }).error);
      addToast({
        title: blocked ? 'Probe Blocked by CERBERUS' : 'Probe Allowed by CERBERUS',
        description: blocked
          ? 'Firewall intercepted the synthetic call and recorded an audit block.'
          : 'Tool call scored clean and logged to the live SSE stream.',
        variant: blocked ? 'danger' : 'success',
      });
      setProbeOpen(false);
      await refreshAll();
    } catch (err) {
      addToast({
        title: 'Backend Unreachable',
        description: err instanceof Error ? err.message : 'Could not deliver MCP call to proxy.',
        variant: 'warning',
      });
    } finally {
      setSendingProbe(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Security Operations Center
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Real-time runtime behavioral telemetry across active MCP agent sessions
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <select
            value={timeWindow}
            onChange={(e) => setTimeWindow(e.target.value as '1h' | '24h' | '7d')}
            className="px-3.5 py-2 rounded-xl bg-white border border-[#E3DDF8] text-xs font-semibold text-[#171638] focus:outline-none focus:border-[#6654E8]"
            aria-label="Time window"
          >
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>
          <Button size="sm" onClick={() => setProbeOpen(true)}>
            <Send className="w-3.5 h-3.5" />
            Test MCP Call
          </Button>
        </div>
      </div>

      {/* 6 KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        {[
          {
            label: 'Active Agents',
            value: stats.activeAgents,
            icon: Bot,
            bg: 'bg-[#22B982]/12 text-[#158A5E]',
          },
          {
            label: 'Total Tool Calls',
            value: stats.totalCalls.toLocaleString(),
            icon: Activity,
            bg: 'bg-[#6654E8]/12 text-[#6654E8]',
          },
          {
            label: 'Flagged Operations',
            value: stats.flagged,
            icon: AlertTriangle,
            bg: 'bg-[#F4AD42]/16 text-[#B7720C]',
          },
          {
            label: 'Blocked Operations',
            value: stats.blocked,
            icon: ShieldBan,
            bg: 'bg-[#F06478]/14 text-[#C6384D]',
          },
          {
            label: 'Quarantined Sessions',
            value: stats.quarantinedSessions,
            icon: Lock,
            bg: 'bg-[#8C7BFA]/16 text-[#5240D6]',
          },
          {
            label: 'System Health',
            value: health?.status === 'healthy' ? 'Healthy' : 'Degraded',
            icon: HeartPulse,
            bg:
              health?.status === 'healthy'
                ? 'bg-[#22B982]/12 text-[#158A5E]'
                : 'bg-[#F4AD42]/16 text-[#B7720C]',
          },
        ].map((kpi) => {
          const Icon = kpi.icon;
          return (
            <Card key={kpi.label} className="p-4 flex items-center gap-3.5">
              <div className={`w-11 h-11 rounded-2xl flex items-center justify-center shrink-0 ${kpi.bg}`}>
                <Icon className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-xl font-extrabold text-[#171638] truncate font-display">
                  {kpi.value}
                </p>
                <p className="text-[11px] font-medium text-[#666581] truncate">{kpi.label}</p>
              </div>
            </Card>
          );
        })}
      </div>

      {/* Charts Row: Area Chart + Donut Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <Card className="lg:col-span-8 p-6">
          <CardHeader
            title={`Threat Activity (${
              timeWindow === '1h' ? 'Last 1 Hour' : timeWindow === '24h' ? 'Last 24 Hours' : 'Last 7 Days'
            })`}
            subtitle="Total intercepted MCP calls vs flagged/blocked alerts"
          />
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activitySeries}>
                <defs>
                  <linearGradient id="cerberusArea" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6654E8" stopOpacity={0.38} />
                    <stop offset="95%" stopColor="#8C7BFA" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="cerberusAlertArea" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F06478" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#F06478" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#E3DDF8" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#666581' }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#666581' }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFFFF',
                    borderColor: '#E3DDF8',
                    borderRadius: '12px',
                    fontSize: '12px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="total"
                  name="Tool Calls"
                  stroke="#6654E8"
                  strokeWidth={2.5}
                  fill="url(#cerberusArea)"
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  name="Flag / Block"
                  stroke="#F06478"
                  strokeWidth={2}
                  fill="url(#cerberusAlertArea)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="lg:col-span-4 p-6 flex flex-col justify-between">
          <CardHeader title="Decision Distribution" subtitle="Allow / Flag / Block / Quarantine" />
          <div className="relative h-48 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={
                    distributionData.length > 0
                      ? distributionData
                      : [{ name: 'No Calls', value: 1, color: '#DCD5FF' }]
                  }
                  dataKey="value"
                  innerRadius={56}
                  outerRadius={78}
                  paddingAngle={3}
                  stroke="none"
                >
                  {(distributionData.length > 0
                    ? distributionData
                    : [{ name: 'No Calls', value: 1, color: '#DCD5FF' }]
                  ).map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-extrabold text-[#171638] font-display">
                {stats.allowedPct}%
              </span>
              <span className="text-[11px] font-medium text-[#666581]">Allowed</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 text-xs">
            {[
              { label: 'Allowed', val: stats.allow, dot: 'bg-[#22B982]' },
              { label: 'Flagged', val: stats.flagged, dot: 'bg-[#F4AD42]' },
              { label: 'Blocked', val: stats.blocked, dot: 'bg-[#F06478]' },
              { label: 'Quarantined', val: stats.quarantine, dot: 'bg-[#6654E8]' },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-[#FAF8FF]">
                <span className="flex items-center gap-1.5 text-[#666581]">
                  <span className={`w-2 h-2 rounded-full ${item.dot}`} />
                  {item.label}
                </span>
                <strong className="font-mono text-[#171638]">{item.val}</strong>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Bottom Row: Recent Incidents + Recent Tool Calls + Agent Activity & Latency */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <Card className="lg:col-span-5 p-6">
          <CardHeader
            title="Recent Incidents"
            subtitle="High-risk or flagged tool invocations"
            icon={<ShieldAlert className="w-4 h-4" />}
            actions={
              <Link
                to="/dashboard/incidents"
                className="text-xs font-semibold text-[#6654E8] hover:underline inline-flex items-center gap-1"
              >
                Investigate <ArrowRight className="w-3 h-3" />
              </Link>
            }
          />
          {recentIncidents.length === 0 ? (
            <p className="text-xs text-[#666581] py-8 text-center">
              No flagged or blocked incidents observed yet.
            </p>
          ) : (
            <div className="space-y-2.5">
              {recentIncidents.map((ev) => (
                <div
                  key={ev.event_id}
                  onClick={() => navigate('/dashboard/incidents')}
                  className="p-3 rounded-xl bg-[#FAF8FF] hover:bg-[#F3F0FF] border border-[#E3DDF8] cursor-pointer flex items-center justify-between gap-3 transition-colors"
                >
                  <div className="min-w-0">
                    <p className="text-xs font-mono font-bold text-[#171638] truncate">
                      {ev.tool_name}
                    </p>
                    <p className="text-[11px] text-[#666581] truncate">
                      {ev.agent_id} · Risk {(ev.risk_score || 0).toFixed(2)}
                    </p>
                  </div>
                  <Badge tone={decisionTone(ev.decision)}>{formatDecisionLabel(ev.decision)}</Badge>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="lg:col-span-7 p-6 space-y-5">
          <CardHeader
            title="Recent Tool Calls & Runtime Latency"
            subtitle="Live interception log and measured proxy overhead"
            icon={<Clock className="w-4 h-4" />}
            actions={
              <Link
                to="/dashboard/monitoring"
                className="text-xs font-semibold text-[#6654E8] hover:underline inline-flex items-center gap-1"
              >
                Full Stream <ArrowRight className="w-3 h-3" />
              </Link>
            }
          />

          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
              <span className="text-[11px] text-[#666581] block">P50 Latency</span>
              <span className="text-base font-bold font-mono text-[#171638]">
                {metrics?.latency_ms ? `${metrics.latency_ms.p50} ms` : 'Pending'}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
              <span className="text-[11px] text-[#666581] block">P95 Latency</span>
              <span className="text-base font-bold font-mono text-[#6654E8]">
                {metrics?.latency_ms ? `${metrics.latency_ms.p95} ms` : 'Pending'}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
              <span className="text-[11px] text-[#666581] block">Storage Backend</span>
              <span className="text-base font-bold font-mono text-[#171638] uppercase">
                {health?.storage?.backend || 'in_memory'}
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[#666581] border-b border-[#E3DDF8]">
                <tr>
                  <th className="py-2 font-semibold">Agent</th>
                  <th className="py-2 font-semibold">Tool</th>
                  <th className="py-2 font-semibold">Risk</th>
                  <th className="py-2 font-semibold text-right">Decision</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F3F0FF]">
                {events.slice(0, 5).map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-[#FAF8FF]">
                    <td className="py-2.5 font-medium text-[#171638]">{ev.agent_id}</td>
                    <td className="py-2.5 font-mono text-[#6654E8]">{ev.tool_name}</td>
                    <td className="py-2.5 font-mono">{(ev.risk_score || 0).toFixed(2)}</td>
                    <td className="py-2.5 text-right">
                      <Badge tone={decisionTone(ev.decision)}>
                        {formatDecisionLabel(ev.decision)}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {agentSummaryRows.length > 0 && (
            <div className="pt-2 border-t border-[#E3DDF8] flex flex-wrap items-center gap-2 text-xs">
              <span className="font-semibold text-[#666581]">Agent Activity:</span>
              {agentSummaryRows.map((a) => (
                <span
                  key={a.agentId}
                  className="px-2.5 py-1 rounded-full bg-[#F3F0FF] border border-[#E3DDF8] font-mono text-[11px]"
                >
                  {a.agentId}: {a.calls} calls (max {a.maxRisk.toFixed(2)})
                </span>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Send Test MCP Call Modal */}
      <Modal
        open={probeOpen}
        onClose={() => setProbeOpen(false)}
        title="Send Live MCP Probe Call"
        subtitle="Submits a real JSON-RPC tools/call request to POST /mcp"
      >
        <form onSubmit={handleSendProbe} className="space-y-4">
          <div className="space-y-1">
            <label className="text-xs font-semibold text-[#171638] block">Agent ID</label>
            <input
              type="text"
              required
              value={probeAgent}
              onChange={(e) => setProbeAgent(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm font-mono"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-semibold text-[#171638] block">Tool Name</label>
            <select
              value={probeTool}
              onChange={(e) => setProbeTool(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm font-mono bg-white"
            >
              <option value="read_file">read_file</option>
              <option value="query_db">query_db</option>
              <option value="http_post">http_post</option>
              <option value="admin_drop_db">admin_drop_db</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-semibold text-[#171638] block">
              {probeTool === 'http_post' ? 'Destination Domain' : 'File Path / Query Target'}
            </label>
            <input
              type="text"
              value={probeDest}
              onChange={(e) => setProbeDest(e.target.value)}
              placeholder={probeTool === 'http_post' ? 'attacker.evil.com' : 'src/main.py'}
              className="w-full px-3.5 py-2 rounded-xl border border-[#E3DDF8] text-sm font-mono"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => setProbeOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={sendingProbe}>
              <ShieldCheck className="w-4 h-4" />
              {sendingProbe ? 'Sending...' : 'Execute Through Proxy'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

