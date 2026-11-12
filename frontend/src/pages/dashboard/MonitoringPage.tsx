import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Code,
  ExternalLink,
  Fingerprint,
  Radio,
  Search,
} from 'lucide-react';
import { Badge, decisionTone, formatDecisionLabel } from '../../components/ui/Badge';
import { Card } from '../../components/ui/Card';
import { Drawer } from '../../components/ui/Drawer';
import { EmptyState } from '../../components/ui/EmptyState';
import { useTelemetry } from '../../context/TelemetryContext';
import type { ToolCallEvent } from '../../types';

function formatTs(ts: number | string): string {
  const ms = typeof ts === 'number' ? (ts > 1e12 ? ts : ts * 1000) : Date.parse(ts);
  if (Number.isNaN(ms)) return '--:--:--';
  return new Date(ms).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export const MonitoringPage: React.FC = () => {
  const { events, isStreaming, connectionSource } = useTelemetry();
  const [search, setSearch] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [serverFilter, setServerFilter] = useState<string>('ALL');
  const [selectedEvent, setSelectedEvent] = useState<ToolCallEvent | null>(null);

  const servers = useMemo(() => {
    const set = new Set(events.map((e) => e.tool_server).filter(Boolean));
    return ['ALL', ...Array.from(set)];
  }, [events]);

  const filtered = useMemo(() => {
    return events.filter((ev) => {
      if (decisionFilter !== 'ALL' && (ev.decision || '').toUpperCase() !== decisionFilter) {
        return false;
      }
      if (serverFilter !== 'ALL' && ev.tool_server !== serverFilter) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          ev.tool_name.toLowerCase().includes(q) ||
          ev.agent_id.toLowerCase().includes(q) ||
          ev.session_id.toLowerCase().includes(q) ||
          (ev.destination_domain || '').toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [events, search, decisionFilter, serverFilter]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Live Tool Call Stream
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Real-time SSE interception feed across HTTP JSON-RPC and Stdio MCP proxies
          </p>
        </div>

        <Badge tone={isStreaming ? 'success' : connectionSource === 'live' ? 'primary' : 'warning'} dot>
          <Radio className={`w-3.5 h-3.5 ${isStreaming ? 'animate-pulse' : ''}`} />
          {isStreaming ? 'Live SSE Stream' : connectionSource === 'live' ? 'Polling API' : 'Demo Snapshot'}
        </Badge>
      </div>

      {/* Filters */}
      <Card className="p-4 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-[#8C7BFA] absolute left-3.5 top-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by tool, agent, session, or destination..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-sm focus:outline-none focus:border-[#6654E8]"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {(['ALL', 'ALLOW', 'FLAG', 'BLOCK', 'QUARANTINE'] as const).map((dec) => (
            <button
              key={dec}
              onClick={() => setDecisionFilter(dec)}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
                decisionFilter === dec
                  ? 'cerberus-gradient-btn text-white'
                  : 'bg-[#F3F0FF] text-[#666581] hover:text-[#171638]'
              }`}
            >
              {dec}
            </button>
          ))}

          <select
            value={serverFilter}
            onChange={(e) => setServerFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-xs font-semibold text-[#171638]"
            aria-label="Filter by MCP server"
          >
            {servers.map((s) => (
              <option key={s} value={s}>
                {s === 'ALL' ? 'All MCP Servers' : s}
              </option>
            ))}
          </select>
        </div>
      </Card>

      {/* Stream Table */}
      {filtered.length === 0 ? (
        <EmptyState
          title="No Intercepted Tool Calls"
          description="Send MCP requests through CERBERUS or trigger a test scenario in Testing & Simulation to stream live events here."
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#FAF8FF] border-b border-[#E3DDF8] text-[#666581]">
                <tr>
                  <th className="px-4 py-3.5 font-semibold">Timestamp</th>
                  <th className="px-4 py-3.5 font-semibold">Agent ID</th>
                  <th className="px-4 py-3.5 font-semibold">MCP Server</th>
                  <th className="px-4 py-3.5 font-semibold">Tool Name</th>
                  <th className="px-4 py-3.5 font-semibold">Operation / Dest</th>
                  <th className="px-4 py-3.5 font-semibold">Risk Score</th>
                  <th className="px-4 py-3.5 font-semibold">Decision</th>
                  <th className="px-4 py-3.5 font-semibold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F3F0FF]">
                {filtered.map((ev) => {
                  const isBlocked = ev.decision === 'block' || ev.decision === 'quarantine';
                  return (
                    <tr
                      key={ev.event_id}
                      onClick={() => setSelectedEvent(ev)}
                      className="hover:bg-[#FAF8FF] cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-[#666581] whitespace-nowrap">
                        {formatTs(ev.timestamp)}
                      </td>
                      <td className="px-4 py-3 font-semibold text-[#171638]">{ev.agent_id}</td>
                      <td className="px-4 py-3 font-mono text-[#666581]">{ev.tool_server}</td>
                      <td className="px-4 py-3 font-mono font-bold text-[#6654E8]">
                        {ev.tool_name}
                      </td>
                      <td className="px-4 py-3 font-mono text-[#666581] max-w-[180px] truncate">
                        {ev.destination_domain ? (
                          <span className="inline-flex items-center gap-1 text-[#C6384D]">
                            <ExternalLink className="w-3 h-3" />
                            {ev.destination_domain}
                          </span>
                        ) : (
                          `Seq #${ev.sequence_position}`
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono font-bold">
                        {(ev.risk_score || 0).toFixed(2)}
                      </td>
                      <td className="px-4 py-3">
                        <Badge tone={decisionTone(ev.decision)}>
                          {formatDecisionLabel(ev.decision)}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-[11px]">
                        <span className={isBlocked ? 'text-[#C6384D]' : 'text-[#148A5E]'}>
                          {isBlocked ? 'Intercepted' : 'Forwarded'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Event Details Drawer */}
      <Drawer
        open={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        title={selectedEvent?.tool_name || ''}
        subtitle={`Event ${selectedEvent?.event_id || ''} · Session ${selectedEvent?.session_id || ''}`}
      >
        {selectedEvent && (
          <div className="space-y-6 text-xs">
            <div className="grid grid-cols-2 gap-3 bg-[#FAF8FF] border border-[#E3DDF8] rounded-2xl p-4 font-mono">
              <div>
                <span className="text-[#666581] block">AGENT ID</span>
                <strong className="text-[#171638]">{selectedEvent.agent_id}</strong>
              </div>
              <div>
                <span className="text-[#666581] block">DECISION</span>
                <Badge tone={decisionTone(selectedEvent.decision)} className="mt-1">
                  {formatDecisionLabel(selectedEvent.decision)}
                </Badge>
              </div>
              <div>
                <span className="text-[#666581] block">MCP SERVER</span>
                <strong className="text-[#171638]">{selectedEvent.tool_server}</strong>
              </div>
              <div>
                <span className="text-[#666581] block">DESTINATION</span>
                <strong className="text-[#6654E8]">
                  {selectedEvent.destination_domain || 'Internal (None)'}
                </strong>
              </div>
              <div>
                <span className="text-[#666581] block">RISK SCORE</span>
                <strong className="text-sm text-[#171638]">
                  {((selectedEvent.risk_score || 0) * 100).toFixed(1)}%
                </strong>
              </div>
              <div>
                <span className="text-[#666581] block">ENTROPY / BYTES</span>
                <strong className="text-[#171638]">
                  {(selectedEvent.parameter_entropy || 0).toFixed(2)} bits ·{' '}
                  {selectedEvent.parameter_size_bytes || 0} B
                </strong>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-bold text-[#171638] uppercase tracking-wider">
                Attributed Risk Factors ({selectedEvent.risk_factors.length})
              </h4>
              {selectedEvent.risk_factors.length === 0 ? (
                <div className="p-3 rounded-xl bg-[#22B982]/10 border border-[#22B982]/30 text-[#148A5E]">
                  No behavioral anomalies or policy violations detected.
                </div>
              ) : (
                <div className="space-y-2">
                  {selectedEvent.risk_factors.map((rf, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-xl bg-[#F06478]/10 border border-[#F06478]/25 text-[#9B2335] flex items-start gap-2"
                    >
                      <AlertTriangle className="w-4 h-4 text-[#F06478] shrink-0 mt-0.5" />
                      <span>{rf}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {selectedEvent.redacted_fields && selectedEvent.redacted_fields.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-bold text-[#B7720C] uppercase tracking-wider flex items-center gap-1.5">
                  <Fingerprint className="w-4 h-4" />
                  Redacted Sensitive Fields
                </h4>
                <div className="p-3 rounded-xl bg-[#F4AD42]/12 border border-[#F4AD42]/30 font-mono text-[#8C5506]">
                  {selectedEvent.redacted_fields.join(', ')}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <h4 className="font-bold text-[#171638] uppercase tracking-wider flex items-center gap-1.5">
                <Code className="w-4 h-4 text-[#6654E8]" />
                Sanitized Parameter Payload
              </h4>
              <pre className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] font-mono text-xs text-[#171638] overflow-x-auto max-h-64">
                {JSON.stringify(selectedEvent.parameters, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};

