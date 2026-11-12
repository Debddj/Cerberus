import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Lock,
  RefreshCw,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { Badge, decisionTone, formatDecisionLabel } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';
import { StatusBanner } from '../../components/ui/StatusBanner';
import { useToast } from '../../context/ToastContext';
import {
  fetchAuditLogs,
  fetchAuditStatus,
  getAuditExportUrl,
  verifyAuditLedger,
} from '../../services/api';
import type { AuditRecord, AuditStatus, AuditVerifyResult } from '../../types';

function truncateHash(h: string): string {
  if (!h || h.length < 14) return h || '-';
  return `${h.slice(0, 6)}...${h.slice(-4)}`;
}

export const AuditPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [auditStatus, setAuditStatus] = useState<AuditStatus | null>(null);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
  const [source, setSource] = useState<'live' | 'offline-demo'>('live');
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<AuditRecord | null>(null);

  const { addToast } = useToast();

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [logsRes, statusRes] = await Promise.all([fetchAuditLogs(100), fetchAuditStatus()]);
      setLogs(logsRes.data);
      setAuditStatus(statusRes.data);
      setSource(logsRes.source);
      setSelected((prev) => prev || logsRes.data[0] || null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const handleVerifyIntegrity = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditLedger();
      setVerifyResult(res);
      addToast({
        title: res.is_valid
          ? `SHA-256 Chain Verified (${res.total_entries} entries)`
          : 'Tampering Alert: Hash Chain Broken!',
        description: res.error || 'Every audit block cryptographically links to its predecessor.',
        variant: res.is_valid ? 'success' : 'danger',
      });
      await loadAll();
    } catch (err) {
      addToast({
        title: 'Verification unavailable',
        description: err instanceof Error ? err.message : 'Backend unreachable',
        variant: 'warning',
      });
    } finally {
      setVerifying(false);
    }
  };

  const filtered = useMemo(() => {
    if (!search.trim()) return logs;
    const q = search.toLowerCase();
    return logs.filter(
      (r) =>
        r.hash.toLowerCase().includes(q) ||
        r.prev_hash.toLowerCase().includes(q) ||
        (r.event?.tool_name || '').toLowerCase().includes(q) ||
        (r.event?.agent_id || '').toLowerCase().includes(q)
    );
  }, [logs, search]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Audit Ledger (Hash-Chained)
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Append-only SHA-256 hash-chained log ledger with Fernet envelope encryption at rest
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <a
            href={getAuditExportUrl()}
            download="cerberus_audit_export.json"
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-white border border-[#E3DDF8] text-xs font-semibold text-[#171638] hover:bg-[#FAF8FF]"
          >
            <Download className="w-3.5 h-3.5 text-[#6654E8]" />
            Export Log
          </a>
          <Button onClick={handleVerifyIntegrity} disabled={verifying}>
            <ShieldCheck className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
            {verifying ? 'Verifying Chain...' : 'Verify Integrity'}
          </Button>
        </div>
      </div>

      <StatusBanner source={source} onRetry={loadAll} />

      {/* Integrity Status & Encryption Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-4 flex items-center gap-3.5">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
              verifyResult?.is_valid === false
                ? 'bg-[#F06478]/14 text-[#C6384D]'
                : 'bg-[#22B982]/14 text-[#158A5E]'
            }`}
          >
            {verifyResult?.is_valid === false ? (
              <AlertTriangle className="w-5 h-5" />
            ) : (
              <CheckCircle2 className="w-5 h-5" />
            )}
          </div>
          <div className="min-w-0">
            <span className="text-[11px] font-medium text-[#666581] block">Chain Integrity</span>
            <strong className="text-sm text-[#171638] truncate block">
              {verifyResult
                ? verifyResult.is_valid
                  ? `Valid (${verifyResult.total_entries} records)`
                  : `TAMPER ALERT: ${verifyResult.error}`
                : 'Click Verify Integrity to audit'}
            </strong>
          </div>
        </Card>

        <Card className="p-4 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-[#EAE6FF] text-[#6654E8] flex items-center justify-center shrink-0">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <span className="text-[11px] font-medium text-[#666581] block">
              Encrypted Log Status
            </span>
            <strong className="text-sm text-[#171638]">
              {auditStatus?.fernet_active
                ? 'Fernet AES-128-CBC + HMAC Active'
                : auditStatus?.encrypt_logs
                  ? 'Encryption Configured'
                  : 'Plaintext JSONL'}
            </strong>
          </div>
        </Card>

        <Card className="p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-medium text-[#666581] block">Chain Head Hash</span>
            <code className="text-xs font-mono font-bold text-[#6654E8]">
              {truncateHash(auditStatus?.chain_head_hash || '')}
            </code>
          </div>
          <Button variant="ghost" size="sm" onClick={loadAll} disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </Card>
      </div>

      {/* Ledger Table + Block Inspector */}
      {filtered.length === 0 ? (
        <EmptyState
          title="No Audit Ledger Records Yet"
          description="Every intercepted MCP tool call is written to the SHA-256 hash-chained audit ledger automatically."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <Card className="lg:col-span-7 overflow-hidden">
            <div className="p-4 border-b border-[#E3DDF8] flex items-center justify-between gap-3">
              <div className="relative flex-1 max-w-sm">
                <Search className="w-4 h-4 text-[#8C7BFA] absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search by SHA-256 hash, tool, or agent..."
                  className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-xs font-mono focus:outline-none focus:border-[#6654E8]"
                />
              </div>
              <span className="text-xs font-mono text-[#666581]">{filtered.length} blocks</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#FAF8FF] border-b border-[#E3DDF8] text-[#666581]">
                  <tr>
                    <th className="py-3 px-4">#</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Event</th>
                    <th className="py-3 px-4">Decision</th>
                    <th className="py-3 px-4 text-right">SHA-256 Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F3F0FF]">
                  {filtered.map((rec) => {
                    const active = selected?.index === rec.index;
                    const ts = rec.event?.timestamp;
                    const dateStr = ts
                      ? new Date(
                          typeof ts === 'number' ? (ts > 1e12 ? ts : ts * 1000) : Date.parse(ts)
                        ).toLocaleTimeString()
                      : '--:--:--';
                    return (
                      <tr
                        key={rec.index}
                        onClick={() => setSelected(rec)}
                        className={`cursor-pointer transition-colors ${
                          active ? 'bg-[#EAE6FF]/65' : 'hover:bg-[#FAF8FF]'
                        }`}
                      >
                        <td className="py-3 px-4 font-bold text-[#666581]">{rec.index}</td>
                        <td className="py-3 px-4 text-[#666581] whitespace-nowrap">{dateStr}</td>
                        <td className="py-3 px-4 font-bold text-[#171638]">
                          {rec.event?.tool_name || 'N/A'}
                        </td>
                        <td className="py-3 px-4">
                          <Badge tone={decisionTone(rec.event?.decision)}>
                            {formatDecisionLabel(rec.event?.decision)}
                          </Badge>
                        </td>
                        <td className="py-3 px-4 text-right text-[#6654E8] font-semibold">
                          {truncateHash(rec.hash)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>

          <Card className="lg:col-span-5 p-6 space-y-4">
            <h3 className="text-sm font-bold text-[#171638]">
              Cryptographic Envelope Inspector
            </h3>
            {selected ? (
              <div className="space-y-3 text-xs font-mono">
                <div className="flex items-center justify-between p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                  <span className="text-[#666581]">Block Index</span>
                  <strong className="text-[#171638]">#{selected.index}</strong>
                </div>
                <div>
                  <span className="text-[11px] text-[#666581] block mb-1">
                    Previous Block Hash (H[i-1])
                  </span>
                  <div className="p-2.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] break-all text-[11px] text-[#666581]">
                    {selected.prev_hash}
                  </div>
                </div>
                <div>
                  <span className="text-[11px] text-[#666581] block mb-1">
                    Current SHA-256 Block Hash (H[i])
                  </span>
                  <div className="p-2.5 rounded-xl bg-[#EAE6FF]/70 border border-[#DCD5FF] break-all text-[11px] text-[#5240D6] font-semibold">
                    {selected.hash}
                  </div>
                </div>
                <div>
                  <span className="text-[11px] text-[#666581] block mb-1">
                    Canonical Event Payload
                  </span>
                  <pre className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-[11px] overflow-x-auto max-h-64 text-[#171638]">
                    {JSON.stringify(selected.event, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <p className="text-xs text-[#666581]">Select a block to inspect.</p>
            )}
          </Card>
        </div>
      )}
    </div>
  );
};

