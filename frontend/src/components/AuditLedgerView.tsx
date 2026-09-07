import React, { useState, useEffect } from 'react';
import { 
  Lock, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw, 
  Hash, 
  FileCode, 
  Search,
  Database
} from 'lucide-react';
import { AuditRecord, AuditVerifyResult } from '../types';
import { fetchAuditLogs, verifyAuditLedger } from '../api';

export const AuditLedgerView: React.FC = () => {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);
  const [search, setSearch] = useState('');

  const loadLogs = async () => {
    setLoading(true);
    try {
      const data = await fetchAuditLogs(50);
      setLogs(data);
      if (data.length > 0 && !selectedRecord) {
        setSelectedRecord(data[0]);
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const runVerification = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditLedger();
      setVerifyResult(res);
    } catch (err: any) {
      setVerifyResult({
        is_valid: false,
        total_entries: 0,
        error: err.message,
        log_path: 'cerberus_audit.jsonl',
      });
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    loadLogs();
    runVerification();
  }, []);

  const filteredLogs = logs.filter((r) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      r.hash.toLowerCase().includes(q) ||
      r.prev_hash.toLowerCase().includes(q) ||
      (r.event?.tool_name || '').toLowerCase().includes(q) ||
      (r.event?.agent_id || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Top Banner & Verification Status */}
      <div className="bg-gradient-to-r from-slate-900 via-soc-panel to-slate-900 p-6 rounded-2xl border border-soc-border glass-panel flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center glow-cyan">
            <Lock className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-mono text-white">Cryptographic Tamper-Evident Audit Ledger</h2>
            <p className="text-xs text-slate-400 font-mono">
              SHA-256 hash-chained append-only record with Fernet encryption and automated log rotation.
            </p>
          </div>
        </div>

        {/* Verification Check Badge & Trigger */}
        <div className="flex items-center space-x-3">
          {verifyResult && (
            <div className={`px-3 py-1.5 rounded-lg border font-mono text-xs flex items-center space-x-1.5 ${
              verifyResult.is_valid
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                : 'bg-rose-500/15 border-rose-500/40 text-rose-300'
            }`}>
              {verifyResult.is_valid ? (
                <>
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span>INTEGRITY VERIFIED ({verifyResult.total_entries} entries)</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                  <span>TAMPER DETECTED: {verifyResult.error}</span>
                </>
              )}
            </div>
          )}

          <button
            onClick={runVerification}
            disabled={verifying}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold transition-all shadow-md glow-cyan"
          >
            <ShieldCheck className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>{verifying ? 'Verifying...' : 'Verify Chain'}</span>
          </button>
        </div>
      </div>

      {/* Main Ledger Table and Envelope Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Ledger Entries List */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="relative w-full max-w-sm">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search by hash or tool..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 font-mono"
              />
            </div>

            <button
              onClick={loadLogs}
              disabled={loading}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>

          <div className="bg-soc-panel rounded-xl border border-soc-border glass-panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-2.5 font-semibold"># INDEX</th>
                    <th className="px-4 py-2.5 font-semibold">TOOL CALL</th>
                    <th className="px-4 py-2.5 font-semibold">DECISION</th>
                    <th className="px-4 py-2.5 font-semibold">BLOCK HASH (SHA-256)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredLogs.map((r) => {
                    const isSelected = selectedRecord?.index === r.index;
                    return (
                      <tr
                        key={r.index}
                        onClick={() => setSelectedRecord(r)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-cyan-950/40 text-cyan-300'
                            : 'hover:bg-slate-800/50 text-slate-300'
                        }`}
                      >
                        <td className="px-4 py-3 font-bold text-slate-400">#{r.index}</td>
                        <td className="px-4 py-3 font-semibold text-white">
                          {r.event?.tool_name || 'N/A'}
                          <span className="block text-[10px] text-slate-500">{r.event?.agent_id}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            r.event?.decision === 'block' ? 'bg-rose-500/20 text-rose-400' :
                            r.event?.decision === 'quarantine' ? 'bg-purple-500/20 text-purple-400' :
                            r.event?.decision === 'flag' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            {r.event?.decision?.toUpperCase() || 'ALLOW'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[11px] font-mono text-cyan-400">
                          {r.hash.slice(0, 16)}...{r.hash.slice(-8)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Envelope Inspector */}
        <div className="space-y-4">
          <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
            Cryptographic Block Envelope
          </h3>

          {selectedRecord ? (
            <div className="bg-soc-panel p-5 rounded-xl border border-soc-border glass-panel space-y-4 font-mono text-xs">
              <div>
                <span className="text-slate-500 block text-[10px]">ENTRY INDEX</span>
                <span className="text-white font-bold text-sm">#{selectedRecord.index}</span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">PREVIOUS BLOCK HASH</span>
                <span className="text-slate-300 break-all text-[11px] bg-slate-950 p-2 rounded block border border-slate-800">
                  {selectedRecord.prev_hash}
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">CURRENT BLOCK SIGNATURE HASH</span>
                <span className="text-cyan-400 break-all text-[11px] bg-slate-950 p-2 rounded block border border-slate-800 font-semibold">
                  {selectedRecord.hash}
                </span>
              </div>

              <div className="space-y-1 pt-2 border-t border-slate-800">
                <span className="text-slate-500 block text-[10px]">PAYLOAD EVENT JSON</span>
                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-emerald-400 overflow-x-auto max-h-72">
                  {JSON.stringify(selectedRecord.event, null, 2)}
                </pre>
              </div>
            </div>
          ) : (
            <div className="p-8 bg-soc-panel rounded-xl border border-soc-border text-center text-slate-500 font-mono text-xs">
              Select an entry to inspect cryptographic hash envelope.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
