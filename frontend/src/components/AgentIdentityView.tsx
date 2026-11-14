import React, { useState, useEffect, useCallback } from 'react';
import { 
  Key, 
  Copy, 
  Check, 
  ShieldAlert, 
  Lock, 
  Radio, 
  AlertTriangle, 
  Clock, 
  RefreshCw, 
  Fingerprint,
  UserCheck,
  Ban
} from 'lucide-react';
import { SessionSummary, IssuedToken } from '../types';
import { fetchSessions, issueToken, quarantineSession } from '../api';

export const AgentIdentityView: React.FC = () => {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  
  // Issue token form state
  const [newAgentId, setNewAgentId] = useState<string>('agent-worker-1');
  const [ttlSeconds, setTtlSeconds] = useState<number>(3600);
  const [issuedToken, setIssuedToken] = useState<IssuedToken | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [issuing, setIssuing] = useState<boolean>(false);

  // Quarantine action state
  const [quarantiningId, setQuarantiningId] = useState<string | null>(null);

  const loadSessions = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetchSessions();
      setSessions(res);
    } catch (err) {
      console.error('Failed to load sessions:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const handleIssueToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAgentId) return;
    try {
      setIssuing(true);
      const token = await issueToken(newAgentId, ttlSeconds);
      setIssuedToken(token);
    } catch (err) {
      console.error('Failed to issue token:', err);
    } finally {
      setIssuing(false);
    }
  };

  const handleCopy = () => {
    if (!issuedToken) return;
    navigator.clipboard.writeText(issuedToken.token);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleQuarantine = async (sessionId: string) => {
    try {
      setQuarantiningId(sessionId);
      await quarantineSession(sessionId);
      await loadSessions();
    } catch (err) {
      console.error('Failed to quarantine session:', err);
    } finally {
      setQuarantiningId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-soc-panel to-slate-900 border border-soc-border glass-panel">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center glow-purple">
            <Key className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold font-mono text-white">Agent Identity &amp; Session Containment (ASI10)</h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Issue cryptographic HMAC authentication tokens, manage agent credentials, and execute instant blast-radius freeze.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Issue HMAC Token */}
        <div className="p-6 rounded-xl bg-soc-panel border border-soc-border glass-panel space-y-4">
          <div className="flex items-center space-x-2 border-b border-soc-border pb-3">
            <UserCheck className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold font-mono text-white">Issue HMAC Agent Token</h3>
          </div>

          <form onSubmit={handleIssueToken} className="space-y-4 font-mono text-xs">
            <div>
              <label className="text-slate-400 block mb-1">Target Agent Identifier</label>
              <input
                type="text"
                value={newAgentId}
                onChange={(e) => setNewAgentId(e.target.value)}
                placeholder="e.g. data-analyzer-bot"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">TTL Expiration (Seconds)</label>
              <select
                value={ttlSeconds}
                onChange={(e) => setTtlSeconds(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
              >
                <option value={1800}>30 Minutes (1800s)</option>
                <option value={3600}>1 Hour (3600s)</option>
                <option value={14400}>4 Hours (14400s)</option>
                <option value={86400}>24 Hours (86400s)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={issuing}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold transition-all shadow-md flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              <Key className="w-4 h-4" />
              <span>{issuing ? 'Generating Token...' : 'Generate HMAC Token'}</span>
            </button>
          </form>

          {/* Display issued token */}
          {issuedToken && (
            <div className="p-4 rounded-xl bg-slate-950 border border-emerald-500/30 space-y-2 font-mono text-xs mt-4">
              <div className="flex items-center justify-between text-emerald-400 font-bold">
                <span className="flex items-center space-x-1">
                  <Check className="w-3.5 h-3.5" />
                  <span>Token Successfully Issued</span>
                </span>
                <span className="text-[10px] text-slate-500">{issuedToken.agent_id}</span>
              </div>

              <div className="p-2.5 bg-slate-900 rounded border border-slate-800 text-cyan-300 break-all select-all text-[11px]">
                {issuedToken.token}
              </div>

              <div className="flex justify-between items-center pt-1 text-[11px] text-slate-400">
                <span>Expires in {issuedToken.ttl_seconds}s</span>
                <button
                  onClick={handleCopy}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center space-x-1"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right 2 Columns: Active Session Controls & ASI10 Quarantine */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-soc-panel border border-soc-border glass-panel space-y-4">
          <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 border-b border-soc-border pb-3">
            <div>
              <h3 className="text-base font-bold font-mono text-white flex items-center space-x-2">
                <span>Active Agent Sessions &amp; Containment (ASI10)</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Monitor live session state and execute zero-delay quarantine to isolate compromised agents.
              </p>
            </div>

            <button
              onClick={loadSessions}
              disabled={loading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center space-x-1 self-start sm:self-auto"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {sessions.length === 0 ? (
              <div className="p-12 text-center text-slate-500 border border-slate-800 rounded-lg">
                No active sessions tracked in memory. Sessions appear when agents make tool calls.
              </div>
            ) : (
              sessions.map((sess) => {
                const isQuarantined = sess.is_quarantined || sess.latest_decision === 'quarantine';

                return (
                  <div
                    key={sess.session_id}
                    className={`p-4 rounded-xl border transition-all flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                      isQuarantined 
                        ? 'bg-purple-950/20 border-purple-500/40 glow-purple' 
                        : 'bg-slate-950 border-slate-800'
                    }`}
                  >
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-white text-sm truncate max-w-xs">{sess.session_id}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {sess.agent_id}
                        </span>
                        {sess.trust_level === 'verified' ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            HMAC VERIFIED
                          </span>
                        ) : (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                            UNVERIFIED
                          </span>
                        )}
                      </div>

                      <div className="text-slate-400 text-[11px] mt-1 space-x-3">
                        <span>Total Events: <strong className="text-slate-200">{sess.total_events}</strong></span>
                        <span>Latest Risk: <strong className={sess.latest_risk_score >= 0.5 ? 'text-rose-400' : 'text-slate-200'}>
                          {(sess.latest_risk_score * 100).toFixed(0)}%
                        </strong></span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 self-end md:self-center">
                      {isQuarantined ? (
                        <span className="px-3 py-1.5 rounded-lg bg-purple-500/20 text-purple-300 border border-purple-500/50 font-bold flex items-center space-x-1.5">
                          <Ban className="w-4 h-4 text-purple-400" />
                          <span>QUARANTINED (FROZEN)</span>
                        </span>
                      ) : (
                        <button
                          onClick={() => handleQuarantine(sess.session_id)}
                          disabled={quarantiningId === sess.session_id}
                          className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                        >
                          <Ban className="w-3.5 h-3.5" />
                          <span>{quarantiningId === sess.session_id ? 'Freezing...' : 'Quarantine Session'}</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
