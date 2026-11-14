import React, { useState, useEffect, useCallback } from 'react';
import { 
  CheckSquare, 
  CheckCircle, 
  XCircle, 
  Clock, 
  AlertTriangle, 
  Search, 
  Code,
  RefreshCw
} from 'lucide-react';
import { ChallengeItem } from '../types';
import { fetchChallenges, resolveChallenge } from '../api';

export const ChallengeInboxView: React.FC = () => {
  const [challenges, setChallenges] = useState<ChallengeItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [filterTab, setFilterTab] = useState<'pending' | 'resolved'>('pending');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [operatorComment, setOperatorComment] = useState<string>('');
  const [selectedChallenge, setSelectedChallenge] = useState<ChallengeItem | null>(null);

  const loadChallenges = useCallback(async () => {
    try {
      setLoading(true);
      const data = await fetchChallenges();
      setChallenges(data);
    } catch (err) {
      console.error('Failed to load challenges:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadChallenges();
    const timer = setInterval(loadChallenges, 8000);
    return () => clearInterval(timer);
  }, [loadChallenges]);

  const handleAction = async (challengeId: string, action: 'approve' | 'reject') => {
    try {
      setResolvingId(challengeId);
      await resolveChallenge(challengeId, action, operatorComment || `Manual operator ${action}`);
      setOperatorComment('');
      setSelectedChallenge(null);
      await loadChallenges();
    } catch (err) {
      console.error(`Failed to ${action} challenge:`, err);
    } finally {
      setResolvingId(null);
    }
  };

  const filteredChallenges = challenges.filter((c) => {
    const isPending = c.status === 'pending';
    if (filterTab === 'pending' && !isPending) return false;
    if (filterTab === 'resolved' && isPending) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        c.tool_name.toLowerCase().includes(q) ||
        c.agent_id.toLowerCase().includes(q) ||
        c.challenge_id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getRemainingSeconds = (expiresAt: number) => {
    const now = Date.now() / 1000;
    const diff = Math.max(0, Math.floor(expiresAt - now));
    return diff;
  };

  const pendingCount = challenges.filter(c => c.status === 'pending').length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-xl bg-soc-panel border border-soc-border glass-panel flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <CheckSquare className="w-6 h-6 text-amber-400" />
            <h2 className="text-xl font-bold font-mono text-white">HUMAN-IN-THE-LOOP APPROVAL INBOX</h2>
            <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
              {pendingCount} PENDING
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Review high-risk tool operations flagged with CHALLENGE before autonomous execution proceeds.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={loadChallenges}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center space-x-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-soc-panel p-4 rounded-xl border border-soc-border">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setFilterTab('pending')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-colors ${
              filterTab === 'pending'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Pending Actions ({pendingCount})
          </button>
          <button
            onClick={() => setFilterTab('resolved')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-colors ${
              filterTab === 'resolved'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Resolved History ({challenges.length - pendingCount})
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search challenges..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Challenge Cards List */}
      <div className="space-y-3">
        {filteredChallenges.length === 0 ? (
          <div className="text-center py-16 bg-soc-panel/50 rounded-xl border border-soc-border">
            <CheckCircle className="w-10 h-10 text-emerald-500/50 mx-auto mb-3" />
            <p className="text-slate-300 text-sm font-mono">No {filterTab} challenges</p>
            <p className="text-slate-500 text-xs mt-1">Autonomous workflows operating within policy thresholds.</p>
          </div>
        ) : (
          filteredChallenges.map((item) => {
            const timeLeft = getRemainingSeconds(item.expires_at);
            const isPending = item.status === 'pending';

            return (
              <div 
                key={item.challenge_id}
                className="p-5 rounded-xl bg-soc-panel border border-soc-border hover:border-slate-600 transition-all space-y-4"
              >
                <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                  <div className="flex items-center space-x-3">
                    <span className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
                      <CheckSquare className="w-4 h-4" />
                    </span>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-base font-bold font-mono text-white">{item.tool_name}</span>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                          {item.tool_server}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 font-mono font-bold">
                          Risk: {(item.risk_score * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 font-mono mt-0.5">
                        Agent: <span className="text-slate-200">{item.agent_id}</span> • Session: <span className="text-slate-200">{item.session_id.slice(0, 16)}...</span>
                      </div>
                    </div>
                  </div>

                  {/* Status & Timer */}
                  <div className="flex items-center space-x-3">
                    {isPending ? (
                      <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-amber-950/40 border border-amber-600/50 text-amber-300 text-xs font-mono font-semibold">
                        <Clock className="w-3.5 h-3.5 animate-spin" />
                        <span>Expires in {timeLeft}s</span>
                      </div>
                    ) : (
                      <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${
                        item.status === 'approved' 
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}>
                        {item.status}
                      </span>
                    )}
                  </div>
                </div>

                {/* Risk Factors */}
                <div className="space-y-1.5 text-xs font-mono">
                  <div className="text-slate-400 uppercase text-[10px] tracking-wider">Trigger Reasons:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {item.risk_factors.map((f, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-rose-950/30 border border-rose-800/40 text-rose-300 flex items-center space-x-1">
                        <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                        <span>{f}</span>
                      </span>
                    ))}
                  </div>
                </div>

                {/* Parameters Preview */}
                {item.parameters && (
                  <div className="space-y-1 text-xs font-mono">
                    <span className="text-slate-400 uppercase text-[10px] tracking-wider flex items-center">
                      <Code className="w-3 h-3 mr-1" /> Call Arguments:
                    </span>
                    <pre className="p-2.5 rounded bg-slate-950 text-cyan-300 overflow-x-auto text-[11px] max-h-24">
                      {JSON.stringify(item.parameters, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Actions for Pending */}
                {isPending && (
                  <div className="pt-2 border-t border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                    <input
                      type="text"
                      placeholder="Optional operator justification..."
                      value={selectedChallenge?.challenge_id === item.challenge_id ? operatorComment : ''}
                      onChange={(e) => {
                        setSelectedChallenge(item);
                        setOperatorComment(e.target.value);
                      }}
                      className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 flex-1"
                    />

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleAction(item.challenge_id, 'approve')}
                        disabled={resolvingId === item.challenge_id}
                        className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                      >
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>Authorize</span>
                      </button>

                      <button
                        onClick={() => handleAction(item.challenge_id, 'reject')}
                        disabled={resolvingId === item.challenge_id}
                        className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                        <span>Deny &amp; Terminate</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Resolution note if already resolved */}
                {!isPending && item.resolution_reason && (
                  <div className="pt-2 border-t border-slate-800 text-[11px] font-mono text-slate-400">
                    Resolution note: <span className="text-slate-300">{item.resolution_reason}</span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
