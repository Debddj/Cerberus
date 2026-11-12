import React, { useCallback, useEffect, useState } from 'react';
import {
  Bar,
  BarChart,
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
  BrainCircuit,
  Cpu,
  GitBranch,
  Layers,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { Badge, decisionTone, formatDecisionLabel } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { StatusBanner } from '../../components/ui/StatusBanner';
import { fetchBehaviorSummary } from '../../services/api';
import type { BehaviorSummary } from '../../types';

type BehaviorTab = 'markov' | 'isolation' | 'transformer' | 'rules' | 'ensemble';

const MODEL_COLORS = ['#6654E8', '#8C7BFA', '#22B982', '#F4AD42'];

export const BehaviorPage: React.FC = () => {
  const [data, setData] = useState<BehaviorSummary | null>(null);
  const [source, setSource] = useState<'live' | 'offline-demo'>('live');
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<BehaviorTab>('markov');

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchBehaviorSummary();
      setData(res.data);
      setSource(res.source);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const weights = data?.ensemble_weights || {
    rule: 0.2,
    markov: 0.2,
    isolation: 0.3,
    transformer: 0.3,
  };

  const weightChartData = [
    { name: 'Rule Floor', pct: Math.round(weights.rule * 100), color: MODEL_COLORS[0] },
    { name: 'Markov Chain', pct: Math.round(weights.markov * 100), color: MODEL_COLORS[1] },
    { name: 'Isolation Forest', pct: Math.round(weights.isolation * 100), color: MODEL_COLORS[2] },
    { name: 'Transformer', pct: Math.round(weights.transformer * 100), color: MODEL_COLORS[3] },
  ];

  const markovTools = (data?.markov.tools || []).slice(0, 6);
  const nodePositions = markovTools.map((_, idx) => {
    const angle = (idx / Math.max(1, markovTools.length)) * Math.PI * 2 - Math.PI / 2;
    return {
      x: 170 + Math.cos(angle) * 110,
      y: 145 + Math.sin(angle) * 95,
    };
  });

  const featureStatsEntries = Object.entries(data?.isolation_forest.scaler_stats || {});

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Behavioural Analysis &amp; ML Intelligence
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Inspect the 4-member cascading detection ensemble, transition matrix, feature stats, and
            live backend scoring configuration
          </p>
        </div>

        <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Models
        </Button>
      </div>

      <StatusBanner source={source} onRetry={loadData} />

      {/* Sub-navigation Tabs matching collage */}
      <div className="flex flex-wrap items-center gap-2 bg-white p-1.5 rounded-2xl border border-[#E3DDF8] w-fit">
        {[
          { id: 'markov', label: 'Markov Chain', icon: GitBranch },
          { id: 'isolation', label: 'Isolation Forest', icon: Activity },
          { id: 'transformer', label: 'Sequence Transformer', icon: Cpu },
          { id: 'rules', label: 'Rule-Based Engine', icon: ShieldAlert },
          { id: 'ensemble', label: 'Ensemble Scoring', icon: Layers },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as BehaviorTab)}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
                isActive
                  ? 'cerberus-gradient-btn text-white'
                  : 'text-[#666581] hover:text-[#171638] hover:bg-[#F3F0FF]'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* 1. MARKOV CHAIN SECTION */}
      {activeTab === 'markov' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <Card className="lg:col-span-5 p-6">
            <CardHeader
              title="Tool Transition Graph"
              subtitle="Directed 1st-order Markov transition topology"
              icon={<GitBranch className="w-4 h-4" />}
            />
            {markovTools.length === 0 ? (
              <p className="text-xs text-[#666581] py-12 text-center">
                No transitions recorded yet. Process tool calls to learn Markov edges.
              </p>
            ) : (
              <div className="bg-[#FAF8FF] border border-[#E3DDF8] rounded-2xl p-3 flex items-center justify-center">
                <svg viewBox="0 0 340 290" className="w-full max-w-[340px] h-auto">
                  <defs>
                    <marker
                      id="markovArrow"
                      markerWidth="8"
                      markerHeight="8"
                      refX="22"
                      refY="3"
                      orient="auto"
                    >
                      <path d="M0,0 L0,6 L7,3 z" fill="#6654E8" />
                    </marker>
                  </defs>
                  {markovTools.map((src, i) =>
                    markovTools.map((dst, j) => {
                      if (i === j) return null;
                      const prob = data?.markov.probabilities[src]?.[dst] || 0;
                      if (prob <= 0) return null;
                      const p1 = nodePositions[i];
                      const p2 = nodePositions[j];
                      return (
                        <line
                          key={`${src}-${dst}`}
                          x1={p1.x}
                          y1={p1.y}
                          x2={p2.x}
                          y2={p2.y}
                          stroke={prob < 0.15 ? '#F06478' : '#6654E8'}
                          strokeWidth={Math.max(1.2, prob * 4)}
                          strokeOpacity={0.75}
                          markerEnd="url(#markovArrow)"
                        />
                      );
                    })
                  )}
                  {markovTools.map((tool, i) => {
                    const pos = nodePositions[i];
                    const shortLabel = tool.length > 10 ? `${tool.slice(0, 9)}…` : tool;
                    return (
                      <g key={tool}>
                        <circle
                          cx={pos.x}
                          cy={pos.y}
                          r={24}
                          fill="#EAE6FF"
                          stroke="#6654E8"
                          strokeWidth={2}
                        />
                        <text
                          x={pos.x}
                          y={pos.y + 3}
                          textAnchor="middle"
                          fontSize="9"
                          fontFamily="JetBrains Mono, monospace"
                          fontWeight="600"
                          fill="#171638"
                        >
                          {shortLabel}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            )}
          </Card>

          <Card className="lg:col-span-7 p-6 space-y-4">
            <CardHeader
              title="Transition Matrix (P)"
              subtitle="Conditional probability P(Next | Previous) with Laplace-smoothed surprise scoring"
            />
            {markovTools.length === 0 ? (
              <p className="text-xs text-[#666581] py-12 text-center">
                Transition probability matrix will populate automatically once tool sequences arrive.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-center font-mono text-xs border-collapse">
                  <thead>
                    <tr className="text-[#666581] border-b border-[#E3DDF8]">
                      <th className="py-2 px-3 text-left">From \ To</th>
                      {markovTools.map((t) => (
                        <th key={t} className="py-2 px-2 truncate max-w-[90px]" title={t}>
                          {t.slice(0, 10)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#F3F0FF]">
                    {markovTools.map((src) => (
                      <tr key={src}>
                        <td className="py-2.5 px-3 text-left font-bold text-[#171638]">{src}</td>
                        {markovTools.map((dst) => {
                          const p = data?.markov.probabilities[src]?.[dst] ?? 0;
                          return (
                            <td key={dst} className="py-2 px-2">
                              <span
                                className="inline-block px-2 py-1 rounded-lg font-semibold"
                                style={{
                                  backgroundColor:
                                    p > 0.4
                                      ? 'rgba(102, 84, 232, 0.22)'
                                      : p > 0.1
                                        ? 'rgba(140, 123, 250, 0.14)'
                                        : 'rgba(243, 240, 255, 0.7)',
                                  color: p > 0.4 ? '#3A29B8' : '#171638',
                                }}
                              >
                                {p.toFixed(2)}
                              </span>
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-xs text-[#666581]">
              <strong className="text-[#171638]">Anomalous Transition Surprise:</strong> Unseen or
              rare transitions (<code className="font-mono">-log2 P(T_i | T_{'{i-1}'})</code>) are
              squashed via logistic sigmoid (<code className="font-mono">midpoint=6.0</code>) so rare
              jumps score &gt;0.70 without distorting linear blending.
            </div>
          </Card>
        </div>
      )}

      {/* 2. ISOLATION FOREST SECTION */}
      {activeTab === 'isolation' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <Card className="lg:col-span-5 p-6 space-y-4">
            <CardHeader
              title="Isolation Forest Telemetry"
              subtitle="Multivariate continuous feature outlier detection"
              icon={<Activity className="w-4 h-4" />}
            />
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                <span className="text-[#666581] block">Model Fit Status</span>
                <Badge
                  tone={data?.isolation_forest.is_fitted ? 'success' : 'warning'}
                  className="mt-1"
                >
                  {data?.isolation_forest.is_fitted ? 'Fitted & Warm' : 'Warming Up'}
                </Badge>
              </div>
              <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                <span className="text-[#666581] block">Warmup Threshold</span>
                <strong className="text-base font-mono text-[#171638]">
                  {data?.isolation_forest.warm_threshold_calls ?? 100} calls
                </strong>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#666581]">
                Running Continuous Feature Distributions (Welford Z-Scaler)
              </h4>
              {featureStatsEntries.length === 0 ? (
                <p className="text-xs text-[#666581]">No feature vectors scaled yet.</p>
              ) : (
                <div className="space-y-2">
                  {featureStatsEntries.map(([key, stat]) => {
                    const std =
                      stat.count > 1 ? Math.sqrt(stat.M2 / (stat.count - 1)).toFixed(2) : '1.00';
                    return (
                      <div
                        key={key}
                        className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between text-xs font-mono"
                      >
                        <span className="font-bold text-[#171638]">{key}</span>
                        <span className="text-[#666581]">
                          μ={stat.mean.toFixed(2)} · σ={std} · n={stat.count}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </Card>

          <Card className="lg:col-span-7 p-6 space-y-4">
            <CardHeader
              title="Recent Isolation Forest Anomaly Scores"
              subtitle="Per-event continuous outlier scores across entropy, payload bytes, inter-call delta & duration"
            />
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={(data?.recent_breakdowns || []).slice(0, 10)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E3DDF8" vertical={false} />
                  <XAxis dataKey="tool_name" tick={{ fontSize: 11, fill: '#666581' }} />
                  <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: '#666581' }} />
                  <Tooltip />
                  <Bar
                    dataKey="isolation_score"
                    name="Isolation Forest Score"
                    fill="#6654E8"
                    radius={[6, 6, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      )}

      {/* 3. SEQUENCE TRANSFORMER SECTION */}
      {activeTab === 'transformer' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <Card className="lg:col-span-5 p-6 space-y-4">
            <CardHeader
              title="Sequence Transformer Autoencoder"
              subtitle="Sliding window (W=5) tool sequence reconstruction loss"
              icon={<Cpu className="w-4 h-4" />}
            />
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                <span className="text-[#666581] block">Status</span>
                <Badge tone={data?.transformer.is_fitted ? 'success' : 'warning'} className="mt-1">
                  {data?.transformer.is_fitted ? 'Trained' : 'Cold / Awaiting Warmup'}
                </Badge>
              </div>
              <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                <span className="text-[#666581] block">Baseline Recon Loss</span>
                <strong className="text-base text-[#171638]">
                  {data?.transformer.baseline_reconstruction_error ?? 0.5}
                </strong>
              </div>
              <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                <span className="text-[#666581] block">Embedding / Hidden</span>
                <strong className="text-[#6654E8]">
                  {data?.transformer.embedding_dim ?? 16}D → {data?.transformer.hidden_dim ?? 32}D
                </strong>
              </div>
              <div className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                <span className="text-[#666581] block">Trained Sessions</span>
                <strong className="text-[#171638]">{data?.transformer.sequence_count ?? 0}</strong>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-bold text-[#666581] uppercase tracking-wider block">
                Learned Sequence Vocabulary ({Object.keys(data?.transformer.vocab || {}).length})
              </span>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(data?.transformer.vocab || {}).map(([tool, idx]) => (
                  <span
                    key={tool}
                    className="px-2.5 py-1 rounded-lg bg-[#EAE6FF] text-[#5240D6] font-mono text-xs"
                  >
                    #{idx}: {tool}
                  </span>
                ))}
              </div>
            </div>
          </Card>

          <Card className="lg:col-span-7 p-6 space-y-4">
            <CardHeader
              title="Sequence Deviation Scores"
              subtitle="Tier 3 neural reconstruction deviation across recent evaluated tool chains"
            />
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={(data?.recent_breakdowns || []).slice(0, 10)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E3DDF8" vertical={false} />
                  <XAxis dataKey="tool_name" tick={{ fontSize: 11, fill: '#666581' }} />
                  <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: '#666581' }} />
                  <Tooltip />
                  <Bar
                    dataKey="transformer_score"
                    name="Transformer Deviation"
                    fill="#8C7BFA"
                    radius={[6, 6, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      )}

      {/* 4. RULE-BASED ENGINE SECTION */}
      {activeTab === 'rules' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <Card className="lg:col-span-7 p-6 space-y-4">
            <CardHeader
              title="Deterministic Pre-Baseline Security Rules"
              subtitle="Zero-day Call #1 floor protecting sessions before statistical baselines warm"
              icon={<ShieldAlert className="w-4 h-4" />}
            />
            <div className="space-y-3">
              {(data?.rule_engine.rules || []).map((rule) => (
                <div
                  key={rule.id}
                  className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-start justify-between gap-4"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-[#6654E8]">{rule.id}</span>
                      <span className="text-sm font-bold text-[#171638]">{rule.name}</span>
                    </div>
                    <p className="text-xs text-[#666581] mt-1">{rule.description}</p>
                  </div>
                  <Badge tone="danger">Floor {rule.floor.toFixed(2)}</Badge>
                </div>
              ))}
            </div>
          </Card>

          <Card className="lg:col-span-5 p-6 space-y-4">
            <CardHeader title="Recent Rule Violations" subtitle="Live triggered heuristic alerts" />
            {(data?.rule_engine.recent_triggers || []).length === 0 ? (
              <p className="text-xs text-[#666581] py-10 text-center">
                No heuristic rule violations triggered yet.
              </p>
            ) : (
              <div className="space-y-2.5">
                {data!.rule_engine.recent_triggers.map((trig) => (
                  <div
                    key={trig.event_id}
                    className="p-3.5 rounded-xl bg-[#FFF5F7] border border-[#F06478]/30 space-y-1 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-[#171638]">{trig.tool_name}</span>
                      <Badge tone="danger">Rule {trig.rule_score.toFixed(2)}</Badge>
                    </div>
                    <p className="text-[11px] text-[#666581]">Agent: {trig.agent_id}</p>
                    <p className="text-[11px] text-[#9B2335] flex items-start gap-1.5 pt-1">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      {trig.factors[0]}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}

      {/* 5. ENSEMBLE SCORING SECTION */}
      {activeTab === 'ensemble' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <Card className="lg:col-span-5 p-6 space-y-4">
            <CardHeader
              title="Backend Ensemble Configuration"
              subtitle="Live weights supplied by CerberusProxyEngine.ensemble_scorer"
              icon={<BrainCircuit className="w-4 h-4" />}
            />

            <div className="h-52 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={weightChartData}
                    dataKey="pct"
                    nameKey="name"
                    innerRadius={50}
                    outerRadius={78}
                    paddingAngle={4}
                  >
                    {weightChartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(val: number) => `${val}%`} />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="grid grid-cols-2 gap-2.5 text-xs">
              {weightChartData.map((w) => (
                <div
                  key={w.name}
                  className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center justify-between"
                >
                  <span className="flex items-center gap-2 font-semibold text-[#171638]">
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: w.color }}
                    />
                    {w.name}
                  </span>
                  <strong className="font-mono text-[#6654E8]">{w.pct}%</strong>
                </div>
              ))}
            </div>

            <div className="p-3.5 rounded-xl bg-[#EAE6FF]/60 border border-[#DCD5FF] text-xs space-y-1">
              <p className="font-bold text-[#171638]">Active Policy Thresholds</p>
              <p className="font-mono text-[#666581]">
                Flag ≥ {data?.thresholds.flag ?? 0.4} · Block ≥ {data?.thresholds.block ?? 0.7} ·
                Quarantine ≥ {data?.thresholds.quarantine ?? 0.9}
              </p>
            </div>
          </Card>

          <Card className="lg:col-span-7 p-6 space-y-4">
            <CardHeader
              title="Recent Composite Risk Breakdowns"
              subtitle="Per-model scores and cascading tier exit telemetry"
            />
            {(data?.recent_breakdowns || []).length === 0 ? (
              <p className="text-xs text-[#666581] py-12 text-center">
                No per-call score breakdowns recorded in this session yet.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#FAF8FF] text-[#666581] border-b border-[#E3DDF8]">
                    <tr>
                      <th className="py-2.5 px-3">Tool</th>
                      <th className="py-2.5 px-2">Rule</th>
                      <th className="py-2.5 px-2">Markov</th>
                      <th className="py-2.5 px-2">IF</th>
                      <th className="py-2.5 px-2">Trans</th>
                      <th className="py-2.5 px-2">Composite</th>
                      <th className="py-2.5 px-3 text-right">Decision</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#F3F0FF]">
                    {data!.recent_breakdowns.slice(0, 10).map((b) => (
                      <tr key={b.event_id} className="hover:bg-[#FAF8FF]">
                        <td className="py-2.5 px-3 font-bold text-[#171638]">{b.tool_name}</td>
                        <td className="py-2.5 px-2">{b.rule_score.toFixed(2)}</td>
                        <td className="py-2.5 px-2">{b.markov_score.toFixed(2)}</td>
                        <td className="py-2.5 px-2">{b.isolation_score.toFixed(2)}</td>
                        <td className="py-2.5 px-2">{b.transformer_score.toFixed(2)}</td>
                        <td className="py-2.5 px-2 font-bold text-[#6654E8]">
                          {b.composite_score.toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <Badge tone={decisionTone(b.decision)}>
                            {formatDecisionLabel(b.decision)}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
};

