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
import { Activity, BarChart3, Clock, Info, RefreshCw, ShieldCheck } from 'lucide-react';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { StatusBanner } from '../../components/ui/StatusBanner';
import { fetchAnalytics } from '../../services/api';
import type { AnalyticsPayload } from '../../types';

const DONUT_COLORS = ['#6654E8', '#8C7BFA', '#B9AEF7', '#22B982'];

export const AnalyticsPage: React.FC = () => {
  const [data, setData] = useState<AnalyticsPayload | null>(null);
  const [source, setSource] = useState<'live' | 'offline-demo'>('live');
  const [loading, setLoading] = useState(true);

  const loadAnalytics = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchAnalytics();
      setData(res.data);
      setSource(res.source);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAnalytics();
  }, [loadAnalytics]);

  const evalSummary = data?.evaluation_benchmark?.summary;
  const ensembleAblation = data?.ablation_study?.[0];
  const weights = data?.ensemble_weights || {
    rule: 0.2,
    markov: 0.2,
    isolation: 0.3,
    transformer: 0.3,
  };

  const contributionData = [
    { name: `Rule (${Math.round(weights.rule * 100)}%)`, value: Math.round(weights.rule * 100) },
    { name: `Markov (${Math.round(weights.markov * 100)}%)`, value: Math.round(weights.markov * 100) },
    {
      name: `Isolation (${Math.round(weights.isolation * 100)}%)`,
      value: Math.round(weights.isolation * 100),
    },
    {
      name: `Transformer (${Math.round(weights.transformer * 100)}%)`,
      value: Math.round(weights.transformer * 100),
    },
  ];

  const scorerEntries = Object.entries(data?.evaluation_benchmark?.scorer_comparison || {}).map(
    ([name, m]) => ({
      name: name.replace('_', ' '),
      stdTpr: Number((m.avg_tpr_std * 100).toFixed(1)),
      evasionTpr: Number((m.avg_tpr_evasion * 100).toFixed(1)),
      fpr: Number((m.avg_fpr * 100).toFixed(2)),
    })
  );

  const livePending = data?.live_telemetry.measurement_status === 'pending_measurement';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Performance Analytics
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Empirical benchmark metrics from evaluation artifacts combined with live proxy runtime
            telemetry
          </p>
        </div>

        <Button variant="outline" size="sm" onClick={loadAnalytics} disabled={loading}>
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Metrics
        </Button>
      </div>

      <StatusBanner source={source} onRetry={loadAnalytics} />

      {/* Primary KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3.5">
        {[
          {
            label: 'Standard TPR',
            val: evalSummary ? `${(evalSummary.standard_tpr * 100).toFixed(1)}%` : 'Pending',
          },
          {
            label: 'Evasion TPR',
            val: evalSummary ? `${(evalSummary.evasion_tpr * 100).toFixed(1)}%` : 'Pending',
          },
          {
            label: 'Precision',
            val: ensembleAblation ? `${ensembleAblation.precision.toFixed(1)}%` : 'Pending',
          },
          {
            label: 'Recall',
            val: ensembleAblation ? `${ensembleAblation.recall.toFixed(1)}%` : 'Pending',
          },
          {
            label: 'F1-Score',
            val: ensembleAblation ? ensembleAblation.f1.toFixed(3) : 'Pending',
          },
          {
            label: 'Overall FPR',
            val: evalSummary ? `${(evalSummary.overall_fpr * 100).toFixed(2)}%` : 'Pending',
          },
          {
            label: 'P50 / P95 Latency',
            val: evalSummary
              ? `${evalSummary.latency.p50.toFixed(1)} / ${evalSummary.latency.p95.toFixed(1)} ms`
              : 'Pending',
          },
          {
            label: 'P99 Latency',
            val: evalSummary ? `${evalSummary.latency.p99.toFixed(2)} ms` : 'Pending',
          },
        ].map((kpi) => (
          <Card key={kpi.label} className="p-4">
            <span className="text-[11px] font-medium text-[#666581] block">{kpi.label}</span>
            <strong className="text-lg font-extrabold text-[#171638] font-display mt-1 block">
              {kpi.val}
            </strong>
          </Card>
        ))}
      </div>

      {/* Live Measurement vs Pending State */}
      <Card className="p-5 bg-[#FAF8FF]">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 text-xs">
            {livePending ? (
              <>
                <Info className="w-4 h-4 text-[#F4AD42] shrink-0" />
                <span className="text-[#8C5506]">
                  <strong>Live Runtime Telemetry: Pending Measurement</strong> — No live proxy calls
                  recorded in current process yet. Showing empirical benchmark distributions from{' '}
                  <code className="font-mono">evaluation/evaluation_results.json</code> &amp;{' '}
                  <code className="font-mono">evaluation/ablation_results.json</code>.
                </span>
              </>
            ) : (
              <>
                <Activity className="w-4 h-4 text-[#22B982] shrink-0" />
                <span className="text-[#148A5E]">
                  <strong>Live Runtime Telemetry Active:</strong>{' '}
                  {data?.live_telemetry.total_calls} intercepted calls measured · Live P50:{' '}
                  {data?.live_telemetry.measured_latency_ms?.p50 ?? '--'} ms · Live P95:{' '}
                  {data?.live_telemetry.measured_latency_ms?.p95 ?? '--'} ms.
                </span>
              </>
            )}
          </div>
          <Badge tone={livePending ? 'warning' : 'success'}>
            {livePending ? 'Benchmark Baseline' : 'Live + Benchmark'}
          </Badge>
        </div>
      </Card>

      {/* Risk Score Distribution + Model Contribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <Card className="lg:col-span-7 p-6">
          <CardHeader
            title="Risk Score Distribution"
            subtitle={
              livePending
                ? 'Live risk histogram awaits proxy calls (displaying live bucket counts = 0)'
                : `Distribution across ${data?.live_telemetry.total_calls} live tool calls`
            }
            icon={<BarChart3 className="w-4 h-4" />}
          />
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.live_telemetry.risk_histogram || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E3DDF8" vertical={false} />
                <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: '#666581' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#666581' }} />
                <Tooltip />
                <Bar dataKey="count" name="Events" fill="#6654E8" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="lg:col-span-5 p-6 flex flex-col justify-between">
          <CardHeader
            title="Model Contribution"
            subtitle="Active backend ensemble weights"
            icon={<ShieldCheck className="w-4 h-4" />}
          />
          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={contributionData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={48}
                  outerRadius={76}
                  paddingAngle={4}
                >
                  {contributionData.map((entry, idx) => (
                    <Cell key={entry.name} fill={DONUT_COLORS[idx % DONUT_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip formatter={(val: number) => `${val}%`} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            {contributionData.map((item, idx) => (
              <div
                key={item.name}
                className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-[#FAF8FF]"
              >
                <span
                  className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: DONUT_COLORS[idx % DONUT_COLORS.length] }}
                />
                <span className="font-medium text-[#171638] truncate">{item.name}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Model-Wise Performance & Ensemble Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <Card className="lg:col-span-6 p-6">
          <CardHeader
            title="Model-Wise Attack-Blocking Capability"
            subtitle="Standard vs Adversarial Evasion TPR (%) from evaluation_results.json"
          />
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scorerEntries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E3DDF8" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#666581' }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#666581' }} />
                <Tooltip />
                <Bar dataKey="stdTpr" name="Standard TPR (%)" fill="#6654E8" radius={[5, 5, 0, 0]} />
                <Bar
                  dataKey="evasionTpr"
                  name="Evasion TPR (%)"
                  fill="#22B982"
                  radius={[5, 5, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="lg:col-span-6 p-6 space-y-4">
          <CardHeader
            title="5-Way Ensemble Ablation Study"
            subtitle="Measured precision, recall, F1, and P50/P99 latency overhead"
            icon={<Clock className="w-4 h-4" />}
          />
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#FAF8FF] border-b border-[#E3DDF8] text-[#666581]">
                <tr>
                  <th className="py-2.5 px-3">Configuration</th>
                  <th className="py-2.5 px-2">Prec</th>
                  <th className="py-2.5 px-2">Rec</th>
                  <th className="py-2.5 px-2">F1</th>
                  <th className="py-2.5 px-2">P50</th>
                  <th className="py-2.5 px-3 text-right">P99</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F3F0FF]">
                {(data?.ablation_study || []).map((row) => (
                  <tr key={row.name} className="hover:bg-[#FAF8FF]">
                    <td className="py-2.5 px-3 font-sans font-semibold text-[#171638]">
                      {row.name}
                    </td>
                    <td className="py-2.5 px-2">{row.precision}%</td>
                    <td className="py-2.5 px-2">{row.recall}%</td>
                    <td className="py-2.5 px-2 font-bold text-[#6654E8]">{row.f1.toFixed(2)}</td>
                    <td className="py-2.5 px-2">{row.p50_ms}ms</td>
                    <td className="py-2.5 px-3 text-right">{row.p99_ms}ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
};

