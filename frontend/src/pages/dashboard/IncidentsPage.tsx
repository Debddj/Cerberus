import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Clock,
  FileSearch,
  Lock,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { Badge, decisionTone, formatDecisionLabel } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { Drawer } from '../../components/ui/Drawer';
import { EmptyState } from '../../components/ui/EmptyState';
import { StatusBanner } from '../../components/ui/StatusBanner';
import { useToast } from '../../context/ToastContext';
import { fetchIncidents, quarantineSession } from '../../services/api';
import type { IncidentRecord, IncidentTimelineStep } from '../../types';

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [source, setSource] = useState<'live' | 'offline-demo'>('live');
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<IncidentRecord | null>(null);
  const [evidenceStep, setEvidenceStep] = useState<IncidentTimelineStep | null>(null);
  const { addToast } = useToast();

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchIncidents();
      setIncidents(res.data);
      setSource(res.source);
      setSelected((prev) => {
        if (!prev) return res.data[0] || null;
        return res.data.find((i) => i.session_id === prev.session_id) || res.data[0] || null;
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const handleQuarantine = async (sessionId: string) => {
    try {
      await quarantineSession(sessionId);
      addToast({
        title: `Session ${sessionId} quarantined`,
        description: 'Added to active quarantine registry.',
        variant: 'warning',
      });
      await loadIncidents();
    } catch (err) {
      addToast({
        title: 'Quarantine request failed',
        description: err instanceof Error ? err.message : 'Backend unavailable',
        variant: 'danger',
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">
            Incident Investigation &amp; Kill-Chain Forensics
          </h1>
          <p className="text-xs text-[#666581] mt-0.5">
            Chronological attack trajectories, Lethal Trifecta breakdowns, and original tool call
            evidence
          </p>
        </div>

        <Button variant="outline" size="sm" onClick={loadIncidents} disabled={loading}>
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Incidents
        </Button>
      </div>

      <StatusBanner source={source} onRetry={loadIncidents} />

      {incidents.length === 0 ? (
        <EmptyState
          icon={<AlertOctagon className="w-7 h-7" />}
          title="No Security Incidents Flagged"
          description="When CERBERUS flags, blocks, or quarantines an agent session, its reconstructed kill-chain timeline appears here."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Incident List */}
          <Card className="lg:col-span-4 p-4 space-y-2.5">
            <h2 className="text-xs font-bold uppercase tracking-wider text-[#666581] px-2">
              Detected Incidents ({incidents.length})
            </h2>
            {incidents.map((inc) => {
              const isSelected = selected?.session_id === inc.session_id;
              return (
                <button
                  key={inc.session_id}
                  onClick={() => setSelected(inc)}
                  className={`w-full text-left p-3.5 rounded-2xl border transition-all space-y-1.5 ${
                    isSelected
                      ? 'bg-[#EAE6FF] border-[#6654E8]'
                      : 'bg-[#FAF8FF] border-[#E3DDF8] hover:bg-[#F3F0FF]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-extrabold text-[#171638]">
                      #{inc.incident_id}
                    </span>
                    <Badge
                      tone={
                        inc.severity === 'critical'
                          ? 'danger'
                          : inc.severity === 'high'
                            ? 'warning'
                            : 'primary'
                      }
                    >
                      {inc.severity.toUpperCase()} RISK
                    </Badge>
                  </div>
                  <p className="text-xs font-semibold text-[#6654E8] truncate">
                    Agent: {inc.agent_id}
                  </p>
                  <div className="flex items-center justify-between text-[11px] font-mono text-[#666581]">
                    <span>{inc.total_calls} calls</span>
                    <span>Peak: {inc.peak_risk_score.toFixed(2)}</span>
                  </div>
                </button>
              );
            })}
          </Card>

          {/* Chronological Timeline & Evidence */}
          {selected && (
            <div className="lg:col-span-8 space-y-6">
              <Card className="p-6 space-y-5">
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#E3DDF8] pb-4">
                  <div>
                    <div className="flex items-center gap-2.5">
                      <h2 className="font-display text-xl font-extrabold text-[#171638]">
                        Incident #{selected.incident_id}
                      </h2>
                      <Badge
                        tone={selected.severity === 'critical' ? 'danger' : 'warning'}
                        dot
                      >
                        {selected.severity === 'critical' ? 'Critical Risk' : 'High Risk'}
                      </Badge>
                      {selected.trifecta_detected && (
                        <Badge tone="purple">Lethal Trifecta</Badge>
                      )}
                    </div>
                    <p className="text-xs font-mono text-[#666581] mt-1">
                      Agent: <strong className="text-[#171638]">{selected.agent_id}</strong> ·
                      Session: <strong className="text-[#171638]">{selected.session_id}</strong> ·
                      Detected: {new Date(selected.detection_time).toLocaleString()}
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <Badge tone={decisionTone(selected.enforcement_decision)}>
                      {formatDecisionLabel(selected.enforcement_decision)}
                    </Badge>
                    {!selected.quarantined && (
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => handleQuarantine(selected.session_id)}
                      >
                        <Lock className="w-3.5 h-3.5" />
                        Quarantine Session
                      </Button>
                    )}
                  </div>
                </div>

                {/* Chronological Attack Timeline (T1, T2, T3...) matching collage */}
                <div className="space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#666581] flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-[#6654E8]" />
                    Chronological Attack Timeline (Click step to inspect evidence)
                  </h3>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-[#FAF8FF] text-[#666581] border-b border-[#E3DDF8]">
                        <tr>
                          <th className="py-2.5 px-3 font-semibold">Timeline</th>
                          <th className="py-2.5 px-3 font-semibold">Details</th>
                          <th className="py-2.5 px-3 font-semibold">Risk</th>
                          <th className="py-2.5 px-3 font-semibold">Decision</th>
                          <th className="py-2.5 px-3 font-semibold text-right">Time</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#F3F0FF]">
                        {selected.timeline.map((step) => {
                          const dotColor =
                            step.decision === 'block' || step.decision === 'quarantine'
                              ? 'bg-[#F06478]'
                              : step.decision === 'flag'
                                ? 'bg-[#F4AD42]'
                                : 'bg-[#22B982]';
                          return (
                            <tr
                              key={step.event_id}
                              onClick={() => setEvidenceStep(step)}
                              className="hover:bg-[#FAF8FF] cursor-pointer transition-colors"
                            >
                              <td className="py-3 px-3 font-mono font-bold text-[#171638] whitespace-nowrap">
                                <span className="inline-flex items-center gap-2">
                                  <span className={`w-2.5 h-2.5 rounded-full ${dotColor}`} />
                                  {step.step}
                                </span>
                              </td>
                              <td className="py-3 px-3 font-mono text-[#171638]">
                                <span className="font-bold text-[#6654E8]">{step.tool_name}</span>
                                <span className="text-[#666581] ml-1.5">
                                  (
                                  {step.destination_domain ||
                                    JSON.stringify(step.parameters).slice(0, 42)}
                                  )
                                </span>
                              </td>
                              <td className="py-3 px-3 font-mono font-semibold">
                                {step.risk_score.toFixed(2)}
                              </td>
                              <td className="py-3 px-3">
                                <Badge tone={decisionTone(step.decision)}>
                                  {formatDecisionLabel(step.decision)}
                                </Badge>
                              </td>
                              <td className="py-3 px-3 text-right font-mono text-[#666581]">
                                {new Date(step.timestamp).toLocaleTimeString()}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Triggered Security Rules */}
                {selected.triggered_rules.length > 0 && (
                  <div className="space-y-2 pt-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-[#666581]">
                      Triggered Security Rules &amp; Signals
                    </h4>
                    <div className="space-y-1.5">
                      {selected.triggered_rules.map((r, i) => (
                        <div
                          key={i}
                          className="p-2.5 rounded-xl bg-[#FFF5F7] border border-[#F06478]/25 text-xs text-[#9B2335] flex items-center gap-2"
                        >
                          <AlertTriangle className="w-3.5 h-3.5 text-[#F06478] shrink-0" />
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Card>

              {/* Narrative Reconstructor Card */}
              <Card className="p-6 space-y-3">
                <CardHeader
                  title="Forensic Kill-Chain Narrative"
                  subtitle="Generated by cerberus.narrative.reconstructor.NarrativeReconstructor"
                  icon={<FileSearch className="w-4 h-4" />}
                />
                <pre className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] font-mono text-xs text-[#171638] whitespace-pre-wrap leading-relaxed overflow-x-auto">
                  {selected.narrative}
                </pre>
              </Card>
            </div>
          )}
        </div>
      )}

      {/* Original Event Evidence Drawer */}
      <Drawer
        open={Boolean(evidenceStep)}
        onClose={() => setEvidenceStep(null)}
        title={`Step ${evidenceStep?.step || ''} · ${evidenceStep?.tool_name || ''}`}
        subtitle={`Event ID: ${evidenceStep?.event_id || ''}`}
      >
        {evidenceStep && (
          <div className="space-y-5 text-xs">
            <div className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] font-mono space-y-1.5">
              <div className="flex justify-between">
                <span className="text-[#666581]">MCP Server</span>
                <strong>{evidenceStep.tool_server}</strong>
              </div>
              <div className="flex justify-between">
                <span className="text-[#666581]">Risk Score</span>
                <strong>{evidenceStep.risk_score.toFixed(3)}</strong>
              </div>
              <div className="flex justify-between">
                <span className="text-[#666581]">Policy Reason</span>
                <strong className="text-right">{evidenceStep.decision_reason || 'N/A'}</strong>
              </div>
            </div>

            <div>
              <h4 className="font-bold text-[#171638] uppercase tracking-wider mb-2">
                Original Sanitized Parameters Evidence
              </h4>
              <pre className="p-4 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] font-mono overflow-x-auto">
                {JSON.stringify(evidenceStep.parameters, null, 2)}
              </pre>
            </div>

            {evidenceStep.risk_factors.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-bold text-[#171638] uppercase tracking-wider">
                  Attributed Signals
                </h4>
                {evidenceStep.risk_factors.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-[#F06478]/10 border border-[#F06478]/25 text-[#9B2335] flex items-start gap-2"
                  >
                    <ShieldAlert className="w-4 h-4 text-[#F06478] shrink-0 mt-0.5" />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
};

