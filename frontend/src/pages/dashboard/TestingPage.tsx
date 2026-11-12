import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Clock,
  FlaskConical,
  Play,
  Radio,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
} from 'lucide-react';
import { Badge, decisionTone, formatDecisionLabel } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { useTelemetry } from '../../context/TelemetryContext';
import { useToast } from '../../context/ToastContext';
import { fetchTestingHistory, runTestingScenario } from '../../services/api';
import { THREAT_SCENARIOS } from '../../services/mockAdapter';
import type { TestingRunResult } from '../../types';

export const TestingPage: React.FC = () => {
  const [runningId, setRunningId] = useState<string | null>(null);
  const [activeResult, setActiveResult] = useState<TestingRunResult | null>(null);
  const [history, setHistory] = useState<TestingRunResult[]>([]);
  const { refreshAll } = useTelemetry();
  const { addToast } = useToast();

  const loadHistory = useCallback(async () => {
    const items = await fetchTestingHistory();
    if (items.length > 0) {
      setHistory(items);
      setActiveResult((prev) => prev || items[0]);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const handleRunScenario = async (scenarioId: string) => {
    setRunningId(scenarioId);
    try {
      const res = await runTestingScenario(scenarioId);
      setActiveResult(res);
      setHistory((prev) => [res, ...prev].slice(0, 20));
      addToast({
        title: `${res.scenario_name}: ${formatDecisionLabel(res.final_decision)}`,
        description:
          res.execution_mode === 'live_backend_engine'
            ? `Executed live in ${res.duration_ms} ms (Peak Risk ${res.peak_risk_score.toFixed(2)})`
            : `Offline simulated run (Peak Risk ${res.peak_risk_score.toFixed(2)})`,
        variant:
          res.final_decision === 'allow'
            ? 'success'
            : res.final_decision === 'flag'
              ? 'warning'
              : 'danger',
      });
      if (res.execution_mode === 'live_backend_engine') {
        await refreshAll();
      }
    } finally {
      setRunningId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-extrabold text-[#171638]">
          Security Test Suite &amp; Attack Simulation
        </h1>
        <p className="text-xs text-[#666581] mt-0.5">
          Validate CERBERUS against predefined adversarial trajectories through the live FastAPI
          firewall engine (or clearly-labelled offline simulation if disconnected)
        </p>
      </div>

      {/* 8 Scenario Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {THREAT_SCENARIOS.map((sc) => {
          const isRunning = runningId === sc.id;
          return (
            <Card key={sc.id} hover className="p-5 flex flex-col justify-between gap-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 rounded-xl bg-[#EAE6FF] text-[#6654E8] flex items-center justify-center">
                    {sc.id === 'normal' ? (
                      <CheckCircle2 className="w-4 h-4 text-[#22B982]" />
                    ) : sc.id === 'baseline_poisoning' ? (
                      <Activity className="w-4 h-4" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-[#F06478]" />
                    )}
                  </div>
                  <Badge tone={sc.id === 'normal' ? 'success' : 'purple'}>{sc.category}</Badge>
                </div>
                <h2 className="text-sm font-bold text-[#171638]">{sc.name}</h2>
                <p className="text-xs text-[#666581] leading-relaxed">{sc.description}</p>
              </div>

              <Button
                size="sm"
                onClick={() => handleRunScenario(sc.id)}
                disabled={Boolean(runningId)}
                className="w-full"
              >
                <Play className="w-3.5 h-3.5" />
                {isRunning ? 'Executing...' : 'Run Test Scenario'}
              </Button>
            </Card>
          );
        })}
      </div>

      {/* Active Result + History */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <Card className="lg:col-span-7 p-6 space-y-4">
          <CardHeader
            title="Test Execution Output"
            subtitle={
              activeResult
                ? `${activeResult.scenario_name} · ${activeResult.duration_ms} ms`
                : 'Select and run any scenario above'
            }
            icon={<FlaskConical className="w-4 h-4" />}
            actions={
              activeResult && (
                <Badge
                  tone={
                    activeResult.execution_mode === 'live_backend_engine' ? 'success' : 'warning'
                  }
                >
                  {activeResult.execution_mode === 'live_backend_engine' ? (
                    <>
                      <Radio className="w-3 h-3" /> Live Backend Engine
                    </>
                  ) : (
                    'Offline Simulation'
                  )}
                </Badge>
              )
            }
          />

          {!activeResult ? (
            <p className="text-xs text-[#666581] py-10 text-center">
              Click <strong>Run Test Scenario</strong> on any card to execute the sequence.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                  <span className="text-[#666581] block">Final Decision</span>
                  <Badge tone={decisionTone(activeResult.final_decision)} className="mt-1">
                    {formatDecisionLabel(activeResult.final_decision)}
                  </Badge>
                </div>
                <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                  <span className="text-[#666581] block">Peak Risk Score</span>
                  <strong className="text-base font-mono text-[#171638]">
                    {activeResult.peak_risk_score.toFixed(3)}
                  </strong>
                </div>
                <div className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
                  <span className="text-[#666581] block">Duration</span>
                  <strong className="text-base font-mono text-[#6654E8]">
                    {activeResult.duration_ms} ms
                  </strong>
                </div>
              </div>

              <div className="space-y-2">
                {activeResult.steps.map((st, idx) => (
                  <div
                    key={st.event_id}
                    className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                  >
                    <div className="min-w-0">
                      <span className="text-[#6654E8] font-bold mr-2">Step #{idx + 1}</span>
                      <strong className="text-[#171638]">{st.tool_name}</strong>
                      {st.destination_domain && (
                        <span className="text-[#C6384D] ml-2">→ {st.destination_domain}</span>
                      )}
                      {st.risk_factors[0] && (
                        <p className="text-[11px] font-sans text-[#666581] mt-1">
                          {st.risk_factors[0]}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span>{st.risk_score.toFixed(2)}</span>
                      <Badge tone={decisionTone(st.decision)}>
                        {formatDecisionLabel(st.decision)}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>

        <Card className="lg:col-span-5 p-6 space-y-4">
          <CardHeader
            title="Test Execution History"
            subtitle="Live backend vs simulated test log"
            icon={<Clock className="w-4 h-4" />}
          />
          {history.length === 0 ? (
            <p className="text-xs text-[#666581] py-8 text-center">No test runs recorded yet.</p>
          ) : (
            <div className="space-y-2.5 max-h-[380px] overflow-y-auto">
              {history.map((run) => (
                <button
                  key={run.run_id}
                  onClick={() => setActiveResult(run)}
                  className="w-full text-left p-3 rounded-xl bg-[#FAF8FF] hover:bg-[#EAE6FF]/60 border border-[#E3DDF8] flex items-center justify-between gap-2 text-xs transition-colors"
                >
                  <div className="min-w-0">
                    <p className="font-bold text-[#171638] truncate">{run.scenario_name}</p>
                    <p className="text-[11px] font-mono text-[#666581]">
                      {run.execution_mode === 'live_backend_engine' ? 'Live Engine' : 'Simulated'} ·{' '}
                      {run.duration_ms} ms
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="font-mono font-bold">{run.peak_risk_score.toFixed(2)}</span>
                    <Badge tone={decisionTone(run.final_decision)}>
                      {formatDecisionLabel(run.final_decision)}
                    </Badge>
                  </div>
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

