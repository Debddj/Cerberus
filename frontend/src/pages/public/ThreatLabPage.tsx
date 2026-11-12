import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FlaskConical,
  Play,
  Radio,
  RotateCcw,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
} from 'lucide-react';
import { Badge, decisionTone, formatDecisionLabel } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card } from '../../components/ui/Card';
import { runTestingScenario } from '../../services/api';
import { THREAT_SCENARIOS } from '../../services/mockAdapter';
import type { TestingRunResult } from '../../types';

export const ThreatLabPage: React.FC = () => {
  const [selectedId, setSelectedId] = useState<string>('prompt_injection');
  const [executionMode, setExecutionMode] = useState<'demonstration' | 'live'>('demonstration');
  const [activeStepIdx, setActiveStepIdx] = useState<number>(99);
  const [animating, setAnimating] = useState(false);
  const [liveResult, setLiveResult] = useState<TestingRunResult | null>(null);
  const [runningLive, setRunningLive] = useState(false);

  const blueprint = THREAT_SCENARIOS.find((s) => s.id === selectedId) || THREAT_SCENARIOS[0];

  const playAnimation = (stepCount: number) => {
    setAnimating(true);
    setActiveStepIdx(0);
    let current = 0;
    const timer = window.setInterval(() => {
      current += 1;
      setActiveStepIdx(current);
      if (current >= stepCount - 1) {
        window.clearInterval(timer);
        setAnimating(false);
      }
    }, 520);
  };

  const handleSelectScenario = (id: string) => {
    setSelectedId(id);
    setLiveResult(null);
    const target = THREAT_SCENARIOS.find((s) => s.id === id);
    playAnimation(target?.steps.length || 3);
  };

  const handleRunLive = async () => {
    setRunningLive(true);
    try {
      const res = await runTestingScenario(selectedId);
      setLiveResult(res);
      playAnimation(res.steps.length);
    } finally {
      setRunningLive(false);
    }
  };

  useEffect(() => {
    playAnimation(blueprint.steps.length);
  }, []);

  const displayedSteps =
    executionMode === 'live' && liveResult
      ? liveResult.steps.map((s, idx) => ({
          tool_name: s.tool_name,
          tool_server: s.tool_server,
          label: s.tool_name,
          paramsPreview: s.destination_domain ? `dest: ${s.destination_domain}` : `step #${idx + 1}`,
          rule_score: s.breakdown?.rule_score ?? 0,
          markov_score: s.breakdown?.markov_score ?? 0,
          isolation_score: s.breakdown?.isolation_score ?? 0,
          transformer_score: s.breakdown?.transformer_score ?? 0,
          composite_score: s.risk_score,
          decision: s.decision,
          reason: s.decision_reason || s.risk_factors[0] || 'Evaluated by live engine',
        }))
      : blueprint.steps;

  const visibleCount = Math.min(displayedSteps.length, activeStepIdx + 1);
  const lastVisible = displayedSteps[Math.max(0, visibleCount - 1)];
  const peakScore = Math.max(
    ...displayedSteps.slice(0, visibleCount).map((s) => s.composite_score),
    0
  );
  const finalDecision =
    displayedSteps.slice(0, visibleCount).find((s) => s.decision === 'quarantine')?.decision ||
    displayedSteps.slice(0, visibleCount).find((s) => s.decision === 'block')?.decision ||
    displayedSteps.slice(0, visibleCount).find((s) => s.decision === 'flag')?.decision ||
    'allow';

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-8">
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="space-y-2">
          <Badge tone="primary">Interactive Threat Simulation Lab</Badge>
          <h1 className="font-display text-3xl sm:text-4xl font-extrabold text-[#171638]">
            Threat Simulation Lab
          </h1>
          <p className="text-sm sm:text-base text-[#666581] max-w-2xl">
            Run controlled attack trajectories across 8 adversarial scenarios and inspect how
            CERBERUS evaluates individual scorers and enforces policy gates.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-white border border-[#E3DDF8] rounded-xl p-1 self-start">
          <button
            onClick={() => setExecutionMode('demonstration')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              executionMode === 'demonstration'
                ? 'cerberus-gradient-btn text-white'
                : 'text-[#666581] hover:text-[#171638]'
            }`}
          >
            Simulated Demonstration
          </button>
          <button
            onClick={() => {
              setExecutionMode('live');
              handleRunLive();
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              executionMode === 'live'
                ? 'cerberus-gradient-btn text-white'
                : 'text-[#666581] hover:text-[#171638]'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            Live Backend Execution
          </button>
        </div>
      </div>

      {/* Clear Distinction Banner */}
      <div
        className={`rounded-xl px-4 py-2.5 border text-xs flex items-center justify-between gap-3 ${
          executionMode === 'live' && liveResult?.execution_mode === 'live_backend_engine'
            ? 'bg-[#22B982]/10 border-[#22B982]/30 text-[#148A5E]'
            : 'bg-[#F4AD42]/12 border-[#F4AD42]/35 text-[#8C5506]'
        }`}
      >
        <div className="flex items-center gap-2">
          <FlaskConical className="w-4 h-4 shrink-0" />
          <span>
            {executionMode === 'live' && liveResult?.execution_mode === 'live_backend_engine' ? (
              <>
                <strong>Live Backend Verification:</strong> Executed against{' '}
                <code className="font-mono">CerberusProxyEngine</code> (Session{' '}
                <code className="font-mono">{liveResult.session_id}</code> ·{' '}
                {liveResult.duration_ms} ms).
              </>
            ) : (
              <>
                <strong>Interactive Demonstration Mode:</strong> Scenario replay uses curated
                reference scoring blueprints for safe public exploration. Switch to{' '}
                <em>Live Backend Execution</em> when the FastAPI server is running.
              </>
            )}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Scenario Selector */}
        <Card className="lg:col-span-4 p-4 space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-[#666581] px-2 pb-1">
            Select Scenario (8)
          </h2>
          {THREAT_SCENARIOS.map((sc) => {
            const active = sc.id === selectedId;
            return (
              <button
                key={sc.id}
                onClick={() => handleSelectScenario(sc.id)}
                className={`w-full text-left px-3.5 py-3 rounded-xl transition-all flex items-center justify-between gap-2 ${
                  active
                    ? 'cerberus-gradient-btn text-white'
                    : 'bg-[#FAF8FF] hover:bg-[#EAE6FF] text-[#171638] border border-[#E3DDF8]'
                }`}
              >
                <div className="min-w-0">
                  <p className="text-sm font-bold truncate">{sc.name}</p>
                  <p
                    className={`text-[11px] truncate ${
                      active ? 'text-white/80' : 'text-[#666581]'
                    }`}
                  >
                    {sc.category}
                  </p>
                </div>
                <Play className={`w-3.5 h-3.5 shrink-0 ${active ? 'text-white' : 'text-[#6654E8]'}`} />
              </button>
            );
          })}
        </Card>

        {/* Interactive Pipeline & Scoring Panel */}
        <div className="lg:col-span-8 space-y-6">
          <Card className="p-6 space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[#E3DDF8] pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold text-[#171638]">{blueprint.name}</h2>
                  <Badge tone="purple">{blueprint.category}</Badge>
                </div>
                <p className="text-sm text-[#666581] mt-1">{blueprint.description}</p>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => playAnimation(displayedSteps.length)}
                  disabled={animating}
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  Replay
                </Button>
                {executionMode === 'live' && (
                  <Button size="sm" onClick={handleRunLive} disabled={runningLive}>
                    {runningLive ? 'Executing...' : 'Re-Run Live'}
                  </Button>
                )}
              </div>
            </div>

            {/* Animated Tool Call Sequence */}
            <div className="space-y-3">
              <span className="text-xs font-bold uppercase tracking-wider text-[#666581] block">
                Intercepted Tool-Call Sequence
              </span>

              <div className="flex flex-wrap items-stretch gap-3">
                {displayedSteps.map((step, idx) => {
                  const revealed = idx <= activeStepIdx;
                  const isDanger = step.decision === 'block' || step.decision === 'quarantine';
                  const isWarn = step.decision === 'flag';
                  return (
                    <React.Fragment key={idx}>
                      <motion.div
                        initial={{ opacity: 0.3, scale: 0.96 }}
                        animate={{
                          opacity: revealed ? 1 : 0.35,
                          scale: revealed ? 1 : 0.96,
                        }}
                        transition={{ duration: 0.25 }}
                        className={`flex-1 min-w-[170px] rounded-2xl p-4 border-2 transition-colors ${
                          !revealed
                            ? 'border-[#E3DDF8] bg-[#FAF8FF]'
                            : isDanger
                              ? 'border-[#F06478] bg-[#FFF5F7]'
                              : isWarn
                                ? 'border-[#F4AD42] bg-[#FFFBF2]'
                                : 'border-[#22B982]/40 bg-white'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1.5">
                          <span className="text-[11px] font-mono font-bold text-[#6654E8]">
                            T{idx + 1}
                          </span>
                          {revealed && (
                            <Badge tone={decisionTone(step.decision)}>
                              {formatDecisionLabel(step.decision)}
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm font-bold text-[#171638] font-mono truncate">
                          {step.tool_name}
                        </p>
                        <p className="text-[11px] text-[#666581] truncate mt-0.5">
                          {step.paramsPreview}
                        </p>
                        {revealed && (
                          <div className="mt-2.5 pt-2 border-t border-[#E3DDF8] flex items-center justify-between text-xs font-mono">
                            <span className="text-[#666581]">Composite</span>
                            <strong
                              className={
                                isDanger
                                  ? 'text-[#C6384D]'
                                  : isWarn
                                    ? 'text-[#B7720C]'
                                    : 'text-[#148A5E]'
                              }
                            >
                              {step.composite_score.toFixed(2)}
                            </strong>
                          </div>
                        )}
                      </motion.div>
                      {idx < displayedSteps.length - 1 && (
                        <div className="hidden sm:flex items-center">
                          <ArrowRight className="w-4 h-4 text-[#8C7BFA]" />
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Individual Model Scores */}
            <div className="space-y-3 pt-2">
              <span className="text-xs font-bold uppercase tracking-wider text-[#666581] block">
                Individual Security Checks (Active Step)
              </span>

              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                {[
                  { label: 'Rule-Based', val: lastVisible?.rule_score ?? 0 },
                  { label: 'Markov Chain', val: lastVisible?.markov_score ?? 0 },
                  { label: 'Isolation Forest', val: lastVisible?.isolation_score ?? 0 },
                  { label: 'Transformer', val: lastVisible?.transformer_score ?? 0 },
                  { label: 'Composite Risk', val: peakScore, highlight: true },
                ].map((m) => (
                  <div
                    key={m.label}
                    className={`rounded-xl p-3.5 border ${
                      m.highlight
                        ? 'bg-[#EAE6FF] border-[#6654E8]/40'
                        : 'bg-[#FAF8FF] border-[#E3DDF8]'
                    }`}
                  >
                    <span className="text-[11px] font-medium text-[#666581] block">{m.label}</span>
                    <span className="text-xl font-extrabold font-mono text-[#171638] mt-1 block">
                      {m.val.toFixed(2)}
                    </span>
                    <div className="w-full h-1.5 rounded-full bg-[#DCD5FF] mt-2 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          m.val >= 0.7
                            ? 'bg-[#F06478]'
                            : m.val >= 0.4
                              ? 'bg-[#F4AD42]'
                              : 'bg-[#22B982]'
                        }`}
                        style={{ width: `${Math.min(100, m.val * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Verdict Banner & Explanation */}
            <div
              className={`rounded-2xl p-5 border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                finalDecision === 'allow'
                  ? 'bg-[#22B982]/10 border-[#22B982]/30'
                  : 'bg-[#F06478]/10 border-[#F06478]/30'
              }`}
            >
              <div className="flex items-start gap-3">
                {finalDecision === 'allow' ? (
                  <CheckCircle2 className="w-6 h-6 text-[#22B982] shrink-0 mt-0.5" />
                ) : finalDecision === 'quarantine' ? (
                  <ShieldAlert className="w-6 h-6 text-[#6654E8] shrink-0 mt-0.5" />
                ) : finalDecision === 'block' ? (
                  <ShieldBan className="w-6 h-6 text-[#F06478] shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-6 h-6 text-[#F4AD42] shrink-0 mt-0.5" />
                )}
                <div>
                  <h3 className="text-sm font-bold text-[#171638]">
                    {finalDecision === 'allow'
                      ? 'Baseline Behaviour Verified'
                      : `Attack Detected! Peak Risk Score: ${peakScore.toFixed(2)} (${
                          peakScore >= 0.7 ? 'High' : 'Elevated'
                        })`}
                  </h3>
                  <p className="text-xs text-[#666581] mt-1 leading-relaxed">
                    {blueprint.explanation}
                  </p>
                </div>
              </div>

              <Badge tone={decisionTone(finalDecision)} className="self-start sm:self-center text-xs px-3 py-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                {formatDecisionLabel(finalDecision)}
              </Badge>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

