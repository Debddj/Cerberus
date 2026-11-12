import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Activity,
  ArrowRight,
  BookOpen,
  Bot,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Database,
  Eye,
  FileCode2,
  FileSearch,
  GitBranch,
  Globe,
  Layers,
  Lock,
  Play,
  Radar,
  RefreshCw,
  Scale,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from 'lucide-react';
import { CerberusLogo } from '../../components/brand/CerberusLogo';
import { MountainBackdrop } from '../../components/brand/MountainBackdrop';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card } from '../../components/ui/Card';
import { THREAT_SCENARIOS } from '../../services/mockAdapter';

const CORE_PILLARS = [
  {
    title: 'Observe',
    desc: 'Intercept & monitor every MCP tool call across HTTP JSON-RPC and local stdio transports.',
    icon: Eye,
  },
  {
    title: 'Analyze',
    desc: 'Detect behavioral drift with Markov transitions, Isolation Forest, and Sequence Transformer.',
    icon: Radar,
  },
  {
    title: 'Enforce',
    desc: 'Apply dynamic OPA Rego policies with a strict 10-second fail-closed circuit breaker.',
    icon: Zap,
  },
  {
    title: 'Investigate',
    desc: 'Reconstruct kill-chains across Reconnaissance, Staging, and Exfiltration with SHA-256 logs.',
    icon: FileSearch,
  },
  {
    title: 'Adapt',
    desc: 'Refit baselines safely using immutable snapshots and Total Variation Distance (TVD) gating.',
    icon: RefreshCw,
  },
];

const CAPABILITIES = [
  {
    title: 'Runtime Interception Proxy',
    desc: 'Transparent reverse proxy interposing on tools/list and tools/call with pre-persistence secret redaction.',
    icon: ShieldCheck,
  },
  {
    title: 'Static Pre-Flight Scanner',
    desc: 'SHA-256 schema pinning, Lethal Trifecta detection, cross-server shadow checks, and scope enforcement.',
    icon: Lock,
  },
  {
    title: '4-Member Behavioral ML',
    desc: 'Cost-aware 3-tier cascading ensemble combining Rules, Markov Chain, Isolation Forest, and Sequence Transformer.',
    icon: BrainCircuit,
  },
  {
    title: 'OPA Rego Policy Gate',
    desc: 'Multi-package Rego v1 enforcement with automated least-privilege policy synthesis and dry-run simulator.',
    icon: Scale,
  },
  {
    title: 'Cryptographic Audit Ledger',
    desc: 'Append-only SHA-256 hash-chained ledger with Fernet encryption at rest and automated rotation.',
    icon: FileCode2,
  },
  {
    title: 'Forensic SOC Console',
    desc: 'Real-time SSE event stream, incident kill-chain narratives, baseline management, and SLA analytics.',
    icon: Activity,
  },
];

const TECH_STACK = [
  { name: 'Python 3.12+', role: 'Core Runtime & CLI' },
  { name: 'FastAPI & Uvicorn', role: 'Async JSON-RPC Gateway & SSE' },
  { name: 'MCP Python SDK', role: 'HTTP & Stdio Proxy Transport' },
  { name: 'OPA & Rego v1', role: 'Declarative Policy Gate' },
  { name: 'scikit-learn', role: 'Isolation Forest Scoring' },
  { name: 'PyTorch / NumPy', role: 'Sequence Autoencoder Drift' },
  { name: 'SQLite & Redis', role: 'Schema Pins & Distributed State' },
  { name: 'React 18 & Recharts', role: 'SOC Dashboard & Telemetry' },
];

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();
  const [previewScenarioId, setPreviewScenarioId] = useState('prompt_injection');
  const previewScenario =
    THREAT_SCENARIOS.find((s) => s.id === previewScenarioId) || THREAT_SCENARIOS[1];

  return (
    <div className="space-y-20 pb-8">
      {/* ── HERO SECTION ─────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden cerberus-hero-surface border-b border-[#E3DDF8]">
        <MountainBackdrop className="absolute bottom-0 left-0 right-0 w-full h-56 sm:h-72 opacity-90" />

        <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-14 pb-20 lg:py-24">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="lg:col-span-7 space-y-6"
            >
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/85 border border-[#DCD5FF] shadow-sm text-xs font-semibold text-[#6654E8]">
                <ShieldCheck className="w-4 h-4" />
                Zero-Trust Control Plane for MCP-Based AI Agents
              </div>

              <h1 className="font-display text-4xl sm:text-5xl lg:text-[54px] font-extrabold tracking-tight text-[#171638] leading-[1.08]">
                Watch. Analyze. Protect.
              </h1>

              <p className="text-lg sm:text-xl text-[#4E4C6A] max-w-2xl leading-relaxed">
                A Runtime Behavioral Firewall for Secure MCP-Based AI Agents. Intercept tool-call
                trajectories, stop indirect prompt injections, and enforce fail-closed zero-trust
                policies in real time.
              </p>

              <div className="flex flex-wrap items-center gap-3.5 pt-2">
                <Button size="lg" onClick={() => navigate('/dashboard')}>
                  Get Started
                  <ArrowRight className="w-4 h-4" />
                </Button>
                <Button size="lg" variant="outline" onClick={() => navigate('/architecture')}>
                  Explore Architecture
                </Button>
                <Button size="lg" variant="secondary" onClick={() => navigate('/threat-lab')}>
                  <Play className="w-4 h-4 text-[#6654E8]" />
                  View Demo
                </Button>
              </div>

              <div className="grid grid-cols-3 gap-4 pt-4 max-w-lg">
                <div className="bg-white/80 backdrop-blur rounded-xl px-3.5 py-2.5 border border-[#E3DDF8]">
                  <span className="text-[11px] font-medium text-[#666581] block">Attack Catch</span>
                  <span className="text-lg font-bold text-[#171638]">100.0%</span>
                </div>
                <div className="bg-white/80 backdrop-blur rounded-xl px-3.5 py-2.5 border border-[#E3DDF8]">
                  <span className="text-[11px] font-medium text-[#666581] block">P95 Latency</span>
                  <span className="text-lg font-bold text-[#6654E8]">14.02 ms</span>
                </div>
                <div className="bg-white/80 backdrop-blur rounded-xl px-3.5 py-2.5 border border-[#E3DDF8]">
                  <span className="text-[11px] font-medium text-[#666581] block">Policy Gate</span>
                  <span className="text-lg font-bold text-[#22B982]">Fail-Closed</span>
                </div>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, scale: 0.94 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.45, delay: 0.1 }}
              className="lg:col-span-5 flex flex-col items-center justify-center"
            >
              <div className="relative flex flex-col items-center">
                <CerberusLogo size={320} showHalo className="w-64 sm:w-80 h-auto drop-shadow-xl" />
                <div className="mt-2 px-4 py-1.5 rounded-full bg-white/90 border border-[#DCD5FF] shadow-card text-xs font-mono text-[#171638] flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#22B982] animate-pulse" />
                  Guardian Active · HTTP &amp; Stdio MCP Interception
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── 1. INTRODUCTION & 5-PILLAR PHILOSOPHY ────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          <div className="lg:col-span-5 cerberus-card p-8 relative overflow-hidden bg-gradient-to-b from-[#FAF8FF] to-[#EDE9FE]">
            <div className="flex flex-col items-center text-center mb-6">
              <CerberusLogo size={112} showHalo />
              <h2 className="font-display text-2xl font-extrabold text-[#171638] mt-2 tracking-tight">
                CERBERUS
              </h2>
              <p className="text-xs font-semibold text-[#6654E8] mt-1">
                Runtime Behavioral Firewall &amp; Zero-Trust Control Plane for MCP-Based AI Agents
              </p>
            </div>
            <div className="space-y-3">
              {CORE_PILLARS.map((pillar) => {
                const Icon = pillar.icon;
                return (
                  <div
                    key={pillar.title}
                    className="flex items-start gap-3.5 bg-white/90 border border-[#E3DDF8] rounded-xl p-3"
                  >
                    <div className="w-9 h-9 rounded-xl bg-[#EAE6FF] text-[#6654E8] flex items-center justify-center shrink-0">
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-[#171638]">{pillar.title}</h3>
                      <p className="text-xs text-[#666581] leading-relaxed">{pillar.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="lg:col-span-7 space-y-5">
            <Badge tone="primary">1. Introduction to CERBERUS</Badge>
            <h2 className="font-display text-3xl sm:text-4xl font-extrabold text-[#171638]">
              Securing the Trajectory, Not Just Isolated Tool Calls
            </h2>
            <p className="text-[#666581] leading-relaxed">
              Modern autonomous AI agents connect to file systems, databases, ticketing systems, and
              external APIs via the <strong>Model Context Protocol (MCP)</strong>. Traditional
              pre-flight scanners and stateless allowlists evaluate every request in isolation —
              leaving agents defenseless against <strong>indirect prompt injection</strong>,{' '}
              <strong>Lethal Trifecta exfiltration chains</strong>,{' '}
              <strong>rug-pull tool schema mutations</strong>, and{' '}
              <strong>slow-drip behavioral drift</strong>.
            </p>
            <p className="text-[#666581] leading-relaxed">
              CERBERUS interposes transparently between your agent loop and upstream MCP tool servers,
              continuously asking:{' '}
              <span className="text-[#171638] font-semibold">
                &ldquo;Does this agent&apos;s multi-step sequence trajectory still look like itself
                over time?&rdquo;
              </span>
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              {[
                'Pre-persistence secret scrubbing (AWS, OpenAI, GitHub PATs, RSA)',
                'Dual-transport proxy: FastAPI JSON-RPC + MCP Stdio wrapper',
                'Anti-poisoning TVD stability gate on versioned baseline snapshots',
                'Auto-synthesized Rego policies with SOC dry-run approval',
              ].map((point) => (
                <div
                  key={point}
                  className="flex items-start gap-2.5 bg-white border border-[#E3DDF8] rounded-xl p-3 text-xs font-medium text-[#171638]"
                >
                  <CheckCircle2 className="w-4 h-4 text-[#22B982] shrink-0 mt-0.5" />
                  <span>{point}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── 2. CORE SECURITY CAPABILITIES ────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <Badge tone="purple">2. Core Security Capabilities</Badge>
          <h2 className="font-display text-3xl font-extrabold text-[#171638]">
            Comprehensive Defense-in-Depth for Agentic AI
          </h2>
          <p className="text-sm text-[#666581]">
            Six synchronized security planes protecting every tool invocation from ingress to audit.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {CAPABILITIES.map((cap) => {
            const Icon = cap.icon;
            return (
              <Card key={cap.title} hover className="p-6 flex flex-col justify-between gap-4">
                <div className="space-y-3">
                  <div className="w-11 h-11 rounded-2xl bg-[#EAE6FF] border border-[#DCD5FF] text-[#6654E8] flex items-center justify-center">
                    <Icon className="w-5 h-5" />
                  </div>
                  <h3 className="text-lg font-bold text-[#171638]">{cap.title}</h3>
                  <p className="text-sm text-[#666581] leading-relaxed">{cap.desc}</p>
                </div>
                <Link
                  to="/features"
                  className="inline-flex items-center gap-1 text-xs font-semibold text-[#6654E8] hover:underline"
                >
                  Explore capability <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </Card>
            );
          })}
        </div>
      </section>

      {/* ── 3. HOW CERBERUS WORKS ────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="cerberus-card p-8 sm:p-10 bg-gradient-to-br from-white via-white to-[#F3F0FF] space-y-8">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div className="space-y-2">
              <Badge tone="primary">3. How CERBERUS Works</Badge>
              <h2 className="font-display text-2xl sm:text-3xl font-extrabold text-[#171638]">
                Three-Stage Real-Time Interception Pipeline
              </h2>
            </div>
            <Link to="/docs#mcp-integration">
              <Button variant="outline" size="sm">
                Read Integration Guide <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              {
                step: '01',
                title: 'Intercept, Verify & Scrub',
                text: 'Every JSON-RPC tools/call frame passes through HMAC identity verification, rate limiting, and pre-persistence SecretRedactor before touching disk.',
              },
              {
                step: '02',
                title: 'Static Scan & Cascading ML',
                text: 'SchemaPinner, ScopeAnalyzer, and LethalTrifectaDetector execute alongside a cost-aware 3-tier behavioral cascade (Rule + Markov -> Isolation Forest -> Transformer).',
              },
              {
                step: '03',
                title: 'OPA Gate & Forensic Ledger',
                text: 'OPA Rego policies arbitrate Allow, Flag, Block, or Quarantine (failing closed if OPA is down), while writing a SHA-256 hash-chained Fernet-encrypted record.',
              },
            ].map((item) => (
              <div
                key={item.step}
                className="bg-[#FAF8FF] border border-[#E3DDF8] rounded-2xl p-6 space-y-3"
              >
                <span className="inline-flex items-center justify-center w-9 h-9 rounded-xl cerberus-gradient-btn text-white font-mono text-xs font-bold">
                  {item.step}
                </span>
                <h3 className="text-base font-bold text-[#171638]">{item.title}</h3>
                <p className="text-sm text-[#666581] leading-relaxed">{item.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── 4. SYSTEM ARCHITECTURE PREVIEW ───────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <Badge tone="primary">4. System Architecture Preview</Badge>
          <h2 className="font-display text-3xl font-extrabold text-[#171638]">
            End-to-End Security Control Plane for MCP Agents
          </h2>
        </div>

        <Card className="p-6 sm:p-8 bg-gradient-to-r from-[#FAF8FF] via-white to-[#FAF8FF]">
          <div className="grid grid-cols-1 lg:grid-cols-11 gap-4 items-center">
            {/* Left: AI Agent */}
            <div className="lg:col-span-3 bg-white border border-[#E3DDF8] rounded-2xl p-6 text-center space-y-2 shadow-sm">
              <div className="w-12 h-12 rounded-2xl bg-[#EAE6FF] text-[#6654E8] flex items-center justify-center mx-auto">
                <Bot className="w-6 h-6" />
              </div>
              <h3 className="font-bold text-[#171638]">AI Agent (LLM)</h3>
              <p className="text-xs text-[#666581]">
                Claude Desktop, Cursor, or Custom LangChain Agent
              </p>
            </div>

            <div className="lg:col-span-1 flex justify-center">
              <ArrowRight className="w-6 h-6 text-[#6654E8] rotate-90 lg:rotate-0" />
            </div>

            {/* Center: CERBERUS Firewall */}
            <div className="lg:col-span-3 bg-[#F3F0FF] border-2 border-[#8C7BFA]/50 rounded-2xl p-5 space-y-3 shadow-card">
              <div className="text-center">
                <span className="text-sm font-extrabold text-[#171638] block">CERBERUS</span>
                <span className="text-[11px] font-semibold text-[#6654E8]">
                  Runtime Behavioral Firewall
                </span>
              </div>
              <div className="space-y-2">
                {[
                  { label: 'Static Scanner', icon: ShieldAlert },
                  { label: 'Behavioral Engine', icon: BrainCircuit },
                  { label: 'Policy Engine (OPA)', icon: Scale },
                  { label: 'Risk Scorer', icon: Cpu },
                ].map((mod) => {
                  const Icon = mod.icon;
                  return (
                    <div
                      key={mod.label}
                      className="flex items-center gap-2.5 bg-white border border-[#E3DDF8] rounded-xl px-3 py-2 text-xs font-semibold text-[#171638]"
                    >
                      <Icon className="w-3.5 h-3.5 text-[#6654E8]" />
                      {mod.label}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="lg:col-span-1 flex justify-center">
              <ArrowRight className="w-6 h-6 text-[#6654E8] rotate-90 lg:rotate-0" />
            </div>

            {/* Right: MCP Tools */}
            <div className="lg:col-span-3 bg-white border border-[#E3DDF8] rounded-2xl p-5 space-y-2.5 shadow-sm">
              <h3 className="font-bold text-[#171638] text-center mb-2">MCP Tool Servers</h3>
              {[
                { label: 'Files & Repos', icon: FileCode2 },
                { label: 'Databases', icon: Database },
                { label: 'External APIs', icon: Globe },
                { label: 'Cloud & Webhooks', icon: Server },
              ].map((srv) => {
                const Icon = srv.icon;
                return (
                  <div
                    key={srv.label}
                    className="flex items-center gap-2.5 bg-[#FAF8FF] border border-[#E3DDF8] rounded-xl px-3 py-2 text-xs font-medium text-[#171638]"
                  >
                    <Icon className="w-3.5 h-3.5 text-[#6654E8]" />
                    {srv.label}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-6 flex justify-center">
            <Button variant="outline" onClick={() => navigate('/architecture')}>
              Open Interactive React Flow Diagram
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </Card>
      </section>

      {/* ── 5. THREAT DEMONSTRATION PREVIEW ──────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div className="space-y-2">
            <Badge tone="danger">5. Threat Demonstration</Badge>
            <h2 className="font-display text-3xl font-extrabold text-[#171638]">
              See CERBERUS Stop Multi-Step Attacks
            </h2>
          </div>
          <Button onClick={() => navigate('/threat-lab')}>
            Launch Full 8-Scenario Threat Lab
            <ArrowRight className="w-4 h-4" />
          </Button>
        </div>

        <Card className="p-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <div className="lg:col-span-4 space-y-2">
              {THREAT_SCENARIOS.slice(0, 5).map((sc) => (
                <button
                  key={sc.id}
                  onClick={() => setPreviewScenarioId(sc.id)}
                  className={`w-full text-left px-4 py-3 rounded-xl text-sm font-semibold transition-all flex items-center justify-between ${
                    sc.id === previewScenarioId
                      ? 'cerberus-gradient-btn text-white'
                      : 'bg-[#F3F0FF] hover:bg-[#EAE6FF] text-[#171638] border border-[#E3DDF8]'
                  }`}
                >
                  <span>{sc.name}</span>
                  <span
                    className={`text-[11px] font-mono ${
                      sc.id === previewScenarioId ? 'text-white/80' : 'text-[#666581]'
                    }`}
                  >
                    {sc.steps.length} steps
                  </span>
                </button>
              ))}
            </div>

            <div className="lg:col-span-8 space-y-5 bg-[#FAF8FF] border border-[#E3DDF8] rounded-2xl p-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="text-xs font-semibold text-[#6654E8]">
                    Simulated Demonstration · {previewScenario.category}
                  </span>
                  <h3 className="text-lg font-bold text-[#171638]">{previewScenario.name}</h3>
                </div>
                <Badge
                  tone={
                    previewScenario.id === 'normal'
                      ? 'success'
                      : previewScenario.steps.some((s) => s.decision === 'quarantine')
                        ? 'purple'
                        : 'danger'
                  }
                >
                  {previewScenario.steps[previewScenario.steps.length - 1].decision.toUpperCase()}
                </Badge>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                {previewScenario.steps.map((step, i) => (
                  <React.Fragment key={i}>
                    <div
                      className={`flex-1 min-w-[155px] bg-white rounded-xl p-3.5 border ${
                        step.decision === 'block' || step.decision === 'quarantine'
                          ? 'border-[#F06478] ring-2 ring-[#F06478]/15'
                          : step.decision === 'flag'
                            ? 'border-[#F4AD42]'
                            : 'border-[#E3DDF8]'
                      }`}
                    >
                      <p className="text-[11px] font-mono text-[#666581]">Step T{i + 1}</p>
                      <p className="text-sm font-bold text-[#171638] mt-0.5">{step.label}</p>
                      <p className="text-[11px] font-mono text-[#6654E8] mt-1">
                        Risk: {step.composite_score.toFixed(2)}
                      </p>
                    </div>
                    {i < previewScenario.steps.length - 1 && (
                      <ArrowRight className="w-4 h-4 text-[#8C7BFA] shrink-0 hidden sm:block" />
                    )}
                  </React.Fragment>
                ))}
              </div>

              <p className="text-xs text-[#666581] leading-relaxed bg-white border border-[#E3DDF8] rounded-xl p-3.5">
                <strong className="text-[#171638]">Firewall Explanation: </strong>
                {previewScenario.explanation}
              </p>
            </div>
          </div>
        </Card>
      </section>

      {/* ── 6. PERFORMANCE HIGHLIGHTS ────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <Badge tone="success">6. Empirical Benchmark Highlights</Badge>
          <h2 className="font-display text-3xl font-extrabold text-[#171638]">
            Verified Sub-20ms Real-Time Enforcement
          </h2>
          <p className="text-sm text-[#666581]">
            Measured across 4 autonomous agent archetypes (Coding, Data, Support, Triage) and
            adaptive evasion replays.
          </p>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Standard Attack TPR', value: '100.0%', sub: '3/3 scenarios caught' },
            { label: 'Adversarial Evasion TPR', value: '66.7%', sub: 'Cold-start & slow-drip' },
            { label: 'P50 / P95 Latency', value: '12.2 / 14.0 ms', sub: 'Sub-15ms proxy hot path' },
            { label: 'Automated Test Suite', value: '60 / 60', sub: 'Unit, E2E, Fuzz & MCP' },
          ].map((stat) => (
            <Card key={stat.label} className="p-5">
              <span className="text-xs font-medium text-[#666581]">{stat.label}</span>
              <p className="text-2xl sm:text-3xl font-extrabold text-[#171638] mt-1 font-display">
                {stat.value}
              </p>
              <span className="text-xs text-[#6654E8] font-medium mt-1 block">{stat.sub}</span>
            </Card>
          ))}
        </div>
      </section>

      {/* ── 7. TECHNOLOGY STACK & 8. RESEARCH CONTRIBUTION ───────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 grid grid-cols-1 lg:grid-cols-12 gap-6">
        <Card className="lg:col-span-6 p-6 sm:p-8 space-y-5">
          <Badge tone="primary">7. Technology Stack</Badge>
          <h3 className="font-display text-2xl font-bold text-[#171638]">
            Production Engineering Foundation
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {TECH_STACK.map((t) => (
              <div
                key={t.name}
                className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-center gap-3"
              >
                <Layers className="w-4 h-4 text-[#6654E8] shrink-0" />
                <div>
                  <p className="text-sm font-bold text-[#171638]">{t.name}</p>
                  <p className="text-xs text-[#666581]">{t.role}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card className="lg:col-span-6 p-6 sm:p-8 space-y-5">
          <Badge tone="purple">8. Research Contribution</Badge>
          <h3 className="font-display text-2xl font-bold text-[#171638]">
            Novel Security Formulations
          </h3>
          <ul className="space-y-3 text-sm text-[#666581]">
            <li className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
              <strong className="text-[#171638]">Segregated Feature Architecture:</strong> Strict
              separation between categorical transition surprise (Markov) and continuous multivariate
              z-scores (Isolation Forest) avoids ordinal encoding bias.
            </li>
            <li className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
              <strong className="text-[#171638]">Cost-Aware Tiered Cascading:</strong> Fast Tier 1
              rules + Markov exit under 1ms for benign loops, reserving Isolation Forest and
              Sequence Transformer for ambiguous signals.
            </li>
            <li className="p-3.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8]">
              <strong className="text-[#171638]">Self-Referential Meta-Security:</strong>{' '}
              Fail-closed OPA outage circuit breaker, pre-persistence secret redaction, and TVD
              anti-poisoning baseline gates.
            </li>
          </ul>
        </Card>
      </section>

      {/* ── 9. GITHUB & DOCUMENTATION CTA ────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="rounded-3xl cerberus-gradient-btn p-8 sm:p-12 text-white flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <span className="inline-flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-white/85">
              <Terminal className="w-3.5 h-3.5" />
              Deploy in Minutes
            </span>
            <h2 className="font-display text-2xl sm:text-3xl font-extrabold">
              Ready to Guard Your Autonomous Agents?
            </h2>
            <p className="text-sm text-white/85 leading-relaxed">
              Explore the full REST &amp; MCP documentation, inspect live traffic in the Security
              Operations Center, or clone the open-source repository.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <Link
              to="/docs"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white text-[#171638] font-semibold text-sm shadow-sm hover:bg-[#F3F0FF] transition-colors"
            >
              <BookOpen className="w-4 h-4 text-[#6654E8]" />
              Documentation
            </Link>
            <a
              href="https://github.com/Debddj/Cerberus"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/15 hover:bg-white/25 border border-white/30 text-white font-semibold text-sm transition-colors"
            >
              <GitBranch className="w-4 h-4" />
              View on GitHub
            </a>
          </div>
        </div>
      </section>
    </div>
  );
};

