import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { CerberusLogo } from '../../components/brand/CerberusLogo';
import { MountainBackdrop } from '../../components/brand/MountainBackdrop';
import { ThreeFirewallCanvas } from '../../components/ThreeFirewallCanvas';
import { Button } from '../../components/ui/Button';
import { Badge } from '../../components/ui/Badge';
import {
  Shield,
  ArrowRight,
  Zap,
  Activity,
  Lock,
  Eye,
  CheckCircle2,
  Terminal,
  Cpu,
  Layers,
  Sparkles,
  AlertTriangle,
  FileCode,
  Network,
  ExternalLink,
  ChevronRight,
  Play,
  RotateCcw
} from 'lucide-react';
import { SEEDED_EVENTS } from '../../services/api';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeScenario, setActiveScenario] = useState<number>(0);
  const [simulationRunning, setSimulationRunning] = useState<boolean>(false);
  const [simulatedVerdict, setSimulatedVerdict] = useState<string | null>(null);

  const scenarios = [
    {
      title: 'The Lethal Trifecta (Toxic Flow)',
      tag: 'ASI01 • ASI06 • ASI08',
      desc: 'Agent reads .env file, parses AWS tokens, and attempts outbound exfiltration through http_post to rogue C2.',
      rule: 1.0,
      markov: 0.94,
      isolation: 0.88,
      transformer: 0.97,
      decision: 'BLOCK',
      color: '#B91C1C'
    },
    {
      title: 'Mimicry vs Taint Provenance DAG',
      tag: 'TAINT • PROVENANCE',
      desc: 'Untrusted GitHub issue payload flows into git commit. Attacker crafts normal-looking traffic, defeated by SHA-256 lineage token.',
      rule: 1.0,
      markov: 0.28,
      isolation: 0.22,
      transformer: 0.31,
      decision: 'BLOCK (Taint Override)',
      color: '#7C3AED'
    },
    {
      title: 'ASI10 Honeytoken Canary Decoy',
      tag: 'CANARY • QUARANTINE',
      desc: 'Agent accesses decoy AWS secret key CERBERUS_CANARY_AWS_9912. O(1) hash detector trips instant quarantine.',
      rule: 1.0,
      markov: 0.72,
      isolation: 0.65,
      transformer: 0.81,
      decision: 'QUARANTINE',
      color: '#DB2777'
    },
    {
      title: 'Slow-Drip Cumulative Exfiltration',
      tag: 'EGRESS DLP • QUOTAS',
      desc: 'Agent sends 45KB bursts every 8 seconds to evade anomaly threshold. Sliding byte quota hits 500KB cap and blocks.',
      rule: 1.0,
      markov: 0.42,
      isolation: 0.48,
      transformer: 0.52,
      decision: 'BLOCK (Quota Exceeded)',
      color: '#D97706'
    }
  ];

  const handleRunSimulation = (idx: number) => {
    setActiveScenario(idx);
    setSimulationRunning(true);
    setSimulatedVerdict(null);
    setTimeout(() => {
      setSimulationRunning(false);
      setSimulatedVerdict(scenarios[idx].decision);
    }, 700);
  };

  return (
    <div className="relative overflow-hidden space-y-24 pb-24">
      {/* =========================================================================
          HERO SECTION (Matches Reference Image)
          ========================================================================= */}
      <section className="relative pt-12 pb-16 md:pt-20 md:pb-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        {/* Polygonal Lavender Mountain Silhouette Backdrop */}
        <MountainBackdrop opacity={0.9} />

        <div className="text-center relative z-10 max-w-4xl mx-auto">
          {/* Status Pill (Unslop: Sentence case, no animated pulse, calm typography) */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/95 border border-[#DDD6FE] shadow-xs mb-8 backdrop-blur-md">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span className="text-xs font-mono font-medium text-[#6654E8]">
              Guardian active
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-xs font-mono text-[#5B5882]">
              HTTP & Stdio MCP interception
            </span>
          </div>

          {/* Three-Headed Cerberus Centerpiece */}
          <div className="mb-6 flex justify-center">
            <CerberusLogo size={100} className="filter drop-shadow-xs" />
          </div>

          {/* Hero Headline (Unslop: Grounded weight, single deliberate accent, zero gradient text) */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-display font-semibold tracking-tight text-[#171638] leading-[1.12] mb-6">
            Watch. Analyze.{' '}
            <span className="text-[#6654E8]">Protect.</span>
          </h1>

          {/* Subhead */}
          <p className="text-base sm:text-lg text-[#5B5882] font-normal max-w-2xl mx-auto leading-relaxed mb-10">
            A runtime behavioral firewall for MCP-based AI agents. Intercepts multi-step tool-call attack chains, tracks data taint provenance, trips canary honeytokens, and enforces fail-closed policy gates in real time.
          </p>

          {/* Action Buttons Row (Unslop: Disciplined nested radii, no bouncy springs) */}
          <div className="flex flex-wrap items-center justify-center gap-3.5 mb-16">
            <Button
              variant="brand"
              size="lg"
              className="rounded-xl px-7 py-3 text-sm shadow-xs hover:bg-[#5543D6] transition-colors"
              rightIcon={<ArrowRight className="w-4 h-4" />}
              onClick={() => navigate('/dashboard')}
            >
              Get Started
            </Button>

            <Button
              variant="outline"
              size="lg"
              className="rounded-xl px-6 py-3 text-sm border-[#DDD6FE] text-[#171638] hover:bg-white hover:border-[#C4B5FD] transition-colors"
              leftIcon={<Layers className="w-4 h-4 text-[#6654E8]" />}
              onClick={() => navigate('/architecture')}
            >
              Explore Architecture
            </Button>

            <Button
              variant="secondary"
              size="lg"
              className="rounded-xl px-6 py-3 text-sm text-[#6654E8] bg-white border border-[#EDE9FE] hover:bg-[#F5F3FF] transition-colors"
              leftIcon={<Play className="w-3.5 h-3.5 fill-current" />}
              onClick={() => navigate('/threat-lab')}
            >
              View Demo
            </Button>
          </div>

          {/* 3 Metrics Summary Cards (Unslop: Sentence case, tabular figures, no bouncy hover scale) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto text-left">
            <div className="p-5 rounded-xl bg-white/95 border border-[#EDE9FE] shadow-xs backdrop-blur-md">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-medium text-[#5B5882]">
                  Attack catch
                </span>
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
              </div>
              <div className="text-2xl sm:text-3xl font-display font-semibold text-[#171638] tracking-tight tabular-nums">
                100.0%
              </div>
              <p className="text-xs text-[#8E8AA7] mt-1 font-mono">
                0% false negatives on toxic flow
              </p>
            </div>

            <div className="p-5 rounded-xl bg-white/95 border border-[#EDE9FE] shadow-xs backdrop-blur-md">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-medium text-[#5B5882]">
                  P95 latency
                </span>
                <span className="w-2 h-2 rounded-full bg-sky-500" />
              </div>
              <div className="text-2xl sm:text-3xl font-display font-semibold text-[#171638] tracking-tight tabular-nums">
                14.02 ms
              </div>
              <p className="text-xs text-[#8E8AA7] mt-1 font-mono">
                Average proxy evaluation overhead
              </p>
            </div>

            <div className="p-5 rounded-xl bg-white/95 border border-[#EDE9FE] shadow-xs backdrop-blur-md">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-medium text-[#5B5882]">
                  Policy gate
                </span>
                <span className="w-2 h-2 rounded-full bg-[#7C3AED]" />
              </div>
              <div className="text-2xl sm:text-3xl font-display font-semibold text-[#6654E8] tracking-tight">
                Fail-closed
              </div>
              <p className="text-xs text-[#8E8AA7] mt-1 font-mono">
                OPA Rego zero-trust enforcement
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          EMBEDDED 3D WEBGL NEURAL FIREWALL CORE SHOWCASE
          ========================================================================= */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="text-center max-w-3xl mx-auto mb-10">
          <Badge variant="primary" size="sm" className="mb-3">
            <Shield className="w-3.5 h-3.5 mr-1 text-[#7C3AED]" />
            WebGL Three.js 3D interactive topology
          </Badge>
          <h2 className="text-3xl sm:text-4xl font-display font-semibold text-[#171638] tracking-tight">
            Live 3D Neural Behavioral Firewall
          </h2>
          <p className="text-sm sm:text-base text-[#5B5882] mt-3">
            Real-time orbital visualization of MCP token traffic traversing all 5 defense layers. Drag to inspect angle, switch between camera presets, or trigger simulated attack packets.
          </p>
        </div>

        {/* Embedded Interactive 3D Canvas */}
        <div className="shadow-xs rounded-xl overflow-hidden border border-[#EDE9FE]">
          <ThreeFirewallCanvas
            theme="lavender"
            height={440}
            events={SEEDED_EVENTS}
            showControls={true}
          />
        </div>
      </section>

      {/* =========================================================================
          5 CORE DEFENSE PILLARS
          ========================================================================= */}
      <section className="py-20 bg-white/80 border-y border-[#EDE9FE] px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-14">
            <span className="text-xs font-mono font-medium text-[#6654E8] bg-[#EDE9FE] px-3 py-1 rounded-md border border-[#DDD6FE]">
              Architecture foundations
            </span>
            <h2 className="text-3xl sm:text-4xl font-display font-semibold text-[#171638] mt-3 tracking-tight">
              Five Architectural Pillars of Zero-Trust
            </h2>
            <p className="text-sm sm:text-base text-[#5B5882] mt-2">
              Cerberus combines statistical anomaly detection with deterministic cryptographic guards.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5">
            {/* Pillar 1 */}
            <div className="p-5 rounded-xl bg-[#F5F3FF]/80 border border-[#EDE9FE] hover:border-[#DDD6FE] transition-colors">
              <div className="w-9 h-9 rounded-lg bg-white flex items-center justify-center text-[#6654E8] shadow-xs mb-3.5 border border-[#EDE9FE]">
                <Eye className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-mono font-medium text-[#8E8AA7]">
                Pillar 01
              </span>
              <h3 className="text-base font-semibold text-[#171638] mt-1 mb-1.5">Observe</h3>
              <p className="text-xs text-[#5B5882] leading-relaxed">
                Full-spectrum JSON-RPC proxy intercepting stdio & HTTP tool calls, calculating parameter Shannon entropy, and sanitizing payloads.
              </p>
            </div>

            {/* Pillar 2 */}
            <div className="p-5 rounded-xl bg-[#F5F3FF]/80 border border-[#EDE9FE] hover:border-[#DDD6FE] transition-colors">
              <div className="w-9 h-9 rounded-lg bg-white flex items-center justify-center text-[#7C3AED] shadow-xs mb-3.5 border border-[#EDE9FE]">
                <Cpu className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-mono font-medium text-[#8E8AA7]">
                Pillar 02
              </span>
              <h3 className="text-base font-semibold text-[#171638] mt-1 mb-1.5">Analyze</h3>
              <p className="text-xs text-[#5B5882] leading-relaxed">
                4-layer ML ensemble (Rule heuristics, Markov transition matrix, Isolation Forest, Transformer) paired with SHA-256 Taint DAG.
              </p>
            </div>

            {/* Pillar 3 */}
            <div className="p-5 rounded-xl bg-[#F5F3FF]/80 border border-[#EDE9FE] hover:border-[#DDD6FE] transition-colors">
              <div className="w-9 h-9 rounded-lg bg-white flex items-center justify-center text-[#B91C1C] shadow-xs mb-3.5 border border-[#EDE9FE]">
                <Lock className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-mono font-medium text-[#8E8AA7]">
                Pillar 03
              </span>
              <h3 className="text-base font-semibold text-[#171638] mt-1 mb-1.5">Enforce</h3>
              <p className="text-xs text-[#5B5882] leading-relaxed">
                Sub-millisecond Open Policy Agent (OPA) Rego v1 evaluation with automated circuit-breakers ensuring strict fail-closed safety.
              </p>
            </div>

            {/* Pillar 4 */}
            <div className="p-5 rounded-xl bg-[#F5F3FF]/80 border border-[#EDE9FE] hover:border-[#DDD6FE] transition-colors">
              <div className="w-9 h-9 rounded-lg bg-white flex items-center justify-center text-[#0284C7] shadow-xs mb-3.5 border border-[#EDE9FE]">
                <FileCode className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-mono font-medium text-[#8E8AA7]">
                Pillar 04
              </span>
              <h3 className="text-base font-semibold text-[#171638] mt-1 mb-1.5">Investigate</h3>
              <p className="text-xs text-[#5B5882] leading-relaxed">
                Tamper-evident cryptographic ledger with Merkle SHA-256 hash chaining, Fernet log encryption, and automated narrative export.
              </p>
            </div>

            {/* Pillar 5 */}
            <div className="p-5 rounded-xl bg-[#F5F3FF]/80 border border-[#EDE9FE] hover:border-[#DDD6FE] transition-colors">
              <div className="w-9 h-9 rounded-lg bg-white flex items-center justify-center text-[#D97706] shadow-xs mb-3.5 border border-[#EDE9FE]">
                <Activity className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-mono font-medium text-[#8E8AA7]">
                Pillar 05
              </span>
              <h3 className="text-base font-semibold text-[#171638] mt-1 mb-1.5">Adapt</h3>
              <p className="text-xs text-[#5B5882] leading-relaxed">
                Continuous online streaming scaler refitting, Total Variation Distance (TVD) baseline drift monitoring, and closed-loop Rego synthesizer.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          6 ENTERPRISE CAPABILITIES GRID
          ========================================================================= */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="text-center max-w-3xl mx-auto mb-14">
          <Badge variant="primary" size="sm" className="mb-3">
            Industry-grade security
          </Badge>
          <h2 className="text-3xl sm:text-4xl font-display font-semibold text-[#171638] tracking-tight">
            Comprehensive Defense Against Agentic Attacks
          </h2>
          <p className="text-sm sm:text-base text-[#5B5882] mt-3">
            Designed for modern AI development environments using Anthropic Claude, Cursor, Google Gemini, and custom MCP tool hosts.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Card 1 */}
          <div className="p-6 rounded-xl bg-white border border-[#EDE9FE] shadow-xs">
            <div className="w-10 h-10 rounded-lg bg-[#EDE9FE] flex items-center justify-center text-[#6654E8] mb-4">
              <Network className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-[#171638] mb-1.5">
              Multi-Step Kill-Chain Interception
            </h3>
            <p className="text-xs text-[#5B5882] leading-relaxed mb-3.5">
              Defeats toxic tool combinations (e.g., File Read → Prompt Injection → Exfiltration Sink) by modeling Markov state transitions and cross-tool parameter entropy.
            </p>
            <span className="text-[11px] font-mono font-medium text-[#6654E8]">
              OWASP ASI01 • ASI06 • ASI08
            </span>
          </div>

          {/* Card 2 */}
          <div className="p-6 rounded-xl bg-white border border-[#EDE9FE] shadow-xs">
            <div className="w-10 h-10 rounded-lg bg-[#EDE9FE] flex items-center justify-center text-[#7C3AED] mb-4">
              <Shield className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-[#171638] mb-1.5">
              Taint & Provenance Tracking DAG
            </h3>
            <p className="text-xs text-[#5B5882] leading-relaxed mb-3.5">
              Fingerprints untrusted web content, issue bodies, and email attachments with cryptographic taint tags. Blocks statistical mimicry attacks deterministically.
            </p>
            <span className="text-[11px] font-mono font-medium text-[#7C3AED]">
              SHA-256 Provenance • 1.0 BLOCK Override
            </span>
          </div>

          {/* Card 3 */}
          <div className="p-6 rounded-xl bg-white border border-[#EDE9FE] shadow-xs">
            <div className="w-10 h-10 rounded-lg bg-[#EDE9FE] flex items-center justify-center text-[#DB2777] mb-4">
              <Zap className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-[#171638] mb-1.5">
              ASI10 Canary Honeytokens
            </h3>
            <p className="text-xs text-[#5B5882] leading-relaxed mb-3.5">
              Plants decoy AWS credentials, .env.canary tokens, and database secrets. Any agent attempt to read or egress a honeytoken triggers instant auto-quarantine.
            </p>
            <span className="text-[11px] font-mono font-medium text-[#DB2777]">
              O(1) Hash Lookup • Auto-Quarantine
            </span>
          </div>

          {/* Card 4 */}
          <div className="p-6 rounded-xl bg-white border border-[#EDE9FE] shadow-xs">
            <div className="w-10 h-10 rounded-lg bg-[#EDE9FE] flex items-center justify-center text-[#D97706] mb-4">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-[#171638] mb-1.5">
              Egress DLP & Sliding Quotas
            </h3>
            <p className="text-xs text-[#5B5882] leading-relaxed mb-3.5">
              Neutralizes slow-drip data exfiltration with 500 KB / 60s sliding window byte quotas and destination caps. Real-time PII & API key regex scanner.
            </p>
            <span className="text-[11px] font-mono font-medium text-[#D97706]">
              Deterministic Sliding Window Guard
            </span>
          </div>

          {/* Card 5 */}
          <div className="p-6 rounded-xl bg-white border border-[#EDE9FE] shadow-xs">
            <div className="w-10 h-10 rounded-lg bg-[#EDE9FE] flex items-center justify-center text-[#0284C7] mb-4">
              <Eye className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-[#171638] mb-1.5">
              Response Shield & LLM Adjudicator
            </h3>
            <p className="text-xs text-[#5B5882] leading-relaxed mb-3.5">
              Inspects tool results and server schemas for hidden prompt injections, system prompt overrides, and markdown beacon leaks before reflection into agent context.
            </p>
            <span className="text-[11px] font-mono font-medium text-[#0284C7]">
              Async Context Reflection Defense
            </span>
          </div>

          {/* Card 6 */}
          <div className="p-6 rounded-xl bg-white border border-[#EDE9FE] shadow-xs">
            <div className="w-10 h-10 rounded-lg bg-[#EDE9FE] flex items-center justify-center text-[#CA8A04] mb-4">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-[#171638] mb-1.5">
              Cryptographic Step-Up Gate
            </h3>
            <p className="text-xs text-[#5B5882] leading-relaxed mb-3.5">
              Pauses borderline or destructive tool calls for human-in-the-loop operator approval via HMAC-SHA256 bearer tokens and Slack Block-Kit webhooks with fail-closed TTLs.
            </p>
            <span className="text-[11px] font-mono font-medium text-[#CA8A04]">
              HMAC Approval • 60s Fail-Closed Timeout
            </span>
          </div>
        </div>
      </section>

      {/* =========================================================================
          INTERACTIVE THREAT LAB SIMULATION PREVIEW
          ========================================================================= */}
      <section className="py-20 bg-[#EDE9FE]/40 border-t border-[#DDD6FE] px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <Badge variant="primary" size="sm" className="mb-2">
              Interactive Simulation
            </Badge>
            <h2 className="text-3xl font-display font-black text-[#171638] mt-2">
              Test Cerberus Against Real Attack Scenarios
            </h2>
            <p className="text-sm text-[#5B5882] mt-2">
              Select an attack vector below to see how Cerberus’s multi-layered scoring pipeline triggers deterministic blocks.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            {/* Scenario Selector Tabs */}
            <div className="lg:col-span-5 space-y-3">
              {scenarios.map((sc, i) => (
                <div
                  key={sc.title}
                  onClick={() => handleRunSimulation(i)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${activeScenario === i
                      ? 'bg-white border-[#6654E8] shadow-lavender-md translate-x-1'
                      : 'bg-white/70 border-[#EDE9FE] hover:bg-white hover:border-[#DDD6FE]'
                    }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-semibold text-[#6654E8]">{sc.tag}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600">
                      Scenario #{i + 1}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-[#171638]">{sc.title}</h4>
                  <p className="text-xs text-[#5B5882] mt-1 line-clamp-2">{sc.desc}</p>
                </div>
              ))}
            </div>

            {/* Live Scoring Breakdown Panel */}
            <div className="lg:col-span-7 bg-white rounded-2xl border border-[#EDE9FE] p-6 shadow-lavender-lg">
              <div className="flex items-center justify-between pb-4 border-b border-[#EDE9FE]">
                <div>
                  <span className="text-xs font-mono text-[#8E8AA7] uppercase tracking-wider block">
                    Telemetry Forensics Inspection
                  </span>
                  <h3 className="text-lg font-bold text-[#171638] mt-0.5">
                    {scenarios[activeScenario].title}
                  </h3>
                </div>
                <Button
                  variant="brand"
                  size="sm"
                  disabled={simulationRunning}
                  leftIcon={<Sparkles className="w-3.5 h-3.5 text-amber-300" />}
                  onClick={() => handleRunSimulation(activeScenario)}
                >
                  {simulationRunning ? 'Evaluating...' : 'Rerun Simulation'}
                </Button>
              </div>

              {/* 4-Layer Scoring Meters */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 my-6">
                <div className="p-3 rounded-xl bg-[#F5F3FF] border border-[#EDE9FE] text-center">
                  <span className="text-[10px] font-mono text-[#5B5882] uppercase block">Rule Scorer</span>
                  <span className="text-xl font-bold font-mono text-[#6654E8] block mt-1">
                    {(scenarios[activeScenario].rule * 100).toFixed(0)}%
                  </span>
                  <span className="text-[9px] font-mono text-[#8E8AA7]">Pre-baseline</span>
                </div>
                <div className="p-3 rounded-xl bg-[#F5F3FF] border border-[#EDE9FE] text-center">
                  <span className="text-[10px] font-mono text-[#5B5882] uppercase block">Markov Matrix</span>
                  <span className="text-xl font-bold font-mono text-[#7C3AED] block mt-1">
                    {(scenarios[activeScenario].markov * 100).toFixed(0)}%
                  </span>
                  <span className="text-[9px] font-mono text-[#8E8AA7]">Sequence surprise</span>
                </div>
                <div className="p-3 rounded-xl bg-[#F5F3FF] border border-[#EDE9FE] text-center">
                  <span className="text-[10px] font-mono text-[#5B5882] uppercase block">Isolation Forest</span>
                  <span className="text-xl font-bold font-mono text-[#0284C7] block mt-1">
                    {(scenarios[activeScenario].isolation * 100).toFixed(0)}%
                  </span>
                  <span className="text-[9px] font-mono text-[#8E8AA7]">Continuous Z-Score</span>
                </div>
                <div className="p-3 rounded-xl bg-[#F5F3FF] border border-[#EDE9FE] text-center">
                  <span className="text-[10px] font-mono text-[#5B5882] uppercase block">Transformer</span>
                  <span className="text-xl font-bold font-mono text-[#DB2777] block mt-1">
                    {(scenarios[activeScenario].transformer * 100).toFixed(0)}%
                  </span>
                  <span className="text-[9px] font-mono text-[#8E8AA7]">Attention window</span>
                </div>
              </div>

              {/* Firewall Decision Output */}
              <div className="p-4 rounded-xl bg-slate-900 text-white font-mono text-xs flex items-center justify-between">
                <div>
                  <span className="text-slate-400 block text-[10px]">CERBERUS RUNTIME VERDICT</span>
                  <span className="text-sm font-bold text-rose-400">
                    DECISION: {scenarios[activeScenario].decision}
                  </span>
                </div>
                <div className="px-3 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[11px]">
                  FAIL-CLOSED ENFORCED
                </div>
              </div>

              <div className="mt-4 text-center">
                <Link
                  to="/threat-lab"
                  className="text-xs font-semibold text-[#6654E8] hover:text-[#5543D6] inline-flex items-center gap-1"
                >
                  Open Full Interactive 8-Scenario Threat Lab <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          FINAL CALL TO ACTION BANNER
          ========================================================================= */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="rounded-3xl bg-gradient-to-r from-[#6654E8] via-[#7C3AED] to-[#5543D6] p-10 sm:p-16 text-center text-white relative overflow-hidden shadow-lavender-lg">
          <div className="relative z-10 max-w-2xl mx-auto space-y-6">
            <h2 className="text-3xl sm:text-5xl font-display font-black tracking-tight">
              Ready to Fortify Your AI Agents?
            </h2>
            <p className="text-base sm:text-lg text-purple-100 font-normal leading-relaxed">
              Integrate the Cerberus runtime behavioral proxy into your existing MCP client in under 2 minutes. Protect against prompt injections, toxic multi-step flows, and exfiltration leaks.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
              <Button
                variant="outline"
                size="lg"
                className="rounded-full bg-white text-[#171638] hover:bg-[#F5F3FF] border-white shadow-lg px-8 py-4 font-semibold"
                rightIcon={<ArrowRight className="w-4 h-4 text-[#6654E8]" />}
                onClick={() => navigate('/dashboard')}
              >
                Launch SOC Console
              </Button>
              <Button
                variant="ghost"
                size="lg"
                className="rounded-full border border-purple-200/50 text-white hover:bg-white/10 px-7 py-4"
                leftIcon={<Terminal className="w-4 h-4" />}
                onClick={() => navigate('/docs')}
              >
                Read Developer Docs
              </Button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};