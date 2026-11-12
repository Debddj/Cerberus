import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  BarChart3,
  BrainCircuit,
  CheckCircle2,
  FileCheck2,
  GitMerge,
  Scale,
  ScanSearch,
  ShieldCheck,
  UserCheck,
} from 'lucide-react';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card } from '../../components/ui/Card';
import { Modal } from '../../components/ui/Modal';

interface FeatureItem {
  id: string;
  title: string;
  tagline: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  highlights: string[];
  deepDive: string;
  socRoute: string;
  socLabel: string;
}

const FEATURES: FeatureItem[] = [
  {
    id: 'runtime-protection',
    title: 'Runtime Protection',
    tagline: 'Transparent HTTP & Stdio MCP Interception',
    description:
      'Intercepts and validates every JSON-RPC tool invocation before execution across remote HTTP gateways and local subprocess stdio wrappers.',
    icon: ShieldCheck,
    highlights: [
      'HMAC-SHA256 verified agent identities & permissive mode tagging',
      'Sliding-window per-tenant rate limiting',
      'Pre-persistence SecretRedactor scrubbing AWS, OpenAI, GitHub PAT & RSA keys',
    ],
    deepDive:
      'CerberusProxyEngine normalizes each MCP tools/call into a ToolCallEvent, measures payload byte length and Shannon entropy, scrubs sensitive tokens before logging or forwarding, and enforces decisions synchronously on the proxy hot path.',
    socRoute: '/dashboard/monitoring',
    socLabel: 'Open Live Monitoring',
  },
  {
    id: 'static-scanning',
    title: 'Static Security Scanning',
    tagline: 'Deterministic Pre-Flight Guardrails',
    description:
      'Verifies SHA-256 tool schema pins, enforces least-privilege tool scopes, blocks cross-server tool shadowing, and tracks Lethal Trifecta capability unions.',
    icon: ScanSearch,
    highlights: [
      'SchemaPinner detects mid-session rug-pull description mutations',
      'ScopeAnalyzer supports learn & strict fail-closed modes',
      'ShadowDetector prevents lookalike MCP servers masquerading trusted tools',
    ],
    deepDive:
      'During tools/list discovery, Cerberus computes canonical SHA-256 hashes of every tool description and inputSchema stored in SQLite. Any runtime deviation trips rug_pull.rego immediately.',
    socRoute: '/dashboard/agents',
    socLabel: 'Inspect Agent Scopes',
  },
  {
    id: 'behavioural-intelligence',
    title: 'Behavioural Intelligence',
    tagline: '4-Member Cascading ML Ensemble',
    description:
      'Detects sequence-level intent drift by combining deterministic floor rules, Markov transition surprise, Isolation Forest outliers, and Sequence Transformer loss.',
    icon: BrainCircuit,
    highlights: [
      'Tier 1 (<1ms): Rule-Based Floor + 1st-Order Markov Chain',
      'Tier 2: Per-agent Isolation Forest over continuous z-scaled telemetry',
      'Tier 3: Sequence Transformer neural autoencoder for deep temporal drift',
    ],
    deepDive:
      'A high-threat circuit breaker bypasses linear averaging whenever any individual detector reports critical confidence (Rule >= 0.75 or ML >= 0.90), eliminating score dilution.',
    socRoute: '/dashboard/behavior',
    socLabel: 'Explore Behavioural Intelligence',
  },
  {
    id: 'policy-enforcement',
    title: 'Dynamic Policy Enforcement',
    tagline: 'OPA Rego v1 & Fail-Closed Circuit Breaker',
    description:
      'Evaluates multi-package Open Policy Agent rules in real time with a 10-second fail-closed circuit breaker when the OPA sidecar is unreachable.',
    icon: Scale,
    highlights: [
      'Base Rego bundles: behavioral, trifecta, rug_pull, privilege_escalation',
      'Interactive Rego editor, toggle controls, and dry-run simulation workbench',
      'Automated fail-closed fallback blocking elevated risk (>= 0.70)',
    ],
    deepDive:
      'Instead of failing open during policy engine outages or DoS attempts, OPAClient trips a cached 10s circuit breaker and enforces deterministic risk thresholds locally.',
    socRoute: '/dashboard/policies',
    socLabel: 'Manage Policies',
  },
  {
    id: 'forensic-audit',
    title: 'Forensic Audit',
    tagline: 'SHA-256 Hash Chain & Fernet Encryption',
    description:
      'Persists every decision into an append-only tamper-evident ledger where each block cryptographically chains to its predecessor.',
    icon: FileCheck2,
    highlights: [
      'H[i] = SHA-256(index : H[i-1] : CanonicalJSON(event))',
      'Fernet symmetric envelope encryption at rest with log rotation',
      'One-click cryptographic integrity verification from CLI or SOC UI',
    ],
    deepDive:
      'Any unauthorized deletion, insertion, or field modification on disk breaks the SHA-256 chain verification immediately and pinpoints the tampered record index.',
    socRoute: '/dashboard/audit',
    socLabel: 'Verify Audit Ledger',
  },
  {
    id: 'incident-reconstruction',
    title: 'Incident Reconstruction',
    tagline: 'Kill-Chain Narrative Timeline',
    description:
      'Automatically weaves suspicious tool-call sessions into chronological Reconnaissance, Data Staging, and Exfiltration attack timelines.',
    icon: GitMerge,
    highlights: [
      'Chronological T1..Tn step timeline with per-step risk escalation',
      'Lethal Trifecta breakdown across private data, untrusted input & egress',
      'NarrativeReconstructor formatted forensic summary & session quarantine',
    ],
    deepDive:
      'Operators can inspect sanitized payload evidence, contributing risk factors, and model breakdowns for each step in an attack trajectory from a single forensic console.',
    socRoute: '/dashboard/incidents',
    socLabel: 'Investigate Incidents',
  },
  {
    id: 'hitl-approval',
    title: 'Human-in-the-Loop Approval',
    tagline: 'Closed-Loop Least-Privilege Rego Synthesis',
    description:
      'Automatically drafts defensive Rego rules whenever a high-risk call is blocked, queueing them for security analyst review before OPA activation.',
    icon: UserCheck,
    highlights: [
      'PolicySynthesizer generates least-privilege Rego from blocked anomalies',
      'SOC Approve & Push to OPA or Reject workflow with audit history',
      'TVD stability gating prevents boiling-frog baseline poisoning',
    ],
    deepDive:
      'Cerberus never auto-applies unreviewed policies or contaminated retraining baselines; flagged sessions (risk >= 0.40) are permanently excluded from baseline snapshots.',
    socRoute: '/dashboard/policies',
    socLabel: 'Review Pending Rules',
  },
  {
    id: 'security-analytics',
    title: 'Security Analytics',
    tagline: 'Empirical Benchmarks & Latency SLAs',
    description:
      'Measures detection TPR, precision, recall, F1-score, false-positive rates across agent archetypes, and P50/P95/P99 runtime overhead.',
    icon: BarChart3,
    highlights: [
      'Live proxy latency percentiles & risk score histograms',
      '5-way ablation comparison from evaluation/ablation_results.json',
      'Automated 8-scenario security validation test suite',
    ],
    deepDive:
      'Separates real measured production telemetry from empirical benchmark datasets, displaying explicit pending-measurement states when no live traffic has been processed yet.',
    socRoute: '/dashboard/analytics',
    socLabel: 'View Analytics',
  },
];

export const FeaturesPage: React.FC = () => {
  const [activeFeature, setActiveFeature] = useState<FeatureItem | null>(null);
  const navigate = useNavigate();

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-12">
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <Badge tone="primary">Key Features</Badge>
        <h1 className="font-display text-4xl font-extrabold text-[#171638]">
          A Comprehensive Security Stack for Agentic AI
        </h1>
        <p className="text-base text-[#666581]">
          Every layer of CERBERUS works in concert to observe, analyze, enforce, investigate, and
          safely adapt autonomous MCP tool workflows.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {FEATURES.map((feat) => {
          const Icon = feat.icon;
          return (
            <Card key={feat.id} hover className="p-6 flex flex-col justify-between gap-5">
              <div className="space-y-3">
                <div className="w-12 h-12 rounded-2xl bg-[#EAE6FF] border border-[#DCD5FF] text-[#6654E8] flex items-center justify-center">
                  <Icon className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-[#171638]">{feat.title}</h2>
                  <p className="text-xs font-semibold text-[#6654E8] mt-0.5">{feat.tagline}</p>
                </div>
                <p className="text-sm text-[#666581] leading-relaxed">{feat.description}</p>
              </div>

              <button
                onClick={() => setActiveFeature(feat)}
                className="inline-flex items-center gap-1.5 text-xs font-bold text-[#6654E8] hover:text-[#5240D6] pt-2 border-t border-[#F3F0FF]"
              >
                <span>Learn More</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </Card>
          );
        })}
      </div>

      <Card className="p-8 bg-gradient-to-r from-[#FAF8FF] to-[#EDE9FE] flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl cerberus-gradient-btn text-white flex items-center justify-center shrink-0">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-[#171638]">
              Test Every Security Layer Live in the Threat Lab
            </h3>
            <p className="text-sm text-[#666581] mt-1">
              Step through 8 realistic MCP attack scenarios and inspect real-time model scores and
              OPA enforcement verdicts.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <Button variant="outline" onClick={() => navigate('/architecture')}>
            System Architecture
          </Button>
          <Button onClick={() => navigate('/threat-lab')}>
            Open Threat Lab <ArrowRight className="w-4 h-4" />
          </Button>
        </div>
      </Card>

      <Modal
        open={Boolean(activeFeature)}
        onClose={() => setActiveFeature(null)}
        title={activeFeature?.title || ''}
        subtitle={activeFeature?.tagline}
        maxWidth="max-w-xl"
      >
        {activeFeature && (
          <div className="space-y-5">
            <p className="text-sm text-[#666581] leading-relaxed">{activeFeature.deepDive}</p>

            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#171638]">
                Implemented Capabilities
              </h4>
              {activeFeature.highlights.map((h) => (
                <div
                  key={h}
                  className="flex items-start gap-2.5 p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-xs text-[#171638]"
                >
                  <CheckCircle2 className="w-4 h-4 text-[#22B982] shrink-0 mt-0.5" />
                  <span>{h}</span>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-2">
              <Button variant="outline" onClick={() => setActiveFeature(null)}>
                Close
              </Button>
              <Button
                onClick={() => {
                  const route = activeFeature.socRoute;
                  setActiveFeature(null);
                  navigate(route);
                }}
              >
                {activeFeature.socLabel}
                <ArrowRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

