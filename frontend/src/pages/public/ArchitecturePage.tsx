import React, { useMemo, useState } from 'react';
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Activity,
  Bot,
  BrainCircuit,
  Cpu,
  Database,
  FileCheck2,
  GitBranch,
  Globe,
  Lock,
  Radio,
  Scale,
  ScanSearch,
  Server,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { Badge } from '../../components/ui/Badge';
import { Card } from '../../components/ui/Card';

interface ArchNodeData extends Record<string, unknown> {
  title: string;
  subtitle: string;
  modulePath: string;
  details: string;
  category: 'ingress' | 'security' | 'decision' | 'egress' | 'observability';
  iconName: string;
}

const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  bot: Bot,
  globe: Globe,
  terminal: Terminal,
  lock: Lock,
  scan: ScanSearch,
  brain: BrainCircuit,
  cpu: Cpu,
  scale: Scale,
  shield: ShieldCheck,
  server: Server,
  ledger: FileCheck2,
  soc: Activity,
};

const CATEGORY_STYLE: Record<ArchNodeData['category'], string> = {
  ingress: 'border-[#DCD5FF] bg-white',
  security: 'border-[#8C7BFA]/60 bg-[#FAF8FF]',
  decision: 'border-[#6654E8] bg-[#EAE6FF]',
  egress: 'border-[#22B982]/50 bg-white',
  observability: 'border-[#F4AD42]/60 bg-[#FFFBF2]',
};

const CerberusArchNode: React.FC<NodeProps<Node<ArchNodeData>>> = ({ data, selected }) => {
  const Icon = ICON_MAP[data.iconName] || ShieldCheck;
  return (
    <div
      className={`px-4 py-3 rounded-2xl border-2 shadow-card min-w-[215px] max-w-[240px] transition-all ${
        CATEGORY_STYLE[data.category]
      } ${selected ? 'ring-4 ring-[#6654E8]/25 scale-[1.02]' : ''}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-[#6654E8] !w-2.5 !h-2.5" />
      <Handle type="target" position={Position.Left} id="left" className="!bg-[#8C7BFA] !w-2 !h-2" />
      <div className="flex items-start gap-2.5">
        <div className="w-8 h-8 rounded-xl bg-[#EAE6FF] text-[#6654E8] flex items-center justify-center shrink-0">
          <Icon className="w-4 h-4" />
        </div>
        <div className="min-w-0">
          <p className="text-xs font-bold text-[#171638] leading-tight">{data.title}</p>
          <p className="text-[11px] text-[#666581] mt-0.5 leading-snug">{data.subtitle}</p>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-[#6654E8] !w-2.5 !h-2.5" />
      <Handle type="source" position={Position.Right} id="right" className="!bg-[#8C7BFA] !w-2 !h-2" />
    </div>
  );
};

const NODE_TYPES = { cerberusNode: CerberusArchNode };

const INITIAL_NODES: Node<ArchNodeData>[] = [
  {
    id: 'agent',
    type: 'cerberusNode',
    position: { x: 260, y: 10 },
    data: {
      title: 'AI Agent',
      subtitle: 'Claude Desktop, Cursor, or LangChain loop',
      modulePath: 'sandbox/agents/*',
      details:
        'Issues MCP JSON-RPC requests (tools/list and tools/call) over HTTP or local subprocess stdio.',
      category: 'ingress',
      iconName: 'bot',
    },
  },
  {
    id: 'http-gw',
    type: 'cerberusNode',
    position: { x: 10, y: 110 },
    data: {
      title: 'HTTP Gateway',
      subtitle: 'POST / & POST /mcp JSON-RPC',
      modulePath: 'src/cerberus/proxy/server.py',
      details:
        'FastAPI async reverse proxy accepting JSON-RPC envelopes, X-Agent-ID, X-Session-ID, and HMAC headers.',
      category: 'ingress',
      iconName: 'globe',
    },
  },
  {
    id: 'stdio-proxy',
    type: 'cerberusNode',
    position: { x: 510, y: 110 },
    data: {
      title: 'STDIO Proxy',
      subtitle: 'Persistent ClientSession wrapper',
      modulePath: 'src/cerberus/proxy/stdio_server.py',
      details:
        'Wraps local child MCP servers via the official MCP Python SDK without exposing upstream stdio directly.',
      category: 'ingress',
      iconName: 'terminal',
    },
  },
  {
    id: 'proxy',
    type: 'cerberusNode',
    position: { x: 260, y: 130 },
    data: {
      title: 'CERBERUS Runtime Proxy',
      subtitle: 'Unified interception & session tracking',
      modulePath: 'CerberusProxyEngine.process_tool_call',
      details:
        'Normalizes calls into ToolCallEvent with monotonic sequence numbers, inter-call delta timing, and session windows.',
      category: 'security',
      iconName: 'shield',
    },
  },
  {
    id: 'auth-redactor',
    type: 'cerberusNode',
    position: { x: 260, y: 245 },
    data: {
      title: 'Auth & Secret Redaction',
      subtitle: 'HMAC-SHA256, rate limit & regex scrub',
      modulePath: 'src/cerberus/proxy/auth.py & redactor.py',
      details:
        'Verifies signed agent tokens, enforces per-tenant sliding-window rate quotas, and scrubs OpenAI/AWS/GitHub/RSA secrets before logging.',
      category: 'security',
      iconName: 'lock',
    },
  },
  {
    id: 'static-scanner',
    type: 'cerberusNode',
    position: { x: 260, y: 360 },
    data: {
      title: 'Static Security Scanner',
      subtitle: 'Schema Pinning, Scope, Shadow, Trifecta',
      modulePath: 'src/cerberus/scanner/*',
      details:
        'Executes deterministic SHA-256 schema pin verification, agent tool scope checks, cross-server shadow detection, and Lethal Trifecta tracking.',
      category: 'security',
      iconName: 'scan',
    },
  },
  {
    id: 'behavior-engine',
    type: 'cerberusNode',
    position: { x: 260, y: 475 },
    data: {
      title: 'Behavioural Analysis Engine',
      subtitle: 'Rules + Markov + Isolation Forest + Transformer',
      modulePath: 'src/cerberus/behavioral/scorers/*',
      details:
        'Runs the 3-tier cost-aware cascade: Tier 1 Rules + Markov (<1ms), Tier 2 Isolation Forest, Tier 3 Sequence Transformer Autoencoder.',
      category: 'security',
      iconName: 'brain',
    },
  },
  {
    id: 'models-side',
    type: 'cerberusNode',
    position: { x: 545, y: 475 },
    data: {
      title: 'Behavioural Models & Store',
      subtitle: 'Versioned Snapshots + TVD Anti-Poisoning',
      modulePath: 'src/cerberus/behavioral/baseline_store.py',
      details:
        'Persists immutable per-agent baselines and rejects poisoned baseline promotions whose Total Variation Distance exceeds max_divergence.',
      category: 'observability',
      iconName: 'cpu',
    },
  },
  {
    id: 'risk-scorer',
    type: 'cerberusNode',
    position: { x: 260, y: 590 },
    data: {
      title: 'Risk Scoring Engine',
      subtitle: 'Ensemble Arbiter + Circuit Breaker',
      modulePath: 'src/cerberus/behavioral/ensemble.py',
      details:
        'Blends model scores using configured weights while escalating immediately via circuit breaker if Rule >= 0.75 or any ML >= 0.90.',
      category: 'security',
      iconName: 'cpu',
    },
  },
  {
    id: 'opa-gate',
    type: 'cerberusNode',
    position: { x: 260, y: 705 },
    data: {
      title: 'OPA Policy Decision Gate',
      subtitle: 'Rego v1 + 10s Fail-Closed Circuit Breaker',
      modulePath: 'src/cerberus/policy/opa_client.py',
      details:
        'Queries Open Policy Agent bundles (behavioral, trifecta, rug_pull, privilege_escalation); trips fail-closed enforcement on OPA outage.',
      category: 'decision',
      iconName: 'scale',
    },
  },
  {
    id: 'verdict',
    type: 'cerberusNode',
    position: { x: 260, y: 820 },
    data: {
      title: 'Allow / Flag / Block / Quarantine',
      subtitle: 'Deterministic Policy Verdict Execution',
      modulePath: 'src/cerberus/policy/enforcer.py',
      details:
        'Permits benign traffic, flags moderate drift, blocks high-risk violations (-32003), or quarantines compromised sessions and synthesizes candidate Rego rules.',
      category: 'decision',
      iconName: 'shield',
    },
  },
  {
    id: 'mcp-servers',
    type: 'cerberusNode',
    position: { x: 260, y: 940 },
    data: {
      title: 'MCP Tool Servers',
      subtitle: 'Files, Databases, APIs & Cloud Tools',
      modulePath: 'src/cerberus/proxy/forwarder.py',
      details:
        'Upstream MCP servers only receive requests that survive static scanning, behavioral scoring, and OPA policy authorization.',
      category: 'egress',
      iconName: 'server',
    },
  },
  {
    id: 'audit-ledger',
    type: 'cerberusNode',
    position: { x: 10, y: 760 },
    data: {
      title: 'Audit Ledger',
      subtitle: 'SHA-256 Hash Chain + Fernet Encryption',
      modulePath: 'src/cerberus/proxy/logger.py',
      details:
        'Writes tamper-evident blocks H[i] = SHA256(i : H[i-1] : CanonicalJSON) with automatic 10 MB rotation and cryptographic verification.',
      category: 'observability',
      iconName: 'ledger',
    },
  },
  {
    id: 'soc-dashboard',
    type: 'cerberusNode',
    position: { x: 545, y: 760 },
    data: {
      title: 'SOC Dashboard',
      subtitle: 'Live SSE Stream, Incidents & Policy UI',
      modulePath: 'frontend/src/pages/dashboard/*',
      details:
        'Real-time React 18 Security Operations Center connected via SSE (/api/events/stream) for monitoring, incident reconstruction, and Rego management.',
      category: 'observability',
      iconName: 'soc',
    },
  },
];

const edgeStyle = { stroke: '#6654E8', strokeWidth: 2 };
const sideEdgeStyle = { stroke: '#8C7BFA', strokeWidth: 1.75, strokeDasharray: '5 4' };

const INITIAL_EDGES: Edge[] = [
  { id: 'e-agent-http', source: 'agent', target: 'http-gw', animated: true, style: sideEdgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#8C7BFA' } },
  { id: 'e-agent-stdio', source: 'agent', target: 'stdio-proxy', animated: true, style: sideEdgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#8C7BFA' } },
  { id: 'e-agent-proxy', source: 'agent', target: 'proxy', animated: true, style: edgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#6654E8' } },
  { id: 'e-http-proxy', source: 'http-gw', target: 'proxy', style: sideEdgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#8C7BFA' } },
  { id: 'e-stdio-proxy', source: 'stdio-proxy', target: 'proxy', style: sideEdgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#8C7BFA' } },
  { id: 'e-proxy-auth', source: 'proxy', target: 'auth-redactor', animated: true, style: edgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#6654E8' } },
  { id: 'e-auth-scan', source: 'auth-redactor', target: 'static-scanner', animated: true, style: edgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#6654E8' } },
  { id: 'e-scan-behav', source: 'static-scanner', target: 'behavior-engine', animated: true, style: edgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#6654E8' } },
  { id: 'e-behav-models', source: 'behavior-engine', sourceHandle: 'right', target: 'models-side', targetHandle: 'left', style: sideEdgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#8C7BFA' } },
  { id: 'e-behav-risk', source: 'behavior-engine', target: 'risk-scorer', animated: true, style: edgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#6654E8' } },
  { id: 'e-risk-opa', source: 'risk-scorer', target: 'opa-gate', animated: true, style: edgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#6654E8' } },
  { id: 'e-opa-verdict', source: 'opa-gate', target: 'verdict', animated: true, style: edgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#6654E8' } },
  { id: 'e-verdict-mcp', source: 'verdict', target: 'mcp-servers', animated: true, style: { stroke: '#22B982', strokeWidth: 2.2 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#22B982' } },
  { id: 'e-verdict-audit', source: 'verdict', target: 'audit-ledger', style: sideEdgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#8C7BFA' } },
  { id: 'e-verdict-soc', source: 'verdict', sourceHandle: 'right', target: 'soc-dashboard', targetHandle: 'left', style: sideEdgeStyle, markerEnd: { type: MarkerType.ArrowClosed, color: '#8C7BFA' } },
];

export const ArchitecturePage: React.FC = () => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>('behavior-engine');
  const selectedNode = useMemo(
    () => INITIAL_NODES.find((n) => n.id === selectedNodeId) || INITIAL_NODES[3],
    [selectedNodeId]
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-10">
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <Badge tone="primary">System Architecture</Badge>
        <h1 className="font-display text-4xl font-extrabold text-[#171638]">
          End-to-End Zero-Trust Pipeline for MCP Agents
        </h1>
        <p className="text-base text-[#666581]">
          Click any component in the interactive React Flow architecture diagram below to inspect
          its runtime contract and source module.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <Card className="lg:col-span-8 overflow-hidden p-0">
          <div className="px-5 py-3.5 border-b border-[#E3DDF8] bg-[#FAF8FF] flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#171638]">
              <GitBranch className="w-4 h-4 text-[#6654E8]" />
              Interactive Interception &amp; Enforcement Graph
            </div>
            <div className="flex items-center gap-2 text-[11px] text-[#666581]">
              <span>Drag to pan · Scroll to zoom · Click node to inspect</span>
            </div>
          </div>

          <div className="h-[660px] w-full bg-[#F7F4FF]">
            <ReactFlow
              nodes={INITIAL_NODES}
              edges={INITIAL_EDGES}
              nodeTypes={NODE_TYPES}
              onNodeClick={(_, node) => setSelectedNodeId(node.id)}
              fitView
              fitViewOptions={{ padding: 0.14 }}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#DCD5FF" gap={18} />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
        </Card>

        <div className="lg:col-span-4 space-y-5">
          <Card className="p-6 space-y-4 border-2 border-[#DCD5FF]">
            <div className="flex items-center justify-between">
              <Badge tone="primary">Selected Component</Badge>
              <span className="text-[11px] font-mono text-[#666581]">
                {selectedNode.data.category.toUpperCase()}
              </span>
            </div>
            <div>
              <h2 className="text-xl font-bold text-[#171638]">{selectedNode.data.title}</h2>
              <p className="text-xs font-semibold text-[#6654E8] mt-0.5">
                {selectedNode.data.subtitle}
              </p>
            </div>
            <p className="text-sm text-[#666581] leading-relaxed">{selectedNode.data.details}</p>
            <div className="p-3 rounded-xl bg-[#F3F0FF] border border-[#E3DDF8]">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#666581] block">
                Implementation Module
              </span>
              <code className="text-xs font-mono text-[#6654E8] break-all">
                {selectedNode.data.modulePath}
              </code>
            </div>
          </Card>

          <Card className="p-6 space-y-3.5">
            <h3 className="text-sm font-bold text-[#171638]">Core Subsystems Illustrated</h3>
            {[
              {
                icon: Globe,
                title: 'HTTP Gateway',
                desc: 'FastAPI POST / & /mcp reverse proxy with HMAC verification and Prometheus /metrics.',
              },
              {
                icon: Terminal,
                title: 'STDIO Proxy',
                desc: 'Persistent MCP ClientSession wrapper for Claude Desktop, Cursor, and local CLI agents.',
              },
              {
                icon: BrainCircuit,
                title: 'Behavioural Models',
                desc: 'Rule Floor, Markov Chain, Isolation Forest, and Sequence Transformer with TVD gating.',
              },
              {
                icon: Database,
                title: 'Audit Ledger',
                desc: 'SHA-256 hash chain + Fernet envelope encryption with 10 MB automated log rotation.',
              },
              {
                icon: Radio,
                title: 'SOC Dashboard',
                desc: 'Real-time SSE telemetry stream, attack chain narratives, and Rego dry-run workbench.',
              },
            ].map((sub) => {
              const Icon = sub.icon;
              return (
                <div
                  key={sub.title}
                  className="p-3 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] flex items-start gap-3"
                >
                  <Icon className="w-4 h-4 text-[#6654E8] shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-bold text-[#171638]">{sub.title}</p>
                    <p className="text-[11px] text-[#666581] leading-relaxed mt-0.5">{sub.desc}</p>
                  </div>
                </div>
              );
            })}
          </Card>
        </div>
      </div>
    </div>
  );
};

