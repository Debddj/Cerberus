import React, { useMemo, useState } from 'react';
import { Check, Copy, Search } from 'lucide-react';
import { CerberusLogo } from '../../components/brand/CerberusLogo';
import { Badge } from '../../components/ui/Badge';
import { Card } from '../../components/ui/Card';
import { useToast } from '../../context/ToastContext';

interface DocSection {
  id: string;
  title: string;
  summary: string;
  body: string[];
  codeTitle?: string;
  code?: string;
}

const DOC_SECTIONS: DocSection[] = [
  {
    id: 'getting-started',
    title: 'Getting Started',
    summary: 'Deploy CERBERUS in minutes as a transparent HTTP or stdio MCP firewall.',
    body: [
      'CERBERUS interposes between autonomous LLM agents (Claude Desktop, Cursor, custom frameworks) and upstream MCP tool servers.',
      'It evaluates sequence-level tool trajectories, scrubs sensitive secrets before persistence, enforces Open Policy Agent (OPA) Rego guardrails, and writes SHA-256 hash-chained audit logs.',
    ],
    codeTitle: 'Quickstart Container Stack',
    code: `git clone https://github.com/Debddj/Cerberus.git\ncd Cerberus\ndocker compose up -d`,
  },
  {
    id: 'installation',
    title: 'Installation',
    summary: 'Install locally using Python 3.12+ and uv package manager.',
    body: [
      'Clone the repository, initialize an isolated virtual environment via uv, and install CERBERUS with development and evaluation tools.',
      'The React SOC console is pre-built and served automatically at /dashboard and /ui.',
    ],
    codeTitle: 'Install via uv',
    code: `uv venv\nsource .venv/bin/activate  # Windows: .venv\\Scripts\\activate\nuv pip install -e ".[dev]"`,
  },
  {
    id: 'system-requirements',
    title: 'System Requirements',
    summary: 'Supported operating systems, runtimes, and policy engine prerequisites.',
    body: [
      'Python 3.12+ (recommended) with scikit-learn, NumPy, FastAPI, Uvicorn, MCP SDK v1.28+, aiosqlite, and cryptography.',
      'Open Policy Agent (OPA v0.68+) running on localhost:8181 for live Rego evaluation; if OPA is offline, CERBERUS activates its strict 10-second fail-closed circuit breaker.',
      'Node.js 18+ is only required when rebuilding frontend/ source assets.',
    ],
  },
  {
    id: 'mcp-integration',
    title: 'MCP Integration',
    summary: 'How CERBERUS intercepts tools/list and tools/call JSON-RPC frames.',
    body: [
      'On tools/list, SchemaPinner computes canonical SHA-256 hashes of every tool description and inputSchema and persists them in SQLite (cerberus_pins.db) while ShadowDetector registers trusted server origins.',
      'On tools/call, CerberusProxyEngine executes secret redaction, static checks, 3-tier behavioral ML scoring, and OPA enforcement before forwarding approved calls.',
    ],
  },
  {
    id: 'http-gateway',
    title: 'HTTP Gateway Configuration',
    summary: 'Expose the FastAPI JSON-RPC proxy and React SOC console on port 8000.',
    body: [
      'Point your MCP client or agent orchestrator to POST http://localhost:8000/mcp with optional X-Agent-ID, X-Session-ID, and Authorization: Bearer <HMAC_TOKEN> headers.',
    ],
    codeTitle: 'Start HTTP Gateway',
    code: `uv run cerberus http --host 0.0.0.0 --port 8000\n\n# Environment overrides:\nexport CERBERUS_MODE=enforce\nexport CERBERUS_FAIL_CLOSED=true\nexport CERBERUS_OPA_URL=http://localhost:8181/v1/data`,
  },
  {
    id: 'stdio-proxy',
    title: 'STDIO Proxy Configuration',
    summary: 'Wrap local subprocess MCP servers inside Claude Desktop or Cursor.',
    body: [
      'Use cerberus stdio --upstream <CMD> to wrap any local MCP server process with full behavioral firewalling and schema pinning.',
    ],
    codeTitle: 'mcpServers.json',
    code: `{\n  "mcpServers": {\n    "filesystem-protected": {\n      "command": "uv",\n      "args": [\n        "run", "cerberus", "stdio",\n        "--upstream", "npx", "-y",\n        "@modelcontextprotocol/server-filesystem", "/workspace"\n      ]\n    }\n  }\n}`,
  },
  {
    id: 'agent-registration',
    title: 'Agent Registration',
    summary: 'Issue HMAC-SHA256 identity tokens and register allowed tool scopes.',
    body: [
      'Register agents via the SOC Agents page (/dashboard/agents) or generate signed HMAC identity tokens from the CLI.',
      'When CERBERUS_REQUIRE_SIGNED_IDENTITY=true, unauthenticated calls are rejected with JSON-RPC error -32001.',
    ],
    codeTitle: 'Issue Signed Agent Token',
    code: `uv run cerberus issue-token --agent-id coding-agent-01 --ttl 3600`,
  },
  {
    id: 'security-policies',
    title: 'Security Policies',
    summary: 'Four base policy packages plus closed-loop Rego synthesis.',
    body: [
      'Base policies live under policies/base/: behavioral.rego, trifecta.rego, rug_pull.rego, and privilege_escalation.rego.',
      'Whenever CERBERUS blocks or quarantines a malicious call, PolicySynthesizer drafts a candidate least-privilege Rego rule for human review.',
    ],
  },
  {
    id: 'opa-rego',
    title: 'OPA and Rego',
    summary: 'Author, test, and dry-run Rego v1 guardrails.',
    body: [
      'Every policy package evaluates input.risk_score, input.static_scan (schema_drift, lethal_trifecta, out_of_scope), and input.config.',
      'You can validate policies locally with the OPA CLI or interactively via POST /policy/simulate.',
    ],
    codeTitle: 'Sample behavioral.rego',
    code: `package cerberus.behavioral\n\ndefault decision := "allow"\n\ndecision := "quarantine" if { input.risk_score >= 0.9 }\ndecision := "block" if { input.risk_score >= 0.7; input.risk_score < 0.9 }\ndecision := "flag" if { input.risk_score >= 0.4; input.risk_score < 0.7 }`,
  },
  {
    id: 'behavioural-models',
    title: 'Behavioural Models',
    summary: 'Rule Floor, Markov Chain, Isolation Forest, and Sequence Transformer.',
    body: [
      'CERBERUS segregates categorical features (Markov transition surprise) from continuous numeric features (parameter entropy, byte size, inter-call latency, session duration, sequence position) normalized via Welford z-scores.',
      'Online baseline refits exclude contaminated sessions (risk >= 0.40) and enforce a Total Variation Distance (TVD) stability gate to defeat boiling-frog poisoning.',
    ],
  },
  {
    id: 'api-reference',
    title: 'API Reference',
    summary: 'Core REST, SSE, and JSON-RPC endpoints exposed by FastAPI.',
    body: [
      'POST /mcp — MCP JSON-RPC interception gateway (tools/list, tools/call)',
      'GET /api/events & GET /api/events/stream — Recent events and live SSE stream',
      'GET /api/agents & POST /api/agents — Agent telemetry, registration, suspend/activate',
      'GET /api/behavior — Live ensemble weights, Markov transition matrix, Isolation Forest & Transformer state',
      'GET /api/policies, POST /api/policies, POST /policy/simulate — Rego bundle CRUD & dry-run',
      'GET /api/incidents — Kill-chain incident reconstruction & narrative',
      'GET /api/audit/logs & POST /api/audit/verify — Hash-chain ledger & cryptographic verification',
      'GET /api/analytics & POST /api/testing/run — Benchmarks & live security test suite',
    ],
  },
  {
    id: 'troubleshooting',
    title: 'Troubleshooting',
    summary: 'Common deployment checks and audit ledger verification.',
    body: [
      'OPA Unreachable: Check Settings or /healthz; CERBERUS intentionally trips fail-closed blocking for risk >= 0.70 during OPA outages.',
      'Audit Integrity Error: Run cerberus verify-log --log-path cerberus_audit.jsonl to identify any modified or truncated JSONL block index.',
    ],
    codeTitle: 'Verify Audit Hash Chain',
    code: `uv run cerberus verify-log --log-path cerberus_audit.jsonl`,
  },
];

export const DocsPage: React.FC = () => {
  const [activeId, setActiveId] = useState<string>('getting-started');
  const [query, setQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const { addToast } = useToast();

  const filteredSections = useMemo(() => {
    if (!query.trim()) return DOC_SECTIONS;
    const q = query.toLowerCase();
    return DOC_SECTIONS.filter(
      (s) =>
        s.title.toLowerCase().includes(q) ||
        s.summary.toLowerCase().includes(q) ||
        s.body.some((b) => b.toLowerCase().includes(q)) ||
        (s.code || '').toLowerCase().includes(q)
    );
  }, [query]);

  const activeSection =
    filteredSections.find((s) => s.id === activeId) || filteredSections[0] || DOC_SECTIONS[0];

  const handleCopy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      addToast({ title: 'Copied snippet to clipboard', variant: 'success' });
      setTimeout(() => setCopiedId(null), 1800);
    } catch {
      addToast({ title: 'Clipboard unavailable', variant: 'warning' });
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-6">
      <Card className="p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-gradient-to-r from-[#FAF8FF] via-white to-[#EAE6FF]">
        <div className="flex items-center gap-3.5">
          <CerberusLogo size={52} showHalo={false} />
          <div>
            <Badge tone="primary">Documentation</Badge>
            <h1 className="font-display text-2xl sm:text-3xl font-extrabold text-[#171638] mt-1">
              CERBERUS Engineering Guide
            </h1>
          </div>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-[#8C7BFA] absolute left-3.5 top-3" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search docs..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-white border border-[#E3DDF8] text-sm text-[#171638] placeholder-[#8E8BA8] focus:outline-none focus:border-[#6654E8]"
          />
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <Card className="lg:col-span-3 p-3 space-y-1">
          {filteredSections.length === 0 ? (
            <p className="text-xs text-[#666581] p-4 text-center">No matching topics.</p>
          ) : (
            filteredSections.map((sec) => {
              const isActive = sec.id === activeSection.id;
              return (
                <button
                  key={sec.id}
                  onClick={() => setActiveId(sec.id)}
                  className={`w-full text-left px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                    isActive
                      ? 'cerberus-gradient-btn text-white'
                      : 'text-[#666581] hover:text-[#171638] hover:bg-[#F3F0FF]'
                  }`}
                >
                  {sec.title}
                </button>
              );
            })
          )}
        </Card>

        <Card className="lg:col-span-9 p-6 sm:p-8 space-y-5">
          <div className="border-b border-[#E3DDF8] pb-4">
            <h2 className="font-display text-2xl font-extrabold text-[#171638]">
              {activeSection.title}
            </h2>
            <p className="text-sm text-[#6654E8] font-medium mt-1">{activeSection.summary}</p>
          </div>

          <div className="space-y-3">
            {activeSection.body.map((para, idx) => (
              <p key={idx} className="text-sm text-[#171638]/85 leading-relaxed">
                {para}
              </p>
            ))}
          </div>

          {activeSection.code && (
            <div className="rounded-2xl border border-[#E3DDF8] bg-[#FAF8FF] overflow-hidden">
              <div className="px-4 py-2.5 bg-[#EAE6FF]/75 border-b border-[#E3DDF8] flex items-center justify-between">
                <span className="text-xs font-mono font-semibold text-[#6654E8]">
                  {activeSection.codeTitle || 'Command'}
                </span>
                <button
                  onClick={() => handleCopy(activeSection.id, activeSection.code!)}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#171638] hover:text-[#6654E8]"
                >
                  {copiedId === activeSection.id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[#22B982]" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy
                    </>
                  )}
                </button>
              </div>
              <pre className="p-4 text-xs font-mono text-[#171638] overflow-x-auto leading-relaxed">
                {activeSection.code}
              </pre>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

