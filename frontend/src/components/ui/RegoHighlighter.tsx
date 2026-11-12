import React from 'react';

interface RegoHighlighterProps {
  code: string;
  editable?: boolean;
  onChange?: (val: string) => void;
  filename?: string;
}

function highlightRegoLine(line: string): React.ReactNode {
  const trimmed = line.trimStart();
  if (trimmed.startsWith('#')) {
    return <span className="text-[#8E8BA8] italic">{line}</span>;
  }

  const tokenRegex =
    /("(?:[^"\\]|\\.)*"|\b(?:package|import|default|if|else|not|in|some|every|contains|true|false|allow|deny|block|decision|reason|input)\b|\b\d+(?:\.\d+)?\b|:=|==|!=|>=|<=|>|<)/g;
  const parts: React.ReactNode[] = [];
  let lastIdx = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = tokenRegex.exec(line)) !== null) {
    if (match.index > lastIdx) {
      parts.push(line.slice(lastIdx, match.index));
    }
    const tok = match[0];
    let cls = 'text-[#171638]';
    if (tok.startsWith('"')) {
      cls = 'text-[#158A5E]';
    } else if (/^\d/.test(tok)) {
      cls = 'text-[#C65102] font-semibold';
    } else if (['package', 'import', 'default', 'if', 'else', 'not', 'in', 'some', 'every', 'contains'].includes(tok)) {
      cls = 'text-[#6654E8] font-semibold';
    } else if (['allow', 'deny', 'block', 'decision', 'reason'].includes(tok)) {
      cls = 'text-[#3A29B8] font-semibold';
    } else if (['true', 'false'].includes(tok)) {
      cls = 'text-[#B7720C] font-semibold';
    } else if (tok === 'input') {
      cls = 'text-[#6654E8]';
    } else {
      cls = 'text-[#666581]';
    }
    parts.push(
      <span key={key++} className={cls}>
        {tok}
      </span>
    );
    lastIdx = tokenRegex.lastIndex;
  }

  if (lastIdx < line.length) {
    parts.push(line.slice(lastIdx));
  }
  return parts.length > 0 ? parts : ' ';
}

export const RegoHighlighter: React.FC<RegoHighlighterProps> = ({
  code,
  editable = false,
  onChange,
  filename = 'policy.rego',
}) => {
  const lines = code.split('\n');

  return (
    <div className="rounded-xl border border-[#E3DDF8] bg-[#FAF8FF] overflow-hidden">
      <div className="px-4 py-2 bg-[#EAE6FF]/75 border-b border-[#E3DDF8] flex items-center justify-between">
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-lg bg-white border border-[#DCD5FF] text-xs font-mono font-semibold text-[#6654E8]">
          {filename}
        </span>
        <span className="text-[11px] font-mono text-[#666581]">OPA Rego v1 · {lines.length} lines</span>
      </div>

      {editable ? (
        <textarea
          value={code}
          onChange={(e) => onChange?.(e.target.value)}
          spellCheck={false}
          rows={Math.max(12, Math.min(24, lines.length + 2))}
          className="w-full p-4 bg-[#FAF8FF] text-[#171638] font-mono text-xs leading-6 focus:outline-none resize-y"
          aria-label="Rego policy code editor"
        />
      ) : (
        <div className="overflow-x-auto max-h-[380px] overflow-y-auto p-4 font-mono text-xs leading-6">
          {lines.map((line, idx) => (
            <div key={idx} className="flex">
              <span className="w-8 shrink-0 select-none text-right pr-3 text-[#A29DC4]">
                {idx + 1}
              </span>
              <pre className="whitespace-pre text-[#171638]">{highlightRegoLine(line)}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

