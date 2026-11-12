import React from 'react';
import { clsx } from 'clsx';

export type BadgeTone = 'neutral' | 'primary' | 'success' | 'warning' | 'danger' | 'purple';

interface BadgeProps {
  children: React.ReactNode;
  tone?: BadgeTone;
  className?: string;
  dot?: boolean;
}

const TONE_MAP: Record<BadgeTone, string> = {
  neutral: 'bg-[#F3F0FF] text-[#666581] border-[#E3DDF8]',
  primary: 'bg-[#6654E8]/12 text-[#5240D6] border-[#6654E8]/25',
  purple: 'bg-[#8C7BFA]/15 text-[#5D49DB] border-[#8C7BFA]/30',
  success: 'bg-[#22B982]/14 text-[#148A5E] border-[#22B982]/30',
  warning: 'bg-[#F4AD42]/16 text-[#B7720C] border-[#F4AD42]/35',
  danger: 'bg-[#F06478]/14 text-[#C6384D] border-[#F06478]/30',
};

const DOT_MAP: Record<BadgeTone, string> = {
  neutral: 'bg-[#666581]',
  primary: 'bg-[#6654E8]',
  purple: 'bg-[#8C7BFA]',
  success: 'bg-[#22B982]',
  warning: 'bg-[#F4AD42]',
  danger: 'bg-[#F06478]',
};

export const Badge: React.FC<BadgeProps> = ({
  children,
  tone = 'neutral',
  className = '',
  dot = false,
}) => {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border whitespace-nowrap',
        TONE_MAP[tone],
        className
      )}
    >
      {dot && <span className={clsx('w-1.5 h-1.5 rounded-full', DOT_MAP[tone])} />}
      {children}
    </span>
  );
};

export function decisionTone(decision?: string | null): BadgeTone {
  switch ((decision || '').toLowerCase()) {
    case 'allow':
    case 'active':
      return 'success';
    case 'flag':
    case 'flagged':
    case 'pending':
      return 'warning';
    case 'block':
    case 'suspended':
      return 'danger';
    case 'quarantine':
    case 'quarantined':
      return 'purple';
    default:
      return 'neutral';
  }
}

export function formatDecisionLabel(decision?: string | null): string {
  switch ((decision || '').toLowerCase()) {
    case 'allow':
      return 'Allowed';
    case 'flag':
      return 'Flagged';
    case 'block':
      return 'Blocked';
    case 'quarantine':
      return 'Quarantined';
    default:
      return 'Pending';
  }
}

