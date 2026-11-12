import React from 'react';
import { Info, Radio } from 'lucide-react';
import { Button } from './Button';

interface StatusBannerProps {
  source: 'live' | 'offline-demo';
  label?: string;
  onRetry?: () => void;
}

export const StatusBanner: React.FC<StatusBannerProps> = ({ source, label, onRetry }) => {
  if (source === 'live') return null;

  return (
    <div className="rounded-xl bg-[#F4AD42]/12 border border-[#F4AD42]/35 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
      <div className="flex items-center gap-2 text-[#8C5506]">
        <Info className="w-4 h-4 text-[#F4AD42] shrink-0" />
        <span>
          <strong>Offline Demonstration Adapter Active:</strong>{' '}
          {label ||
            'FastAPI backend is unreachable right now. Displaying clearly-labelled demonstration records instead of live security telemetry.'}
        </span>
      </div>
      {onRetry && (
        <Button size="sm" variant="outline" onClick={onRetry}>
          <Radio className="w-3.5 h-3.5 text-[#6654E8]" />
          Reconnect Live API
        </Button>
      )}
    </div>
  );
};

