import React from 'react';
import { CerberusLogo } from '../brand/CerberusLogo';

interface LoadingScreenProps {
  label?: string;
}

export const LoadingScreen: React.FC<LoadingScreenProps> = ({
  label = 'Initializing CERBERUS Control Plane...',
}) => {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center gap-4 p-8">
      <div className="relative flex items-center justify-center">
        <div className="absolute inset-0 rounded-full bg-[#8C7BFA]/20 blur-xl animate-pulse" />
        <CerberusLogo size={88} className="relative animate-pulse" />
      </div>
      <div className="text-center space-y-1">
        <p className="text-sm font-bold tracking-wide text-[#171638] uppercase">CERBERUS</p>
        <p className="text-xs text-[#666581] font-medium">{label}</p>
      </div>
    </div>
  );
};

