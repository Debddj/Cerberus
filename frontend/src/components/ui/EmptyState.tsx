import React from 'react';
import { CerberusLogo } from '../brand/CerberusLogo';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, description, action }) => {
  return (
    <div className="cerberus-card p-10 text-center flex flex-col items-center justify-center">
      <div className="w-14 h-14 rounded-2xl bg-[#F3F0FF] border border-[#E3DDF8] flex items-center justify-center text-[#6654E8] mb-4">
        {icon || <CerberusLogo size={34} showHalo={false} />}
      </div>
      <h4 className="text-base font-bold text-[#171638]">{title}</h4>
      <p className="text-sm text-[#666581] max-w-md mt-1.5 leading-relaxed">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
};

