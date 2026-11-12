import React from 'react';
import { clsx } from 'clsx';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
  onClick?: () => void;
}

export const Card: React.FC<CardProps> = ({ children, className = '', hover = false, onClick }) => {
  return (
    <div
      onClick={onClick}
      className={clsx(
        'cerberus-card',
        hover && 'transition-all duration-200 hover:shadow-card-hover hover:border-[#C7BDFC]',
        onClick && 'cursor-pointer',
        className
      )}
    >
      {children}
    </div>
  );
};

export const CardHeader: React.FC<{
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}> = ({ title, subtitle, icon, actions, className = '' }) => (
  <div className={clsx('flex flex-wrap items-center justify-between gap-3 mb-4', className)}>
    <div className="flex items-center gap-3 min-w-0">
      {icon && (
        <div className="w-9 h-9 rounded-xl bg-[#EAE6FF] border border-[#DCD5FF] flex items-center justify-center text-[#6654E8] shrink-0">
          {icon}
        </div>
      )}
      <div className="min-w-0">
        <h3 className="text-base font-bold text-[#171638] truncate">{title}</h3>
        {subtitle && <p className="text-xs text-[#666581] mt-0.5">{subtitle}</p>}
      </div>
    </div>
    {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
  </div>
);

