import React from 'react';
import { clsx } from 'clsx';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger' | 'success';
  size?: 'sm' | 'md' | 'lg';
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  className = '',
  disabled,
  ...props
}) => {
  const sizes = {
    sm: 'px-3 py-1.5 text-xs rounded-lg',
    md: 'px-4 py-2 text-sm rounded-xl',
    lg: 'px-6 py-3 text-sm rounded-xl',
  };

  const variants = {
    primary: 'cerberus-gradient-btn text-white font-semibold border border-transparent',
    secondary:
      'bg-[#EAE6FF] hover:bg-[#DCD5FF] text-[#171638] font-semibold border border-[#DCD5FF]',
    outline:
      'bg-white hover:bg-[#F3F0FF] text-[#171638] font-semibold border border-[#E3DDF8] shadow-sm',
    ghost: 'bg-transparent hover:bg-[#EAE6FF]/70 text-[#666581] hover:text-[#171638] font-medium',
    danger:
      'bg-[#F06478] hover:bg-[#E14F64] text-white font-semibold shadow-sm border border-transparent',
    success:
      'bg-[#22B982] hover:bg-[#1BA371] text-white font-semibold shadow-sm border border-transparent',
  };

  return (
    <button
      disabled={disabled}
      className={clsx(
        'inline-flex items-center justify-center gap-2 transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-[#6654E8]/35 disabled:opacity-55 disabled:cursor-not-allowed whitespace-nowrap',
        sizes[size],
        variants[variant],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
};

