import React from 'react';

interface MountainBackdropProps {
  className?: string;
}

/**
 * Misty pastel lavender mountain silhouettes matching the CERBERUS landing hero aesthetic.
 */
export const MountainBackdrop: React.FC<MountainBackdropProps> = ({ className = '' }) => {
  return (
    <svg
      viewBox="0 0 1440 360"
      preserveAspectRatio="none"
      className={`pointer-events-none select-none ${className}`}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="mntBack" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#D7CEFD" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#EAE6FF" stopOpacity="0.15" />
        </linearGradient>
        <linearGradient id="mntMid" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#C5B8FA" stopOpacity="0.6" />
          <stop offset="100%" stopColor="#EFEBFD" stopOpacity="0.2" />
        </linearGradient>
        <linearGradient id="mntFront" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#B6A6F6" stopOpacity="0.62" />
          <stop offset="100%" stopColor="#F3F0FF" stopOpacity="0.95" />
        </linearGradient>
      </defs>

      <path
        d="M0 245 L140 165 L270 218 L430 132 L580 210 L740 120 L920 198 L1085 95 L1255 182 L1375 135 L1440 168 L1440 360 L0 360 Z"
        fill="url(#mntBack)"
      />
      <path
        d="M0 278 L195 190 L345 248 L510 175 L690 250 L860 155 L1030 225 L1190 140 L1350 212 L1440 185 L1440 360 L0 360 Z"
        fill="url(#mntMid)"
      />
      <path
        d="M0 308 L160 242 L310 288 L480 228 L660 296 L830 212 L1010 276 L1180 202 L1340 258 L1440 232 L1440 360 L0 360 Z"
        fill="url(#mntFront)"
      />
    </svg>
  );
};

