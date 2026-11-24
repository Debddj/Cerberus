import React from 'react';

interface CerberusLogoProps {
  size?: number | string;
  className?: string;
  showBadge?: boolean;
  glow?: boolean;
}

export const CerberusLogo: React.FC<CerberusLogoProps> = ({
  size = 40,
  className = '',
  showBadge = false,
  glow = false,
}) => {
  const dimension = typeof size === 'number' ? `${size}px` : size;

  return (
    <div className={`relative inline-flex items-center justify-center ${className}`}>
      <svg
        width={dimension}
        height={dimension}
        viewBox="0 0 120 120"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="transition-opacity duration-200"
      >
        <defs>
          {/* Lavender & Purple Gradients */}
          <linearGradient id="shieldGrad" x1="20" y1="20" x2="100" y2="110" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#7C3AED" />
            <stop offset="50%" stopColor="#6654E8" />
            <stop offset="100%" stopColor="#4F46E5" />
          </linearGradient>

          <linearGradient id="shieldRim" x1="20" y1="20" x2="100" y2="110" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#DDD6FE" />
            <stop offset="50%" stopColor="#A78BFA" />
            <stop offset="100%" stopColor="#6654E8" />
          </linearGradient>

          <linearGradient id="wolfLeftGrad" x1="15" y1="25" x2="45" y2="70" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#DDD6FE" />
            <stop offset="40%" stopColor="#8B5CF6" />
            <stop offset="100%" stopColor="#3E319E" />
          </linearGradient>

          <linearGradient id="wolfCenterGrad" x1="45" y1="15" x2="75" y2="65" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#EDE9FE" />
            <stop offset="40%" stopColor="#7C3AED" />
            <stop offset="100%" stopColor="#2E2374" />
          </linearGradient>

          <linearGradient id="wolfRightGrad" x1="75" y1="25" x2="105" y2="70" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#DDD6FE" />
            <stop offset="40%" stopColor="#8B5CF6" />
            <stop offset="100%" stopColor="#3E319E" />
          </linearGradient>

          <linearGradient id="eyeGlow" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#38BDF8" />
            <stop offset="100%" stopColor="#00F0FF" />
          </linearGradient>

          <filter id="softGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Outer Circular Guardian Halo */}
        <circle cx="60" cy="60" r="56" stroke="url(#shieldRim)" strokeWidth="1.5" strokeOpacity="0.4" strokeDasharray="3 3" />
        <circle cx="60" cy="60" r="52" stroke="#6654E8" strokeWidth="0.75" strokeOpacity="0.25" />

        {/* Guardian Backdrop Shield Geometry */}
        <path
          d="M60 12 L96 26 C96 68 60 98 60 108 C60 98 24 68 24 26 Z"
          fill="url(#shieldGrad)"
          fillOpacity="0.12"
          stroke="url(#shieldRim)"
          strokeWidth="1.5"
        />

        {/* --- LEFT CERBERUS HEAD --- */}
        <g id="left-head" opacity="0.92">
          {/* Ear */}
          <polygon points="26,22 34,34 22,38" fill="url(#wolfLeftGrad)" stroke="#6654E8" strokeWidth="0.75" />
          {/* Crown & Brow */}
          <polygon points="34,34 46,38 38,46 28,40" fill="#6654E8" fillOpacity="0.85" />
          {/* Snout & Jaw */}
          <polygon points="22,38 34,44 26,52 14,44" fill="url(#wolfLeftGrad)" />
          {/* Muzzle Tip */}
          <polygon points="14,44 22,46 18,50" fill="#171638" />
          {/* Left Eye */}
          <polygon points="30,39 34,41 29,43" fill="url(#eyeGlow)" filter="url(#softGlow)" />
        </g>

        {/* --- RIGHT CERBERUS HEAD --- */}
        <g id="right-head" opacity="0.92">
          {/* Ear */}
          <polygon points="94,22 86,34 98,38" fill="url(#wolfRightGrad)" stroke="#6654E8" strokeWidth="0.75" />
          {/* Crown & Brow */}
          <polygon points="86,34 74,38 82,46 92,40" fill="#6654E8" fillOpacity="0.85" />
          {/* Snout & Jaw */}
          <polygon points="98,38 86,44 94,52 106,44" fill="url(#wolfRightGrad)" />
          {/* Muzzle Tip */}
          <polygon points="106,44 98,46 102,50" fill="#171638" />
          {/* Right Eye */}
          <polygon points="90,39 86,41 91,43" fill="url(#eyeGlow)" filter="url(#softGlow)" />
        </g>

        {/* --- CENTER CERBERUS HEAD (ALPHA GUARDIAN) --- */}
        <g id="center-head">
          {/* Left Ear */}
          <polygon points="48,14 55,28 44,30" fill="url(#wolfCenterGrad)" stroke="#A78BFA" strokeWidth="0.75" />
          {/* Right Ear */}
          <polygon points="72,14 65,28 76,30" fill="url(#wolfCenterGrad)" stroke="#A78BFA" strokeWidth="0.75" />
          {/* Forehead Crest */}
          <polygon points="48,28 60,18 72,28 60,36" fill="#DDD6FE" fillOpacity="0.9" />
          {/* Cheeks */}
          <polygon points="44,30 55,28 60,36 50,44 38,36" fill="url(#wolfCenterGrad)" />
          <polygon points="76,30 65,28 60,36 70,44 82,36" fill="url(#wolfCenterGrad)" />
          {/* Center Muzzle / Bridge */}
          <polygon points="50,44 60,36 70,44 60,56" fill="url(#shieldGrad)" />
          {/* Nose Tip */}
          <polygon points="56,54 64,54 60,59" fill="#171638" />
          {/* Eyes (Glowing Cyan / Ice Violet) */}
          <polygon points="50,33 55,34 51,37" fill="url(#eyeGlow)" filter="url(#softGlow)" />
          <polygon points="70,33 65,34 69,37" fill="url(#eyeGlow)" filter="url(#softGlow)" />
        </g>

        {/* --- FOREFRONT PURPLE LOCK SHIELD --- */}
        <g id="lock-shield" transform="translate(0, 4)">
          {/* Shield Outline */}
          <path
            d="M60 48 L80 56 C80 82 60 98 60 102 C60 98 40 82 40 56 Z"
            fill="url(#shieldGrad)"
            stroke="url(#shieldRim)"
            strokeWidth="2"
            filter="url(#softGlow)"
          />
          {/* Inner Inset Shield */}
          <path
            d="M60 52 L76 59 C76 80 60 93 60 97 C60 93 44 80 44 59 Z"
            fill="#1E1B4B"
            fillOpacity="0.6"
            stroke="#C4B5FD"
            strokeWidth="0.75"
          />
          {/* Padlock Shackle */}
          <path
            d="M54 68 V63 C54 59.7 56.7 57 60 57 C63.3 57 66 59.7 66 63 V68"
            stroke="#DDD6FE"
            strokeWidth="2.5"
            strokeLinecap="round"
            fill="none"
          />
          {/* Padlock Body */}
          <rect x="51" y="67" width="18" height="15" rx="3.5" fill="#DDD6FE" stroke="#6654E8" strokeWidth="1" />
          {/* Keyhole */}
          <circle cx="60" cy="73" r="1.8" fill="#5543D6" />
          <polygon points="59,73 61,73 61.5,77 58.5,77" fill="#5543D6" />
        </g>
      </svg>

      {showBadge && (
        <span className="ml-2.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold tracking-wider bg-[#EDE9FE] text-[#6654E8] border border-[#DDD6FE]">
          MCP FIREWALL
        </span>
      )}
    </div>
  );
};