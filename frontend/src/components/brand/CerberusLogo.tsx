import React from 'react';

interface CerberusLogoProps {
  className?: string;
  size?: number;
  showHalo?: boolean;
}

/**
 * Official CERBERUS three-headed guardian wolf with shield and padlock emblem.
 */
export const CerberusLogo: React.FC<CerberusLogoProps> = ({
  className = '',
  size = 44,
  showHalo = true,
}) => {
  const uid = React.useId().replace(/:/g, '');

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 240 220"
      width={size}
      height={Math.round((size * 220) / 240)}
      className={className}
      fill="none"
      aria-label="CERBERUS Three-Headed Guardian Logo"
    >
      <defs>
        <radialGradient id={`halo-${uid}`} cx="50%" cy="42%" r="50%">
          <stop offset="0%" stopColor="#FFF9EB" stopOpacity="0.96" />
          <stop offset="55%" stopColor="#E9E2FF" stopOpacity="0.58" />
          <stop offset="100%" stopColor="#DCD5FF" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`furDark-${uid}`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#5B4D9B" />
          <stop offset="100%" stopColor="#2D235C" />
        </linearGradient>
        <linearGradient id={`furMid-${uid}`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#8C7BFA" />
          <stop offset="100%" stopColor="#4A3B8F" />
        </linearGradient>
        <linearGradient id={`furLight-${uid}`} x1="50%" y1="0%" x2="50%" y2="100%">
          <stop offset="0%" stopColor="#F1EEFF" />
          <stop offset="65%" stopColor="#C7BDFC" />
          <stop offset="100%" stopColor="#7B6AC7" />
        </linearGradient>
        <linearGradient id={`shieldFill-${uid}`} x1="50%" y1="0%" x2="50%" y2="100%">
          <stop offset="0%" stopColor="#F4F1FF" />
          <stop offset="48%" stopColor="#B9AEF7" />
          <stop offset="100%" stopColor="#6E5EE0" />
        </linearGradient>
        <linearGradient id={`lockGrad-${uid}`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3E2F84" />
          <stop offset="100%" stopColor="#1E1848" />
        </linearGradient>
        <filter id={`shadow-${uid}`} x="-12%" y="-12%" width="124%" height="124%">
          <feDropShadow dx="0" dy="8" stdDeviation="8" floodColor="#6654E8" floodOpacity="0.22" />
        </filter>
      </defs>

      {showHalo && <circle cx="120" cy="96" r="94" fill={`url(#halo-${uid})`} />}

      <g filter={`url(#shadow-${uid})`}>
        {/* Chest & Shoulder Fur Mantle */}
        <path d="M54 148 L72 108 L168 108 L186 148 L152 178 L88 178 Z" fill={`url(#furDark-${uid})`} />
        <path d="M62 142 L80 116 L160 116 L178 142 L154 166 L86 166 Z" fill={`url(#furMid-${uid})`} />

        {/* Left Guardian Head */}
        <g>
          <polygon points="35,44 55,64 46,84" fill="#3B2E78" />
          <polygon points="62,48 76,68 58,76" fill="#5D4EA6" />
          <polygon points="39,49 51,64 45,76" fill="#C9BFFA" />
          <polygon points="32,82 44,64 68,64 82,82 76,108 58,124 38,112 28,96" fill={`url(#furMid-${uid})`} />
          <polygon points="38,68 62,66 74,80 56,92 38,84" fill={`url(#furLight-${uid})`} />
          <polygon points="22,95 38,84 56,92 52,114 32,115 20,104" fill="#B6AAF4" />
          <polygon points="21,98 30,96 31,105 23,106" fill="#211A4C" />
          <polygon points="40,86 48,84 46,90 39,90" fill="#FFFFFF" />
          <polygon points="56,92 75,83 80,104 60,122 50,114" fill={`url(#furDark-${uid})`} />
          <polygon points="54,116 74,104 68,128 50,130" fill="#C4B9FA" opacity="0.85" />
        </g>

        {/* Right Guardian Head */}
        <g>
          <polygon points="205,44 185,64 194,84" fill="#3B2E78" />
          <polygon points="178,48 164,68 182,76" fill="#5D4EA6" />
          <polygon points="201,49 189,64 195,76" fill="#C9BFFA" />
          <polygon points="208,82 196,64 172,64 158,82 164,108 182,124 202,112 212,96" fill={`url(#furMid-${uid})`} />
          <polygon points="202,68 178,66 166,80 184,92 202,84" fill={`url(#furLight-${uid})`} />
          <polygon points="218,95 202,84 184,92 188,114 208,115 220,104" fill="#B6AAF4" />
          <polygon points="219,98 210,96 209,105 217,106" fill="#211A4C" />
          <polygon points="200,86 192,84 194,90 201,90" fill="#FFFFFF" />
          <polygon points="184,92 165,83 160,104 180,122 190,114" fill={`url(#furDark-${uid})`} />
          <polygon points="186,116 166,104 172,128 190,130" fill="#C4B9FA" opacity="0.85" />
        </g>

        {/* Center Alpha Guardian Head */}
        <g>
          <polygon points="84,18 103,44 86,58" fill="#46378D" />
          <polygon points="88,26 98,44 88,52" fill="#E3DCFF" />
          <polygon points="156,18 137,44 154,58" fill="#46378D" />
          <polygon points="152,26 142,44 152,52" fill="#E3DCFF" />
          <polygon points="86,54 104,38 136,38 154,54 162,84 148,108 120,118 92,108 78,84" fill={`url(#furDark-${uid})`} />
          <polygon points="94,48 120,36 146,48 148,74 120,86 92,74" fill={`url(#furLight-${uid})`} />
          <polygon points="80,78 96,68 108,86 92,106 76,94" fill="#7D6DD4" />
          <polygon points="160,78 144,68 132,86 148,106 164,94" fill="#7D6DD4" />
          <polygon points="111,64 129,64 134,88 120,104 106,88" fill="#F4F1FF" />
          <polygon points="103,82 120,74 137,82 132,104 120,112 108,104" fill="#DBD3FE" />
          <polygon points="99,66 111,71 107,76 97,72" fill="#171638" />
          <polygon points="101,68 108,71 106,74 100,71" fill="#F4F1FF" />
          <polygon points="141,66 129,71 133,76 143,72" fill="#171638" />
          <polygon points="139,68 132,71 134,74 140,71" fill="#F4F1FF" />
          <polygon points="113,90 127,90 124,98 120,101 116,98" fill="#1E1747" />
        </g>

        {/* Protective Shield + Padlock */}
        <g>
          <path
            d="M120 112 L162 124 L159 162 C157 186 140 202 120 211 C100 202 83 186 81 162 L78 124 Z"
            fill={`url(#shieldFill-${uid})`}
            stroke="#FFFFFF"
            strokeWidth="4.5"
            strokeLinejoin="round"
          />
          <path
            d="M120 119 L154 129 L151 161 C149 181 136 195 120 203 C104 195 91 181 89 161 L86 129 Z"
            fill="none"
            stroke="#FFFFFF"
            strokeOpacity="0.55"
            strokeWidth="1.5"
          />
          <path
            d="M108 153 V144 C108 137.4 113.4 132 120 132 C126.6 132 132 137.4 132 144 V153"
            fill="none"
            stroke="#251D58"
            strokeWidth="6.5"
            strokeLinecap="round"
          />
          <rect x="101" y="150" width="38" height="31" rx="6" fill={`url(#lockGrad-${uid})`} />
          <circle cx="120" cy="162" r="3.6" fill="#E9E4FF" />
          <path d="M118.4 164 L121.6 164 L122.4 172 L117.6 172 Z" fill="#E9E4FF" />
        </g>
      </g>
    </svg>
  );
};

