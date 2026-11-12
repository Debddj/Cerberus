/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cerberus: {
          bg: '#F3F0FF',
          'bg-secondary': '#EAE6FF',
          card: '#FFFFFF',
          primary: '#6654E8',
          secondary: '#8C7BFA',
          soft: '#DCD5FF',
          text: '#171638',
          muted: '#666581',
          success: '#22B982',
          warning: '#F4AD42',
          danger: '#F06478',
          border: '#E3DDF8',
        }
      },
      fontFamily: {
        display: ['"Plus Jakarta Sans"', 'Inter', 'system-ui', 'sans-serif'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 10px 30px -12px rgba(102, 84, 232, 0.14)',
        'card-hover': '0 18px 36px -12px rgba(102, 84, 232, 0.22)',
        pill: '0 8px 20px -6px rgba(102, 84, 232, 0.45)',
      }
    },
  },
  plugins: [],
}
