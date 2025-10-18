/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      maxWidth: {
        '100vw': '100vw',
      },
      width: {
        '100vw': '100vw',
      },
      colors: {
        'zypheron': {
          50: '#f0fffe',
          100: '#ccfdf9', 
          200: '#99fbf4',
          300: '#5ef4e8',
          400: '#2ee6d6',
          500: '#00D4AA', // Main teal from logo
          600: '#00b899',
          700: '#008B73', // Darker teal
          800: '#006b5a',
          900: '#00544a',
        },
        'zypheron-red': {
          50: '#fff5f3',
          100: '#ffe7e1',
          200: '#ffd4c8',
          300: '#ffb8a1',
          400: '#ff9270',
          500: '#FF4444', // Bright red from logo
          600: '#FF6B35', // Flame highlight
          700: '#e63e1f',
          800: '#c23417',
          900: '#a02f19',
        },
        'terminal': {
          bg: '#0a0a0a',
          surface: '#1a1a1a',
          border: '#404040',
          text: '#e5e5e5',
          muted: '#a3a3a3',
          accent: '#00D4AA', // Updated to match new teal
        }
      },
      fontFamily: {
        'mono': ['Fira Code', 'JetBrains Mono', 'Monaco', 'Consolas', 'monospace'],
        'orbitron': ['Orbitron', 'monospace'],
        'inter': ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-red': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'terminal-cursor': 'blink 1s step-end infinite',
        'glow-teal': 'glow-teal 2s ease-in-out infinite alternate',
      },
      keyframes: {
        blink: {
          '0%, 50%': { opacity: '1' },
          '51%, 100%': { opacity: '0' },
        },
        'glow-teal': {
          '0%': { 'box-shadow': '0 0 20px #00D4AA' },
          '100%': { 'box-shadow': '0 0 30px #00D4AA, 0 0 40px #00D4AA' },
        }
      },
      screens: {
        'xs': '475px',
        'sm': '640px',
        'md': '768px',
        'lg': '1024px',
        'xl': '1280px',
        '2xl': '1536px',
      }
    },
  },
  plugins: [],
} 