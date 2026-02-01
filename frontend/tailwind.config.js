/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Severity colors for threat visualization
        severity: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#ca8a04',
          low: '#16a34a',
          none: '#6b7280',
        },
        // Dark theme colors
        canvas: {
          bg: '#0f172a',
          node: '#1e293b',
          border: '#334155',
          text: '#f1f5f9',
        }
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-out forwards',
        'draw-edge': 'drawEdge 0.8s ease-out forwards',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        drawEdge: {
          '0%': { strokeDashoffset: '100%' },
          '100%': { strokeDashoffset: '0%' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 5px var(--glow-color)' },
          '50%': { boxShadow: '0 0 20px var(--glow-color)' },
        },
      },
    },
  },
  plugins: [],
}
