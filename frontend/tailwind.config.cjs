/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{vue,ts,tsx,js,jsx}',
  ],
  corePlugins: {
    preflight: false,
  },
  theme: {
    extend: {
      fontFamily: {
        sans: [
          'Noto Sans SC',
          'PingFang SC',
          'Microsoft YaHei',
          'system-ui',
          '-apple-system',
          'sans-serif',
        ],
        mono: [
          'JetBrains Mono',
          'Cascadia Code',
          'Consolas',
          'monospace',
        ],
      },
      colors: {
        fusion: {
          bg: '#000000',
          sidebar: '#0d0d0d',
          surface: '#080808',
          panel: '#101010',
          raised: '#171717',
          border: '#262626',
          soft: '#1a1a1a',
          text: '#fafafa',
          muted: '#a3a3a3',
          subtle: '#737373',
          green: '#22c55e',
          yellow: '#eab308',
          blue: '#3b82f6',
          red: '#ef4444',
          orange: '#f97316',
        },
      },
      borderRadius: {
        fusion: '8px',
      },
      boxShadow: {
        fusion: '0 1px 2px rgba(0, 0, 0, 0.28)',
      },
    },
  },
  plugins: [],
}
