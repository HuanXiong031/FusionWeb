import type { Metadata } from 'next'
import logoImage from '@/assets/images/logo.png'
import './globals.css'

export const metadata: Metadata = {
  title: 'FusionWeb',
  description: 'FusionWeb security scanning platform',
  icons: {
    icon: logoImage.src,
    shortcut: logoImage.src,
    apple: logoImage.src,
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN" className="light" data-theme="vercel" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function () {
                try {
                  var key = 'fusionweb-theme';
                  var themes = ['vercel','vercel-dark','violet-bloom','bubblegum','quantum-rose','clean-slate','cosmic-night','cyberpunk','eva-unit-01'];
                  var darkThemes = ['vercel-dark','quantum-rose','cosmic-night','cyberpunk','eva-unit-01'];
                  var saved = localStorage.getItem(key) || 'vercel';
                  var resolved = themes.indexOf(saved) >= 0 ? saved : 'vercel';
                  var root = document.documentElement;
                  root.dataset.theme = resolved;
                  root.classList.remove('light', 'dark');
                  root.classList.add(darkThemes.indexOf(resolved) >= 0 ? 'dark' : 'light');
                } catch (error) {}
              })();
            `,
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  )
}
