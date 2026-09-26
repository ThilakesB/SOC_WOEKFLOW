/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Surfaces — a single elevation ramp, not ad-hoc greys.
        base: 'rgb(var(--surface-base) / <alpha-value>)',
        surface: 'rgb(var(--surface-raised) / <alpha-value>)',
        elevated: 'rgb(var(--surface-elevated) / <alpha-value>)',
        overlay: 'rgb(var(--surface-overlay) / <alpha-value>)',

        line: {
          subtle: 'rgb(var(--border-subtle) / <alpha-value>)',
          DEFAULT: 'rgb(var(--border-default) / <alpha-value>)',
          strong: 'rgb(var(--border-strong) / <alpha-value>)',
        },

        ink: {
          DEFAULT: 'rgb(var(--text-primary) / <alpha-value>)',
          secondary: 'rgb(var(--text-secondary) / <alpha-value>)',
          muted: 'rgb(var(--text-muted) / <alpha-value>)',
          inverse: 'rgb(var(--text-inverse) / <alpha-value>)',
        },

        // Severity is semantic, never decorative.
        critical: 'rgb(var(--sev-critical) / <alpha-value>)',
        high: 'rgb(var(--sev-high) / <alpha-value>)',
        medium: 'rgb(var(--sev-medium) / <alpha-value>)',
        low: 'rgb(var(--sev-low) / <alpha-value>)',
        info: 'rgb(var(--sev-info) / <alpha-value>)',

        // Verdict vocabulary
        truepositive: 'rgb(var(--verdict-tp) / <alpha-value>)',
        suspicious: 'rgb(var(--verdict-suspicious) / <alpha-value>)',
        benign: 'rgb(var(--verdict-benign) / <alpha-value>)',
        unknown: 'rgb(var(--verdict-unknown) / <alpha-value>)',

        accent: {
          DEFAULT: 'rgb(var(--accent) / <alpha-value>)',
          soft: 'rgb(var(--accent-soft) / <alpha-value>)',
          ink: 'rgb(var(--accent-ink) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter var', 'Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      fontSize: {
        // Deliberate type scale — no arbitrary font-size utilities in components.
        '2xs': ['0.6875rem', { lineHeight: '1rem', letterSpacing: '0.01em' }],
        xs: ['0.75rem', { lineHeight: '1.125rem' }],
        sm: ['0.8125rem', { lineHeight: '1.25rem' }],
        base: ['0.875rem', { lineHeight: '1.375rem' }],
        lg: ['1rem', { lineHeight: '1.5rem' }],
        xl: ['1.125rem', { lineHeight: '1.625rem' }],
        '2xl': ['1.375rem', { lineHeight: '1.75rem', letterSpacing: '-0.01em' }],
        '3xl': ['1.75rem', { lineHeight: '2rem', letterSpacing: '-0.02em' }],
        '4xl': ['2.25rem', { lineHeight: '2.5rem', letterSpacing: '-0.025em' }],
      },
      borderRadius: {
        DEFAULT: '0.375rem',
        md: '0.5rem',
        lg: '0.75rem',
        xl: '1rem',
      },
      boxShadow: {
        panel: '0 1px 2px rgb(0 0 0 / 0.28), 0 0 0 1px rgb(var(--border-subtle) / 0.6)',
        pop: '0 12px 32px -8px rgb(0 0 0 / 0.6), 0 0 0 1px rgb(var(--border-default))',
        focus: '0 0 0 2px rgb(var(--surface-base)), 0 0 0 4px rgb(var(--accent) / 0.55)',
      },
      keyframes: {
        'fade-up': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateX(8px)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
        'pulse-ring': {
          '0%': { boxShadow: '0 0 0 0 rgb(var(--accent) / 0.45)' },
          '70%': { boxShadow: '0 0 0 6px rgb(var(--accent) / 0)' },
          '100%': { boxShadow: '0 0 0 0 rgb(var(--accent) / 0)' },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
      },
      animation: {
        'fade-up': 'fade-up 240ms cubic-bezier(0.22, 1, 0.36, 1) both',
        'slide-in': 'slide-in 200ms cubic-bezier(0.22, 1, 0.36, 1) both',
        'pulse-ring': 'pulse-ring 1.8s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        shimmer: 'shimmer 1.6s infinite',
      },
    },
  },
  plugins: [],
}
