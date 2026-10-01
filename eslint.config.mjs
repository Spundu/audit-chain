import js from '@eslint/js';
import tseslint from 'typescript-eslint';

// Flat config. Type-aware linting is deliberately off to stay fast; `tsc --noEmit` (typecheck)
// covers the type-level checks.
export default tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', '*.config.{js,mjs,cjs,ts,mts}'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
);
