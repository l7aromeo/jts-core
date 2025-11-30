import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/index.ts', // Re-exports only
        'src/**/index.ts', // Re-exports
        'src/stores/redis-store.ts', // Requires Redis
        'src/stores/postgres-store.ts', // Requires PostgreSQL
        'src/cli/**', // CLI tools (tested manually)
        'src/client/**', // Client SDK (requires browser/network)
      ],
      thresholds: {
        lines: 75,
        functions: 80,
        branches: 70,
        statements: 75,
      },
    },
    testTimeout: 10000,
  },
});
