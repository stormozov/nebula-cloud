/// <reference types="vitest" />
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    // Test execution environment (browser emulation)
    environment: "happy-dom",
    // Global functions: describe, it, expect, vi, etc.
    globals: true,

    // The initialization file before running the tests
    setupFiles: ["./tests/setup.ts"],

    // Excluded folders
    exclude: ["**/node_modules/**", "**/dist/**", "**/e2e/**", "**/*.config.*"],

    // Test Coverage Settings
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["src/**/*"],
      exclude: [
        "node_modules/**",
        "dist/**",
        "**/*.scss",
        "src/main.tsx",
        "src/vite-env.d.ts",
        "**/*.d.ts",
        "**/*.config.*",
        "**/*.json",
        "tests/**",
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/types/**",
        "**/types.ts",
        "**/index.ts",
        "**/selectors.ts",
        "store/**",
        "routes/**"
      ],
      thresholds: {
        branches: 80,
        functions: 80,
        lines: 80,
        statements: 80,
      },
    },

    // Settings for MSW (Mock Service Worker)
    server: {
      deps: {
        inline: ["msw"],
      },
    },
  },
});
