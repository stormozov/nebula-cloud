import path from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";
import { analyzer } from "vite-bundle-analyzer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const API_URL = env.VITE_API_URL || "http://localhost:8000";

  return {
    plugins: [react(), analyzer()],

    base: "./",

    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
        "@pages": path.resolve(__dirname, "./src/pages"),
        "@components": path.resolve(__dirname, "./src/components"),
        "@utils": path.resolve(__dirname, "./src/shared/utils"),
        "@hooks": path.resolve(__dirname, "./src/hooks"),
        "@shared": path.resolve(__dirname, "./src/shared"),
        "@assets": path.resolve(__dirname, "./src/assets"),
        "@tests": path.resolve(__dirname, "./tests"),
      },
    },

    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: API_URL,
          changeOrigin: true,
          secure: false,

          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          configure: (proxy, _options) => {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            proxy.on("proxyReq", (proxyReq, _req, _res) => {
              proxyReq.setHeader("Accept", "application/json");
            });
          },
        },
      },
    },

    build: {
      outDir: "dist",
      emptyOutDir: true,
      sourcemap: mode === "development",
      rollupOptions: {
        input: {
          main: path.resolve(__dirname, "index.html"),
        },
        output: {
          entryFileNames: "assets/[name]-[hash].js",
          chunkFileNames: "assets/[name]-[hash].js",
          assetFileNames: "assets/[name]-[hash].[ext]",
        },
      },
    },

    define: {
      "process.env.API_URL": JSON.stringify(API_URL),
    },
  };
});
