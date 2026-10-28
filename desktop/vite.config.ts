import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 浏览器预览（npm run dev）时没有 Rust 侧 HTTP，请求经这个代理转给本机隔离后台，
// 顺带绕过 CORS；Tauri 运行时走 invoke("api_post")，不经过这里。
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1421,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:3012",
        changeOrigin: true,
      },
    },
  },
  build: {
    target: "chrome110",
    outDir: "dist",
  },
});
