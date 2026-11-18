import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Fixed, unhashed output filenames (admin.js / admin.css) because the Rust backend
// embeds them at compile time via include_str!() with a literal path — a content
// hash in the filename would break that on every rebuild.
export default defineConfig({
  plugins: [react()],
  base: "/admin/",
  build: {
    outDir: "dist",
    rollupOptions: {
      input: "index.html",
      output: {
        entryFileNames: "assets/admin.js",
        chunkFileNames: "assets/admin.js",
        assetFileNames: (info) =>
          info.name?.endsWith(".css") ? "assets/admin.css" : "assets/[name][extname]",
      },
    },
  },
});
