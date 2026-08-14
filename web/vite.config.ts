// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - TanStack devtools (dev-only, first), tanstackStart, viteReact, tailwindcss, tsConfigPaths,
//     nitro (build-only using cloudflare as a default target), VITE_* env injection, @ path alias,
//     React/TanStack dedupe, error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import { defineConfig } from "@lovable.dev/vite-tanstack-config";

// GitHub Pages serves the site from a subpath (/ghost-recover/); the engine's
// local web server serves it at the root. GH_PAGES=1 switches the base URL.
const base = process.env.GH_PAGES === "1" ? "/ghost-recover/" : "/";

export default defineConfig({
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
    pages: [{ path: "/", prerender: { enabled: true } }],
  },
  // Static export for GitHub Pages hosting (ghost-recover is served from a
  // subpath of nkbeast.github.io, so the base URL must be the repo name).
  // nitro is disabled: TanStack Start's own vite-based prerenderer emits the
  // static files (the index route opts in via `prerender` in src/routes/index.tsx).
  vite: {
    base,
  },
  nitro: false,
});