import { useState } from "react";
import { motion } from "motion/react";
import { Reveal, SectionHeading } from "./Reveal";
import { apiEndpoints } from "@/lib/ghost-data";
import webShot from "@/assets/ghostrecoverweb.png.asset.json";
import previewShot from "@/assets/preview.png.asset.json";
import bannerShot from "@/assets/ghost-recover-banner.png.asset.json";

const shots = [
  {
    id: "web",
    label: "Web interface",
    url: webShot.url,
    caption: "Browse recovered files, filter by type, preview photos and video in the browser.",
  },
  {
    id: "preview",
    label: "Scan results",
    url: previewShot.url,
    caption: "Honest progress: bytes scanned, candidates validated, files recovered — live.",
  },
  {
    id: "banner",
    label: "The engine",
    url: bannerShot.url,
    caption: "One binary: web UI, CLI and HTTP API over the same read-only-first engine.",
  },
];

export function Screens() {
  const [active, setActive] = useState(shots[0]!.id);
  const current = shots.find((s) => s.id === active) ?? shots[0]!;

  return (
    <section id="interface" className="relative py-24 sm:py-32">
      <div
        className="pointer-events-none absolute inset-x-0 top-1/4 h-96 opacity-60"
        style={{
          background:
            "radial-gradient(60% 50% at 50% 50%, color-mix(in oklab, var(--primary-glow) 18%, transparent), transparent 70%)",
        }}
        aria-hidden
      />
      <div className="relative mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="see it working"
          title={
            <>
              A local web interface, <span className="text-spectral">not a wall of flags</span>
            </>
          }
          blurb="Run ./ghost_recover and a browser opens on 127.0.0.1:3030. Long operations return a job id and are polled with a live progress bar. Images, audio and video play in place, PDFs render in an iframe and unknown formats fall back to a hex viewer."
        />

        <Reveal className="mt-10">
          <div className="flex flex-wrap gap-2">
            {shots.map((s) => (
              <button
                key={s.id}
                onClick={() => setActive(s.id)}
                className={`rounded-md border px-4 py-2 font-mono text-xs tracking-widest uppercase transition-colors ${
                  s.id === active
                    ? "border-primary/60 bg-primary/15 text-primary"
                    : "border-border bg-surface/50 text-muted-foreground hover:text-foreground"
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </Reveal>

        <Reveal delay={0.1} className="mt-6">
          <div className="panel overflow-hidden rounded-xl p-2 sm:p-3">
            <motion.img
              key={current.id}
              src={current.url}
              alt={`GHOST RECOVER — ${current.label}`}
              initial={{ opacity: 0, scale: 0.99 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5 }}
              loading="lazy"
              className="w-full rounded-lg border border-border"
            />
          </div>
          <p className="mt-3 font-mono text-xs text-muted-foreground">{current.caption}</p>
        </Reveal>

        <div className="mt-14 grid gap-5 lg:grid-cols-[1fr_1.15fr]">
          <Reveal>
            <div className="panel h-full rounded-xl p-6">
              <h3 className="text-lg font-bold">Automate it: it&apos;s an HTTP API</h3>
              <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
                The UI is a thin client over the same API. Files stream window-by-window and answer HTTP
                Range requests natively, so a player can seek through a multi-gigabyte carve without
                loading it. <code className="font-mono text-primary">max=</code> bounds a preview&apos;s
                byte budget (the response carries{" "}
                <code className="font-mono text-primary">X-Content-Truncated: 1</code>), while downloads
                always get the complete file.
              </p>
              <p className="mt-4 rounded-md border border-primary/25 bg-primary/8 p-3 font-mono text-xs text-primary">
                /api/file only serves paths under the output root — the engine will not read arbitrary
                files off the host.
              </p>
            </div>
          </Reveal>
          <Reveal delay={0.08}>
            <div className="panel h-full overflow-hidden rounded-xl">
              <div className="border-b border-border bg-surface-2/60 px-4 py-2.5 font-mono text-[11px] text-muted-foreground">
                127.0.0.1:3030 — endpoints
              </div>
              <pre className="no-scrollbar overflow-x-auto p-4 font-mono text-[11.5px] leading-6 text-muted-foreground sm:text-xs">
                {apiEndpoints.join("\n")}
              </pre>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
