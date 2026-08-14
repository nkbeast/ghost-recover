import { useState } from "react";
import { Check, Copy, Terminal } from "lucide-react";
import { Reveal, SectionHeading } from "./Reveal";
import { buildSteps, cliCommands } from "@/lib/ghost-data";

function CopyBlock({ lines, label }: { lines: string[]; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="panel overflow-hidden rounded-xl">
      <div className="flex items-center justify-between border-b border-border bg-surface-2/60 px-4 py-2.5">
        <span className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
          <Terminal className="h-3.5 w-3.5" /> {label}
        </span>
        <button
          onClick={copy}
          className="inline-flex items-center gap-1.5 rounded border border-border px-2 py-1 font-mono text-[10px] tracking-widest text-muted-foreground uppercase transition-colors hover:border-primary/60 hover:text-primary"
        >
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? "copied" : "copy"}
        </button>
      </div>
      <pre className="no-scrollbar overflow-x-auto p-4 font-mono text-[11.5px] leading-6 sm:text-xs">
        {lines.map((l) => (
          <div key={l} className={l.startsWith("#") ? "text-muted-foreground" : "text-foreground/90"}>
            {l}
          </div>
        ))}
      </pre>
    </div>
  );
}

export function GetStarted() {
  return (
    <section id="start" className="relative border-y border-border/70 bg-surface/25 py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="quick start"
          title={
            <>
              Clone, build, <span className="text-spectral">recover</span>
            </>
          }
          blurb="Needs a C++17 compiler and CMake ≥ 3.16. zlib is optional (SquashFS/cramfs/JFFS2 decompression); zstd is too (Btrfs zstd extents). Recovered files go to $GHOST_OUTPUT, or ~/ghost-recover-output."
        />

        <div className="mt-12 grid gap-5 lg:grid-cols-2">
          <Reveal>
            <CopyBlock lines={buildSteps} label="build" />
          </Reveal>
          <Reveal delay={0.08}>
            <CopyBlock lines={cliCommands.map((c) => c.cmd)} label="command line" />
          </Reveal>
        </div>

        <div className="mt-6 grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {cliCommands.map((c, i) => (
            <Reveal key={c.cmd} delay={Math.min(i * 0.05, 0.25)}>
              <div className="panel h-full rounded-lg p-4">
                <code className="block font-mono text-[11px] break-words text-primary">{c.cmd}</code>
                <p className="mt-2 text-xs text-muted-foreground">{c.note}</p>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal className="mt-8">
          <div className="panel rounded-xl p-6">
            <h3 className="text-base font-bold">Locked disk? It unlocks itself, safely.</h3>
            <p className="mt-3 max-w-4xl text-sm leading-relaxed text-muted-foreground">
              Reading a physical disk needs root. Pick a locked disk and the interface offers to unlock it: it
              launches a privileged copy of itself and hands over the port, so the browser reconnects to the
              same page with full disk access. It prefers <strong className="text-foreground">pkexec</strong> —
              your desktop&apos;s own authentication dialog, so the password never passes through this program —
              and where polkit is unavailable it falls back to a sudo password, used once and never stored.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
