import { motion } from "motion/react";
import { Reveal, SectionHeading } from "./Reveal";
import { fsFamilies, fsIdentifiedOnly, deletionTechniques } from "@/lib/ghost-data";

export function Filesystems() {
  return (
    <section id="filesystems" className="relative border-y border-border/70 bg-surface/25 py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="44 filesystems · 20 walked families"
          title={
            <>
              It reads the metadata, <span className="text-spectral">so paths come back too</span>
            </>
          }
          blurb="Every driver reconstructs full directory paths and describes files as extent lists — so fragmented files come out intact, not corrupted."
        />

        <div className="mt-14 grid gap-5 lg:grid-cols-5">
          {fsFamilies.map((f, i) => (
            <Reveal key={f.group} delay={i * 0.06}>
              <div className="panel h-full rounded-xl p-5">
                <p className="font-mono text-[11px] tracking-[0.25em] text-primary uppercase">{f.group}</p>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {f.items.map((it) => (
                    <motion.span
                      key={it}
                      whileHover={{ scale: 1.06 }}
                      className="rounded border border-border bg-surface-2/70 px-2 py-1 font-mono text-[11px] text-foreground/90"
                    >
                      {it}
                    </motion.span>
                  ))}
                </div>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal className="mt-6">
          <div className="panel rounded-xl p-6">
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <h3 className="text-base font-bold">
                Identified so you know what you&apos;re actually looking at
              </h3>
              <span className="font-mono text-[11px] text-muted-foreground">
                detection only — reported honestly
              </span>
            </div>
            <div className="mt-4 flex flex-wrap gap-1.5">
              {fsIdentifiedOnly.map((f) => (
                <span
                  key={f}
                  className="rounded border border-border/70 bg-background/60 px-2 py-1 font-mono text-[11px] text-muted-foreground"
                >
                  {f}
                </span>
              ))}
            </div>
            <p className="mt-4 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              ZFS is parsed at the vdev-label / uberblock level. File-level recovery would need a full DMU
              traversal, so the engine says so instead of pretending — and points you at{" "}
              <code className="font-mono text-primary">zpool import -o readonly=on</code> or signature
              carving as the working alternatives.
            </p>
          </div>
        </Reveal>

        <div className="mt-20">
          <SectionHeading
            kicker="recover deleted files"
            title={
              <>
                Each filesystem gets the techniques that{" "}
                <span className="text-spectral">actually apply to it</span>
              </>
            }
          />
          <div className="mt-10 grid gap-3">
            {deletionTechniques.map((t, i) => (
              <Reveal key={t.fs} delay={Math.min(i * 0.04, 0.3)}>
                <div className="panel group grid gap-2 rounded-lg p-4 transition-colors hover:border-primary/50 sm:grid-cols-[200px_1fr] sm:items-center sm:gap-6">
                  <span className="font-mono text-sm font-bold text-primary">{t.fs}</span>
                  <span className="text-sm leading-relaxed text-muted-foreground">{t.tech}</span>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
