import { Reveal, SectionHeading } from "./Reveal";
import { projectLayout } from "@/lib/ghost-data";
import arch from "@/assets/ghost-recover-architecture.png.asset.json";

const passes = [
  {
    n: "01",
    title: "Filesystem metadata walk",
    body: "Reads the live and deleted structures of the filesystem to rebuild the directory tree exactly as it was.",
  },
  {
    n: "02",
    title: "Signature carving",
    body: "A byte-level sweep that finds files by content — works even when the filesystem is gone, formatted over or corrupted.",
  },
  {
    n: "03",
    title: "Partition & geometry recovery",
    body: "Finds lost partitions and works out RAID geometry when the metadata is destroyed.",
  },
];

export function Architecture() {
  return (
    <section className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="how it works"
          title={
            <>
              Three complementary passes, <span className="text-spectral">so nothing is missed</span>
            </>
          }
        />

        <div className="mt-12 grid gap-4 md:grid-cols-3">
          {passes.map((p, i) => (
            <Reveal key={p.n} delay={i * 0.08}>
              <div className="panel h-full rounded-xl p-6">
                <span className="text-spectral font-mono text-3xl font-bold">{p.n}</span>
                <h3 className="mt-3 text-base font-bold">{p.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{p.body}</p>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={0.1} className="mt-8">
          <div className="panel overflow-hidden rounded-xl p-2 sm:p-3">
            <img
              src={arch.url}
              alt="GHOST RECOVER engine architecture: filesystem scanning, data carving, RAID, imaging and repair"
              loading="lazy"
              className="w-full rounded-lg border border-border"
            />
          </div>
        </Reveal>

        <Reveal delay={0.14} className="mt-8">
          <div className="panel overflow-hidden rounded-xl">
            <div className="border-b border-border bg-surface-2/60 px-4 py-2.5 font-mono text-[11px] text-muted-foreground">
              project layout
            </div>
            <div className="divide-y divide-border/70">
              {projectLayout.map(([path, desc]) => (
                <div key={path} className="grid gap-1 px-4 py-3 sm:grid-cols-[210px_1fr] sm:gap-4">
                  <code className="font-mono text-xs text-primary">{path}</code>
                  <span className="text-xs text-muted-foreground sm:text-sm">{desc}</span>
                </div>
              ))}
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
