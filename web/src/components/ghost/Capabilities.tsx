import { motion } from "motion/react";
import { FolderTree, Scan, Layers, HardDrive, Wrench, Cpu, type LucideIcon } from "lucide-react";
import { Reveal, SectionHeading } from "./Reveal";
import { capabilities } from "@/lib/ghost-data";

const icons: Record<string, LucideIcon> = { FolderTree, Scan, Layers, HardDrive, Wrench, Cpu };

export function Capabilities() {
  return (
    <section id="capabilities" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="one engine, every technique"
          title={
            <>
              Everything a recovery lab does, <span className="text-spectral">in one binary</span>
            </>
          }
          blurb="Most tools do one trick. GHOST RECOVER combines the metadata walk, the byte-level carve and the geometry rebuild — three complementary passes so nothing is missed."
        />

        <div className="mt-14 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {capabilities.map((c, i) => {
            const Icon = icons[c.icon] ?? Scan;
            return (
              <Reveal key={c.title} delay={i * 0.07}>
                <motion.article
                  whileHover={{ y: -6 }}
                  transition={{ type: "spring", stiffness: 300, damping: 22 }}
                  className="panel group h-full rounded-xl p-6 transition-colors hover:border-primary/50"
                >
                  <div className="flex items-start justify-between gap-4">
                    <span className="flex h-11 w-11 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary transition-shadow group-hover:shadow-[0_0_28px_-6px_color-mix(in_oklab,var(--primary)_60%,transparent)]">
                      <Icon className="h-5 w-5" />
                    </span>
                    <span className="rounded border border-border bg-surface-2/60 px-2 py-1 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                      {c.tag}
                    </span>
                  </div>
                  <h3 className="mt-5 text-lg font-bold">{c.title}</h3>
                  <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{c.body}</p>
                </motion.article>
              </Reveal>
            );
          })}
        </div>
      </div>
    </section>
  );
}
