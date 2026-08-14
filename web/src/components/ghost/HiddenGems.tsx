import { motion } from "motion/react";
import { Sparkles } from "lucide-react";
import { Reveal, SectionHeading } from "./Reveal";
import { hiddenGems } from "@/lib/ghost-data";

export function HiddenGems() {
  return (
    <section className="relative border-y border-border/70 bg-surface/25 py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="the details nobody advertises"
          title={
            <>
              The parts you only find <span className="text-spectral">by reading the commits</span>
            </>
          }
          blurb="Recovery software is judged on the edge cases. These are the ones GHOST RECOVER already handles."
        />

        <div className="mt-14 grid gap-5 md:grid-cols-2">
          {hiddenGems.map((g, i) => (
            <Reveal key={g.title} delay={i * 0.06}>
              <motion.div
                whileHover={{ y: -5 }}
                transition={{ type: "spring", stiffness: 280, damping: 22 }}
                className="panel relative h-full overflow-hidden rounded-xl p-6"
              >
                <span className="absolute -top-10 -right-10 h-28 w-28 rounded-full bg-primary/10 blur-2xl" />
                <div className="flex items-center gap-2 text-primary">
                  <Sparkles className="h-4 w-4" />
                  <span className="font-mono text-[10px] tracking-[0.3em] uppercase">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                </div>
                <h3 className="mt-4 text-lg font-bold">{g.title}</h3>
                <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{g.body}</p>
              </motion.div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
