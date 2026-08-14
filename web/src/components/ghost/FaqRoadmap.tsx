import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { ChevronDown, GitBranch } from "lucide-react";
import { Reveal, SectionHeading } from "./Reveal";
import { faqs, roadmap } from "@/lib/ghost-data";

export function FaqRoadmap() {
  const [open, setOpen] = useState<number | null>(0);

  return (
    <section className="relative py-24 sm:py-32">
      <div className="mx-auto grid max-w-7xl gap-14 px-5 lg:grid-cols-[1.15fr_0.85fr]">
        <div>
          <SectionHeading kicker="faq" title="Questions people actually ask" />
          <div className="mt-10 grid gap-3">
            {faqs.map((f, i) => (
              <Reveal key={f.q} delay={Math.min(i * 0.04, 0.2)}>
                <div className="panel overflow-hidden rounded-lg">
                  <button
                    onClick={() => setOpen(open === i ? null : i)}
                    className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left"
                  >
                    <span className="text-sm font-semibold">{f.q}</span>
                    <ChevronDown
                      className={`h-4 w-4 shrink-0 text-primary transition-transform duration-300 ${
                        open === i ? "rotate-180" : ""
                      }`}
                    />
                  </button>
                  <AnimatePresence initial={false}>
                    {open === i ? (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                        className="overflow-hidden"
                      >
                        <p className="px-5 pb-4 text-sm leading-relaxed text-muted-foreground">{f.a}</p>
                      </motion.div>
                    ) : null}
                  </AnimatePresence>
                </div>
              </Reveal>
            ))}
          </div>
        </div>

        <div>
          <SectionHeading kicker="roadmap" title="What's next" />
          <Reveal className="mt-10">
            <div className="panel rounded-xl p-6">
              <ul className="grid gap-4">
                {roadmap.map((r) => (
                  <li key={r} className="flex gap-3 text-sm text-muted-foreground">
                    <GitBranch className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                    <span className="leading-relaxed">{r}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-6 border-t border-border pt-4 text-sm text-foreground">
                Contributions toward any of these are very welcome. CI builds and runs the full verification
                suite on every pull request.
              </p>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
