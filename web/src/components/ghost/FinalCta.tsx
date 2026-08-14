import { motion } from "motion/react";
import { Github, Star, GitFork, Scale } from "lucide-react";
import logo from "@/assets/ghost-recover-logo.png";
import { REPO_URL } from "@/lib/ghost-data";
import { Reveal } from "./Reveal";

export function FinalCta() {
  return (
    <section className="relative overflow-hidden border-t border-border/70 py-24 sm:py-32">
      <div className="veil absolute inset-0" aria-hidden />
      <div className="grid-floor absolute inset-0 opacity-60" aria-hidden />
      <div className="relative mx-auto max-w-4xl px-5 text-center">
        <motion.img
          src={logo}
          alt="GHOST RECOVER logo"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
          className="screen-logo animate-float mx-auto w-28"
        />
        <Reveal>
          <h2 className="mt-6 text-3xl leading-tight font-bold text-balance sm:text-5xl">
            Deleted is not gone. <span className="text-spectral">Prove it.</span>
          </h2>
          <p className="mx-auto mt-5 max-w-2xl text-base leading-relaxed text-muted-foreground">
            Free and open source, MIT licensed. No accounts, no trials, no telemetry. Star the repo, build it in
            four commands, and keep it on the rescue USB you hope you never need.
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer"
              className="glow-ring inline-flex items-center gap-2.5 rounded-md bg-primary px-7 py-3.5 font-mono text-sm font-bold text-primary-foreground transition-transform hover:-translate-y-0.5"
            >
              <Github className="h-4 w-4" /> Open on GitHub
            </a>
            <a
              href={`${REPO_URL}/stargazers`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2.5 rounded-md border border-border bg-surface/60 px-7 py-3.5 font-mono text-sm backdrop-blur transition-colors hover:border-primary/60 hover:text-primary"
            >
              <Star className="h-4 w-4" /> Star the project
            </a>
            <a
              href={`${REPO_URL}/fork`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2.5 rounded-md border border-border bg-surface/60 px-7 py-3.5 font-mono text-sm backdrop-blur transition-colors hover:border-primary/60 hover:text-primary"
            >
              <GitFork className="h-4 w-4" /> Fork &amp; contribute
            </a>
          </div>
        </Reveal>
      </div>

      <footer className="relative mx-auto mt-20 max-w-7xl px-5">
        <div className="flex flex-col items-center justify-between gap-4 border-t border-border pt-8 sm:flex-row">
          <p className="font-mono text-xs text-muted-foreground">
            GHOST RECOVER · Linux data recovery engine
          </p>
          <p className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
            <Scale className="h-3.5 w-3.5" /> MIT © 2026 Naveenkumar D · vendored cpp-httplib keeps its own MIT
            notice
          </p>
        </div>
      </footer>
    </section>
  );
}
