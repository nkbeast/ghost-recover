import { useEffect, useMemo, useState } from "react";
import { motion } from "motion/react";
import { Github, Terminal, ShieldCheck, ArrowDown } from "lucide-react";
import logo from "@/assets/ghost-recover-logo.png.asset.json";
import { REPO_URL } from "@/lib/ghost-data";

const lines = [
  "$ sudo ghost_recover scan /dev/sda2 --deleted",
  "  detect: ext4 (journal present) · 44 fs drivers loaded",
  "  jbd2 journal mining ......... 2,481 extent trees",
  "  orphan inodes ............... 1,096 candidates",
  "  dir-entry slack ............. 318 names rebuilt",
  "  found 3,895 deleted files with full paths",
  "$ sudo ghost_recover carve /dev/sda2 --out ~/carved",
  "  aho-corasick: 315 signatures · single pass",
  "  entropy screen + content-hash dedup .. ok",
  "  recovered 12,704 files at true size",
];

function useTypewriter(all: string[]) {
  const [shown, setShown] = useState<string[]>([]);
  const [partial, setPartial] = useState("");

  useEffect(() => {
    let li = 0;
    let ci = 0;
    let cancelled = false;

    const tick = () => {
      if (cancelled) return;
      const line = all[li % all.length] ?? "";
      ci += 1;
      if (ci <= line.length) {
        setPartial(line.slice(0, ci));
        window.setTimeout(tick, 14);
      } else {
        setShown((s) => [...s.slice(-8), line]);
        setPartial("");
        li += 1;
        if (li >= all.length) {
          window.setTimeout(() => {
            if (cancelled) return;
            setShown([]);
            li = 0;
            ci = 0;
            tick();
          }, 2600);
          return;
        }
        ci = 0;
        window.setTimeout(tick, 320);
      }
    };
    const t = window.setTimeout(tick, 700);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [all]);

  return { shown, partial };
}

function Pixels() {
  const bits = useMemo(
    () =>
      Array.from({ length: 26 }, (_, i) => ({
        left: 6 + ((i * 37) % 88),
        top: 32 + ((i * 53) % 62),
        size: 3 + (i % 4) * 2,
        delay: (i % 9) * 0.55,
        dur: 6 + (i % 5),
      })),
    [],
  );
  return (
    <div className="pointer-events-none absolute inset-0" aria-hidden>
      {bits.map((b, i) => (
        <span
          key={i}
          className="absolute rounded-[1px] bg-primary"
          style={{
            left: `${b.left}%`,
            top: `${b.top}%`,
            width: b.size,
            height: b.size,
            animation: `drift ${b.dur}s ease-in-out ${b.delay}s infinite`,
            boxShadow: "0 0 10px color-mix(in oklab, var(--primary) 70%, transparent)",
          }}
        />
      ))}
    </div>
  );
}

export function Hero() {
  const { shown, partial } = useTypewriter(lines);

  return (
    <section id="top" className="relative overflow-hidden pt-32 pb-20 sm:pt-40 sm:pb-28">
      <div className="veil absolute inset-0" aria-hidden />
      <div className="grid-floor absolute inset-0 opacity-70" aria-hidden />
      <Pixels />

      <div className="relative mx-auto grid max-w-7xl items-center gap-14 px-5 lg:grid-cols-[1.05fr_0.95fr]">
        <div>
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center gap-2 rounded-full border border-primary/40 bg-primary/10 px-3.5 py-1.5 font-mono text-[11px] tracking-[0.2em] text-primary uppercase"
          >
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-primary" />
            </span>
            MIT · C++17 · Linux · read-only first
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.75, delay: 0.06 }}
            className="mt-7 text-4xl leading-[1.03] font-bold tracking-tight text-balance sm:text-6xl lg:text-7xl"
          >
            Your files are still
            <br />
            on that disk.
            <br />
            <span className="text-spectral">Go get them.</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.75, delay: 0.16 }}
            className="mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground"
          >
            GHOST RECOVER is an all-in-one Linux data recovery engine: it walks the raw metadata of{" "}
            <strong className="font-semibold text-foreground">44 filesystems</strong>, carves{" "}
            <strong className="font-semibold text-foreground">315 file formats</strong> by signature,
            reassembles broken RAID arrays, clones failing drives and repairs damaged disks — with a web
            interface, a CLI and an HTTP API.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.75, delay: 0.26 }}
            className="mt-9 flex flex-wrap items-center gap-3"
          >
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer"
              className="glow-ring group inline-flex items-center gap-2.5 rounded-md bg-primary px-6 py-3.5 font-mono text-sm font-bold tracking-wide text-primary-foreground transition-transform hover:-translate-y-0.5"
            >
              <Github className="h-4 w-4" />
              Clone the repo
            </a>
            <a
              href="#start"
              className="inline-flex items-center gap-2.5 rounded-md border border-border bg-surface/60 px-6 py-3.5 font-mono text-sm tracking-wide text-foreground backdrop-blur transition-colors hover:border-primary/60 hover:text-primary"
            >
              <Terminal className="h-4 w-4" />
              Build in 4 commands
            </a>
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.4 }}
            className="mt-8 flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-xs text-muted-foreground"
          >
            <span className="inline-flex items-center gap-2 text-primary">
              <ShieldCheck className="h-3.5 w-3.5" /> refuses to write to the source disk
            </span>
            <span>88 checks · 0 failures</span>
            <span>runs on 1 GiB RAM</span>
            <span>no telemetry</span>
          </motion.div>
        </div>

        <div className="relative">
          <motion.img
            src={logo.url}
            alt="GHOST RECOVER ghost logo dissolving into data pixels"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1 }}
            className="screen-logo animate-float pointer-events-none absolute -top-40 right-0 hidden w-52 opacity-80 lg:block xl:w-60"
          />
          <motion.div
            initial={{ opacity: 0, y: 28, rotateX: 8 }}
            animate={{ opacity: 1, y: 0, rotateX: 0 }}
            transition={{ duration: 0.9, delay: 0.2 }}
            className="panel relative overflow-hidden rounded-xl"
          >
            <div className="flex items-center gap-2 border-b border-border bg-surface-2/60 px-4 py-2.5">
              <span className="h-2.5 w-2.5 rounded-full bg-danger/80" />
              <span className="h-2.5 w-2.5 rounded-full bg-accent/80" />
              <span className="h-2.5 w-2.5 rounded-full bg-primary/80" />
              <span className="ml-2 font-mono text-[11px] text-muted-foreground">
                ghost_recover — live scan
              </span>
            </div>
            <div className="relative h-[340px] overflow-hidden px-4 py-4 font-mono text-[12px] leading-6 sm:text-[13px]">
              <div
                className="pointer-events-none absolute inset-x-0 top-0 h-16 opacity-40"
                style={{
                  background:
                    "linear-gradient(180deg, transparent, color-mix(in oklab, var(--primary) 30%, transparent), transparent)",
                  animation: "scan 6s linear infinite",
                }}
                aria-hidden
              />
              {shown.map((l, i) => (
                <div
                  key={`${l}-${i}`}
                  className={l.startsWith("$") ? "text-primary" : "text-muted-foreground"}
                >
                  {l}
                </div>
              ))}
              {partial ? (
                <div className={partial.startsWith("$") ? "text-primary" : "text-muted-foreground"}>
                  {partial}
                  <span className="ml-0.5 inline-block h-3.5 w-1.5 animate-blink bg-primary align-middle" />
                </div>
              ) : null}
            </div>
          </motion.div>
        </div>
      </div>

      <div className="relative mx-auto mt-16 flex max-w-7xl justify-center px-5">
        <a
          href="#capabilities"
          className="inline-flex items-center gap-2 font-mono text-[11px] tracking-[0.3em] text-muted-foreground uppercase transition-colors hover:text-primary"
        >
          <ArrowDown className="h-3.5 w-3.5 animate-bounce" /> scroll
        </a>
      </div>
    </section>
  );
}
