import { useEffect, useRef, useState } from "react";
import { useInView } from "motion/react";
import { stats } from "@/lib/ghost-data";

function Counter({ to, suffix }: { to: number; suffix: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });
  const [n, setN] = useState(0);

  useEffect(() => {
    if (!inView) return;
    const start = performance.now();
    const dur = 1400;
    let raf = 0;
    const step = (t: number) => {
      const p = Math.min(1, (t - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      setN(Math.round(to * eased));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [inView, to]);

  return (
    <span ref={ref} className="text-spectral font-mono text-4xl font-bold sm:text-5xl">
      {n}
      {suffix}
    </span>
  );
}

export function Stats() {
  return (
    <section className="relative border-y border-border/70 bg-surface/30">
      <div className="mx-auto grid max-w-7xl gap-8 px-5 py-12 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((s) => (
          <div key={s.label} className="border-l border-primary/30 pl-5">
            <Counter to={s.value} suffix={s.suffix} />
            <p className="mt-2 text-sm font-semibold">{s.label}</p>
            <p className="font-mono text-xs text-muted-foreground">{s.sub}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
