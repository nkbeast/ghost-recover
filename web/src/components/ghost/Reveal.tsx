import { motion } from "motion/react";
import type { ReactNode } from "react";

type Props = {
  children: ReactNode;
  delay?: number;
  y?: number;
  className?: string;
};

export function Reveal({ children, delay = 0, y = 26, className }: Props) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y, filter: "blur(6px)" }}
      whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  );
}

export function SectionHeading({
  kicker,
  title,
  blurb,
  align = "left",
}: {
  kicker: string;
  title: ReactNode;
  blurb?: string;
  align?: "left" | "center";
}) {
  return (
    <Reveal className={align === "center" ? "mx-auto max-w-3xl text-center" : "max-w-3xl"}>
      <p className="font-mono text-xs tracking-[0.35em] text-primary uppercase">{kicker}</p>
      <h2 className="mt-4 text-3xl leading-tight font-bold text-balance sm:text-4xl md:text-5xl">
        {title}
      </h2>
      {blurb ? <p className="mt-5 text-base leading-relaxed text-muted-foreground">{blurb}</p> : null}
    </Reveal>
  );
}
