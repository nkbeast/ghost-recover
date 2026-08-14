import { motion } from "motion/react";
import {
  Cpu,
  Database,
  FileSearch,
  HardDrive,
  Layers,
  ListTree,
  Lock,
  Monitor,
  Server,
  Terminal,
} from "lucide-react";
import type { ComponentType } from "react";

type Node = { icon: ComponentType<{ className?: string }>; label: string; note: string };

const layers: { id: string; kicker: string; tone: "primary" | "accent" | "muted"; nodes: Node[] }[] =
  [
    {
      id: "surface",
      kicker: "interfaces",
      tone: "primary",
      nodes: [
        { icon: Monitor, label: "Web UI", note: "127.0.0.1:3030" },
        { icon: Terminal, label: "CLI", note: "./ghost_recover" },
        { icon: Server, label: "HTTP API", note: "/api/*" },
      ],
    },
    {
      id: "core",
      kicker: "engine core",
      tone: "accent",
      nodes: [
        { icon: Cpu, label: "Job orchestrator", note: "async jobs + live progress" },
        { icon: Layers, label: "Streaming window", note: "1 GiB RAM budget" },
      ],
    },
    {
      id: "passes",
      kicker: "recovery passes",
      tone: "primary",
      nodes: [
        { icon: ListTree, label: "Filesystem walk", note: "44 filesystems" },
        { icon: FileSearch, label: "Signature carving", note: "315 carvers" },
        { icon: HardDrive, label: "Partition & RAID", note: "geometry rebuild" },
      ],
    },
    {
      id: "io",
      kicker: "device layer",
      tone: "muted",
      nodes: [
        { icon: Lock, label: "Read-only access", note: "no writes to source" },
        { icon: Database, label: "Imaging & output root", note: "sparse images, logs" },
      ],
    },
  ];

const toneClass = {
  primary: "text-primary border-primary/35 bg-primary/8",
  accent: "text-accent border-accent/35 bg-accent/8",
  muted: "text-muted-foreground border-border bg-surface/50",
} as const;

function Connector({ delay }: { delay: number }) {
  return (
    <div className="relative mx-auto h-10 w-px overflow-hidden bg-border" aria-hidden>
      <motion.span
        className="absolute inset-x-[-1px] h-4 rounded-full"
        style={{
          background:
            "linear-gradient(to bottom, transparent, color-mix(in oklab, var(--primary) 90%, transparent), transparent)",
        }}
        initial={{ y: -18 }}
        animate={{ y: 42 }}
        transition={{ duration: 1.6, repeat: Infinity, ease: "linear", delay }}
      />
    </div>
  );
}

export function ArchitectureDiagram() {
  return (
    <div className="panel relative overflow-hidden rounded-xl p-5 sm:p-8">
      <div className="grid-floor pointer-events-none absolute inset-0 opacity-40" aria-hidden />
      <div className="relative">
        {layers.map((layer, li) => (
          <div key={layer.id}>
            <motion.div
              initial={{ opacity: 0, y: 18, filter: "blur(6px)" }}
              whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ duration: 0.6, delay: li * 0.12, ease: [0.16, 1, 0.3, 1] }}
            >
              <p className="mb-3 text-center font-mono text-[11px] tracking-[0.35em] text-muted-foreground uppercase">
                {layer.kicker}
              </p>
              <div
                className={`grid gap-3 ${layer.nodes.length === 3 ? "sm:grid-cols-3" : "sm:grid-cols-2"}`}
              >
                {layer.nodes.map((n) => (
                  <motion.div
                    key={n.label}
                    whileHover={{ y: -4 }}
                    transition={{ type: "spring", stiffness: 320, damping: 22 }}
                    className={`rounded-lg border p-4 backdrop-blur-sm ${toneClass[layer.tone]}`}
                  >
                    <n.icon className="h-5 w-5" />
                    <p className="mt-3 text-sm font-bold text-foreground">{n.label}</p>
                    <p className="mt-1 font-mono text-[11px] text-muted-foreground">{n.note}</p>
                  </motion.div>
                ))}
              </div>
            </motion.div>
            {li < layers.length - 1 ? <Connector delay={li * 0.4} /> : null}
          </div>
        ))}
      </div>
    </div>
  );
}
