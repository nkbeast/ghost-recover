import { motion } from "motion/react";
import { Reveal, SectionHeading } from "./Reveal";
import { carveCategories } from "@/lib/ghost-data";

const marquee = [
  "JPEG","PNG","GIF","TIFF","WebP","HEIC","JXL","CR2","NEF","ARW","DNG","MP4","MKV","MOV","AVI","FLV","ASF",
  "MPEG-TS","MP3","AAC","FLAC","OGG","WAV","PDF","OLE2","DOCX","ODF","RTF","ZIP","7z","RAR","tar","CAB","XAR",
  "SQLite","dBase","ESEDB","EVTX","REG","ELF","PE","Mach-O","WASM","DEX","pcap","pcapng","E01","AFF","DMP","PLY","NES",
];

export function Carving() {
  return (
    <section id="carving" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="315 signatures · 14 categories"
          title={
            <>
              No filesystem? <span className="text-spectral">Doesn&apos;t matter.</span>
            </>
          }
          blurb="One Aho-Corasick pass over the device instead of one search per signature. Formats that describe their own length are walked structurally, so files come out at their true size instead of a fixed guess. Results are entropy-screened, deduplicated by content hash, and can be restricted to free space."
        />
      </div>

      <Reveal className="mt-12">
        <div className="relative overflow-hidden border-y border-border/70 bg-surface/40 py-4">
          <div className="flex w-max animate-marquee gap-3 will-change-transform">
            {[...marquee, ...marquee].map((f, i) => (
              <span
                key={`${f}-${i}`}
                className="rounded border border-border bg-background/60 px-3 py-1.5 font-mono text-xs text-muted-foreground"
              >
                {f}
              </span>
            ))}
          </div>
          <div
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                "linear-gradient(90deg, var(--background), transparent 12%, transparent 88%, var(--background))",
            }}
            aria-hidden
          />
        </div>
      </Reveal>

      <div className="mx-auto mt-12 max-w-7xl px-5">
        <div className="grid gap-4 md:grid-cols-2">
          {carveCategories.map((c, i) => (
            <Reveal key={c.name} delay={Math.min(i * 0.04, 0.3)}>
              <motion.div
                whileHover={{ x: 4 }}
                className="panel rounded-lg border-l-2 border-l-primary/60 p-4"
              >
                <p className="text-sm font-bold">{c.name}</p>
                <p className="mt-2 font-mono text-[11.5px] leading-6 text-muted-foreground">{c.formats}</p>
              </motion.div>
            </Reveal>
          ))}
        </div>

        <Reveal className="mt-8">
          <div className="panel rounded-xl p-6 sm:p-8">
            <h3 className="text-lg font-bold">One source file per format family</h3>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              The registry grew from 263 to 315 signatures and was refactored from 14 category files into 175
              per-format translation units — with 31 new structural walkers (ARJ, ARC, PAK, WAD, QED, Android
              boot, EWF, minidump, PNM, SGI, XPM, CRW, NSV, WTV, NES, dBase and more) and matching fixtures.
              Registry output stayed byte-identical.
            </p>
            <div className="mt-5 grid gap-3 font-mono text-xs sm:grid-cols-3">
              <div className="rounded-md border border-primary/25 bg-primary/8 p-3 text-primary">
                315/315 fixtures green
              </div>
              <div className="rounded-md border border-primary/25 bg-primary/8 p-3 text-primary">
                dense-disk e2e 292/292 byte-exact
              </div>
              <div className="rounded-md border border-primary/25 bg-primary/8 p-3 text-primary">
                2M candidate cap stays meaningful
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
