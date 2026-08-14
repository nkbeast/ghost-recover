import { ShieldAlert, ShieldCheck, Bug, FlaskConical } from "lucide-react";
import { Reveal, SectionHeading } from "./Reveal";

const rules = [
  {
    icon: ShieldAlert,
    title: "Never write back to the source",
    body: "Writing recovered files onto the disk you are recovering from overwrites the free space still holding the rest of your data. The engine refuses this outright — for recovery, carving and imaging — rather than warning about it.",
  },
  {
    icon: ShieldCheck,
    title: "Clone the dying drive first",
    body: "If a drive is making noises or throwing I/O errors, run ghost_recover image and recover from the clone. Bad-sector retries and a resumable map file mean you can stop and continue.",
  },
  {
    icon: Bug,
    title: "Repairs are dry runs",
    body: "Every repair is a dry run unless you pass apply, and the original sectors are saved first. Nothing is written anywhere unless you started the engine with --allow-writes.",
  },
];

export function Proof() {
  return (
    <section id="proof" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="working safely"
          title={
            <>
              Recovery attempts destroy data. <span className="text-spectral">This one can&apos;t.</span>
            </>
          }
        />

        <div className="mt-12 grid gap-4 md:grid-cols-3">
          {rules.map((r, i) => (
            <Reveal key={r.title} delay={i * 0.08}>
              <div className="panel h-full rounded-xl border-t-2 border-t-accent/60 p-6">
                <r.icon className="h-5 w-5 text-accent" />
                <h3 className="mt-4 text-base font-bold">{r.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{r.body}</p>
              </div>
            </Reveal>
          ))}
        </div>

        <div className="mt-20 grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <Reveal>
            <div className="panel h-full rounded-xl p-6 sm:p-8">
              <div className="flex items-center gap-2 text-primary">
                <FlaskConical className="h-4 w-4" />
                <span className="font-mono text-[11px] tracking-[0.3em] uppercase">
                  testing &amp; verification
                </span>
              </div>
              <h3 className="mt-4 text-2xl font-bold">
                88 automated checks. <span className="text-spectral">0 failures.</span>
              </h3>
              <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
                The suite builds real ext4/ext2/NTFS/FAT32/exFAT/Btrfs/XFS/ISO/UDF/SquashFS/cramfs/MINIX/JFFS2
                filesystems from a known corpus — no mounting, no root — deletes files from some of them, then
                checks that the engine identifies each filesystem, finds the deleted files, and writes every
                recovered file back out <strong className="text-foreground">byte-for-byte identical</strong> to
                the original, verified by <strong className="text-foreground">MD5, not by the engine&apos;s own
                reporting</strong>.
              </p>
              <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
                The Btrfs fixture rewrites real extents as compressed ones (inline zlib/lzo/zstd, regular zlib
                extents) and the NTFS fixture stores one file as an LZNT1 stream, so the compressed-content
                paths are proven against the same corpus. Also covered: MBR logical partitions, partition
                recovery after wiping both GPT copies, RAID 0/5 geometry recovery from data alone, parity
                rebuild of a destroyed member, superblock repair (dry run vs apply), bad-sector imaging, the
                refusal to write onto the source disk, and corrupt / truncated / random images handled without
                crashing or being misidentified.
              </p>
              <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
                Static analysis runs clang-tidy with the <code className="font-mono text-primary">bugprone*</code>,{" "}
                <code className="font-mono text-primary">clang-analyzer*</code> and{" "}
                <code className="font-mono text-primary">misc-const-correctness</code> groups, and the suite also
                runs under <strong className="text-foreground">ASan/UBSan</strong> — this tool parses hostile
                on-disk structures for a living, so memory safety is tested, not assumed.
              </p>
            </div>
          </Reveal>

          <Reveal delay={0.08}>
            <div className="panel h-full overflow-hidden rounded-xl">
              <div className="border-b border-border bg-surface-2/60 px-4 py-2.5 font-mono text-[11px] text-muted-foreground">
                ./tests/verify.sh
              </div>
              <pre className="no-scrollbar overflow-x-auto p-4 font-mono text-[11.5px] leading-6">
                <span className="text-primary">$ ./tests/verify.sh</span>
                {"\n"}
                <span className="text-muted-foreground">
                  {`building fixtures (no mount, no root) ......... ok
ext4 / ext2 / ext3 ........................... pass
NTFS (+ LZNT1 stream) ........................ pass
FAT32 / exFAT / VFAT ......................... pass
Btrfs (zlib · lzo · zstd · inline) ........... pass
XFS / MINIX / cramfs / JFFS2 ................. pass
ISO 9660 / UDF ............................... pass
partition recovery (both GPT copies wiped) ... pass
RAID 0/5 geometry from data alone ............ pass
parity rebuild of destroyed member ........... pass
refuses to write onto source disk ............ pass
md5 byte-for-byte on every recovered file .... pass`}
                </span>
                {"\n"}
                <span className="text-primary">88 checks · 0 failures</span>
                <span className="ml-1 inline-block h-3.5 w-1.5 animate-blink bg-primary align-middle" />
              </pre>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
