export const REPO_URL = "https://github.com/nkbeast/ghost-recover";

export const stats = [
  { value: 44, suffix: "", label: "filesystems identified", sub: "20 families fully walked" },
  { value: 315, suffix: "", label: "carver signatures", sub: "14 categories, one AC pass" },
  { value: 88, suffix: "", label: "automated checks", sub: "0 failures, MD5-verified" },
  { value: 1, suffix: " GiB", label: "minimum RAM", sub: "RAM-aware thread pools" },
];

export const capabilities = [
  {
    icon: "FolderTree",
    title: "Filesystem & deleted-file recovery",
    body: "Walks raw metadata of 44 filesystems to rebuild full directory paths — from the journal, orphan inodes, directory slack, MFT slack and FAT1/FAT2 differencing. Not just \"scan free space\".",
    tag: "44 filesystems",
  },
  {
    icon: "Scan",
    title: "RAW signature carving",
    body: "315 formats across 14 categories matched in a single Aho-Corasick sweep, with structural length validation, entropy screening and content-hash dedup. Works with no filesystem at all.",
    tag: "315 formats",
  },
  {
    icon: "Layers",
    title: "RAID reassembly",
    body: "Reads md superblocks 0.90 and 1.x, or derives chunk size, member order and parity layout blind — then rebuilds a missing member from parity. Linear, RAID 0/1/5/6/10.",
    tag: "0 · 1 · 5 · 6 · 10",
  },
  {
    icon: "HardDrive",
    title: "Failing-drive imaging",
    body: "ddrescue-style cloning with a resumable map file, large reads on the good pass and sector-by-sector retries over bad areas. Image the dying drive first, recover from the clone.",
    tag: "resumable map",
  },
  {
    icon: "Wrench",
    title: "Filesystem repair",
    body: "Restores ext superblocks, FAT/exFAT boot regions, NTFS boot sectors and GPT headers from backups, and rebuilds an MBR from recovered partitions. Dry run until you say apply.",
    tag: "dry-run first",
  },
  {
    icon: "Cpu",
    title: "Built for low-end hardware",
    body: "Candidate limits, caches and thread pools scale with installed memory. Jobs run one at a time in a fair queue and the progress bar reports honest byte- and candidate-based percentages.",
    tag: "1 GiB RAM",
  },
];

export const fsFamilies = [
  {
    group: "Linux",
    items: [
      "ext2",
      "ext3",
      "ext4",
      "XFS",
      "Btrfs",
      "F2FS",
      "ReiserFS",
      "JFS",
      "MINIX",
      "UFS/UFS2",
      "romfs",
      "cramfs",
    ],
  },
  { group: "Windows", items: ["NTFS", "FAT12", "FAT16", "FAT32", "VFAT", "exFAT"] },
  { group: "Apple", items: ["APFS", "HFS+", "HFS", "HFSX"] },
  { group: "Optical", items: ["ISO 9660 (Joliet + Rock Ridge)", "UDF"] },
  { group: "Embedded", items: ["SquashFS", "JFFS2"] },
];

export const fsIdentifiedOnly = [
  "BCachefs",
  "NILFS2",
  "EROFS",
  "UBIFS",
  "YAFFS2",
  "OCFS2",
  "GFS2",
  "SysV",
  "Xiafs",
  "Reiser4",
  "Linux swap",
  "LUKS",
  "LVM2",
  "md RAID",
  "VMFS",
  "ReFS",
  "ZFS (vdev label / uberblock)",
];

export const deletionTechniques = [
  {
    fs: "ext2/3/4",
    tech: "deleted inodes (i_dtime), jbd2 journal mining for extent trees unlink() cleared, directory-entry slack, orphan inode list, backup superblocks",
  },
  {
    fs: "NTFS",
    tech: "unused MFT records, $I30 index slack, $UsnJrnl change journal, $MFTMirr and backup-boot-sector fallbacks, alternate data streams",
  },
  {
    fs: "FAT / VFAT",
    tech: "0xE5 entries, long-name reassembly, first-character recovery from the LFN checksum, FAT1/FAT2 differencing, directory slack, orphaned cluster chains",
  },
  { fs: "exFAT", tech: "directory entry sets with the in-use bit cleared, contiguous-stream reconstruction" },
  { fs: "Btrfs / APFS", tech: "copy-on-write leaves from superseded generations" },
  { fs: "XFS", tech: "inodes in released B+tree slots" },
  { fs: "F2FS", tech: "obsolete node blocks left by the log-structured writer" },
  { fs: "UFS / UFS2", tech: "orphan inodes in the live cylinder groups" },
  { fs: "SquashFS", tech: "orphan-inode scan of the metadata tables" },
  { fs: "JFFS2", tech: "dinode signature scan of dead blocks" },
  { fs: "ReiserFS", tech: "unlinked inodes swept from released leaf nodes" },
];

export const carveCategories = [
  { name: "Images", formats: "JPEG · PNG · GIF · TIFF · BMP · WebP · HEIC · JXL · FLIF · BPG · PNM · SGI · XPM · PICT · ICO" },
  { name: "Camera RAW", formats: "CR2 · CRW · NEF · ARW · ORF · RAF · DNG · MRW · PEF · RW2" },
  { name: "Video", formats: "MP4 / ISO-BMFF · MKV / EBML · AVI / RIFF · MOV · FLV · ASF/WMV · MPEG PS/TS · NSV · WTV" },
  { name: "Audio", formats: "MP3 · AAC · AC-3 · FLAC · Ogg · WAV · TTA · OFR · VQF · RA" },
  { name: "Documents", formats: "PDF · OLE2 (DOC/XLS/PPT) · OOXML · ODF · RTF · DVI · FDF · QXP" },
  { name: "Archives", formats: "ZIP · 7z · RAR · tar · ar · CAB · XAR · ARJ · ARC · ZOO · SQX · KGB · ZPAQ · RZIP · UHARC · ALZ · PAK · WAD" },
  { name: "Databases", formats: "SQLite · dBase family · ESEDB · registry hives · QED" },
  { name: "Executables", formats: "ELF · PE · Mach-O · WASM · DEX · Android boot" },
  { name: "Forensic images", formats: "EWF (E01) · AFF · minidump (DMP)" },
  { name: "Network", formats: "pcap · pcapng" },
  { name: "Logs & artifacts", formats: "EVTX · REG · PCF" },
  { name: "Crypto & keys", formats: "GPG keyrings · certificates" },
  { name: "3D & fonts", formats: "PLY · LWO2 · ILBM · TTF/OTF/WOFF" },
  { name: "Retro & misc", formats: "NES · IFF/FORM · CRW · misc containers" },
];

export const hiddenGems = [
  {
    title: "Privilege hand-off, not a password prompt",
    body: "Pick a locked disk and the interface launches a privileged copy of itself and hands over the port — the browser reconnects to the same page with full disk access. It prefers pkexec so your password never passes through the program; sudo is a one-time fallback, never stored.",
  },
  {
    title: "It refuses to destroy your data",
    body: "GHOST RECOVER will not write recovered data back onto the disk it came from — for recovery, carving or imaging. Not a warning: an outright refusal. Everything is read-only unless you start it with --allow-writes.",
  },
  {
    title: "Fragmented MP3/AAC carved as one file",
    body: "Frame walkers resync over a bounded 32 KiB window instead of ending at the first overwritten frame, so a partly-overwritten track carves as a single playable file instead of one file per frame run.",
  },
  {
    title: "Honest about undecidable geometry",
    body: "A chunk size of N and N/2 map the start of an array identically. On a near-empty array the engine reports the alternatives with low confidence rather than presenting a guess as a finding. Same for ZFS: it names the limit instead of pretending.",
  },
  {
    title: "Structural validators kill the garbage",
    body: "1 MiB of random noise used to carve ~29 bogus JXL/GPG files. With the new validators: at most one. Weak 1-byte magics get a scan-time admission filter so the candidate cap stays meaningful on dense media.",
  },
  {
    title: "Previews that can't crash your browser",
    body: "Files stream window-by-window and answer HTTP Range natively, so players seek through multi-gigabyte carves without loading them. Video previews stream behind a 256 MiB cap, and /api/file only serves paths under the output root.",
  },
];

export const apiEndpoints = [
  "GET  /api/health /api/disks /api/filesystems /api/carvers /api/browse",
  "GET  /api/privileges   POST /api/elevate   GET /api/elevate/status",
  "POST /api/handover (privilege hand-off)    POST /api/shutdown",
  "POST /api/detect /api/partitions",
  "POST /api/scan /api/carve /api/deep /api/extract /api/image   -> { job }",
  "GET  /api/job?id=  /api/jobs           POST /api/job/cancel",
  "GET  /api/results?job=&offset=&limit=&q=&ext=&only=&sort=",
  "GET  /api/content?job=&index=[&max=]   /api/hex  /api/fileinfo  /api/file",
  "POST /api/raid/detect /api/raid/assemble /api/repair /api/save",
];

export const cliCommands = [
  { cmd: "sudo ghost_recover parts   /dev/sda --deep", note: "partitions, incl. deleted ones" },
  { cmd: "sudo ghost_recover scan    /dev/sda2 --deleted", note: "list deleted files" },
  { cmd: "sudo ghost_recover recover /dev/sda2 --out ~/rescued", note: "extract with full paths" },
  {
    cmd: "sudo ghost_recover carve   /dev/sda2 --out ~/carved --categories image,document",
    note: "signature carving",
  },
  { cmd: "sudo ghost_recover image   /dev/sdb  --out ~/sdb.img", note: "clone a failing drive" },
  { cmd: "ghost_recover raid    m0.img m1.img m2.img --out ~/array.img", note: "reassemble an array" },
];

export const buildSteps = [
  "git clone https://github.com/nkbeast/ghost-recover",
  "cd ghost-recover",
  "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release",
  "cmake --build build -j",
  "./build/ghost_recover        # opens the web interface",
];

export const faqs = [
  {
    q: "What can I recover with GHOST RECOVER?",
    a: "Deleted files, formatted partitions, lost photos/videos/documents from RAW-scanned disks, RAID arrays whose metadata is gone, and files off failing drives you first clone to an image.",
  },
  {
    q: "Does it work if the filesystem is damaged or was formatted over?",
    a: "Yes — signature carving works on raw bytes and does not need a filesystem at all. Combine it with the filesystem walk when metadata still exists for the most complete result.",
  },
  {
    q: "Is it safe? Will it overwrite my data?",
    a: "The engine is read-only-first and refuses to write recovered data onto the source disk. Repairs are dry runs by default and the original sectors are saved first.",
  },
  {
    q: "Do I need root?",
    a: "Only to read physical block devices. Images, USB sticks and other files can be scanned with no elevation at all.",
  },
  {
    q: "Can it run on an old low-RAM machine?",
    a: "Yes — thread pools, caches and candidate limits scale with installed memory, and it runs comfortably on 1 GiB.",
  },
  {
    q: "Is it free?",
    a: "Yes — MIT licensed, free and open source. No accounts, no trials, no telemetry.",
  },
];

export const roadmap = [
  "NTFS LZX / XPRESS content decompression",
  "Real-world recovery fidelity tests beyond synthetic fixtures",
  "Forensics extras: PST/Outlook, browser artifacts, deeper Windows app-data coverage",
  "Windows and macOS builds",
  "Bad-block retry heuristics (multi-pass like ddrescue)",
];

export const projectLayout = [
  ["include/ghost/", "types, I/O, JSON, filesystem, carving, disk, recovery, server headers"],
  ["src/core/", "windowed and cached DiskReader, JSON, hashing, job manager"],
  ["src/fs/", "detection and one file per filesystem family"],
  ["src/carve/", "Aho-Corasick matcher, signature registry, carving engine"],
  ["src/disk/", "device enumeration, partition tables, RAID"],
  ["src/recover/", "extraction, repair, imaging"],
  ["src/server.cpp", "HTTP API"],
  ["web/", "interface (index.html, app.js, styles.css)"],
  ["tests/", "fixture builder and end-to-end verification"],
];
