# GHOST//RECOVER

A data recovery engine for Linux. It reads filesystem metadata to find files
(including deleted ones), carves files out of raw sectors when the metadata is
gone, reassembles RAID arrays, clones failing drives, and repairs damaged
filesystem structures — through a local web interface or from the command line.

Everything is read-only unless you explicitly ask for a repair and start the
engine with `--allow-writes`.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Requires a C++17 compiler and CMake ≥ 3.16. zlib is optional; without it,
SquashFS/cramfs/JFFS2 contents cannot be decompressed (their file listings still
work).

## Run

```sh
./build/ghost_recover            # opens the interface in a browser
./build/ghost_recover --help     # command-line usage
```

Reading a physical disk needs root. You do not have to start the program that
way: if you pick a locked disk, the interface offers to unlock it, launches a
privileged copy of itself and hands over the port, so the browser reconnects to
the same page with full disk access. It prefers **pkexec**, so your desktop's own
authentication dialog appears and the password never passes through this program;
where polkit is unavailable it falls back to a sudo password, used once and never
stored. A declined or mistyped password leaves the running session untouched.

Files written while elevated are handed back to the account that authenticated,
so recovered data does not end up owned by root.

Starting with `sudo ./build/ghost_recover` still works and skips the prompt.
Recovered files go to `$GHOST_OUTPUT`, or `~/ghost-recover-output`.

```sh
sudo ghost_recover parts   /dev/sda --deep      # partitions, incl. deleted ones
sudo ghost_recover scan    /dev/sda2 --deleted  # list deleted files
sudo ghost_recover recover /dev/sda2 --out ~/rescued
sudo ghost_recover carve   /dev/sda2 --out ~/carved --categories image,document
sudo ghost_recover image   /dev/sdb  --out ~/sdb.img     # clone a failing drive
     ghost_recover raid    m0.img m1.img m2.img --out ~/array.img
```

## What it does

**Filesystem drivers** — ext2/3/4, NTFS, FAT12/16/32, exFAT, XFS, Btrfs, F2FS,
HFS+/HFSX, APFS, ISO 9660 (Joliet + Rock Ridge), UDF, SquashFS, cramfs, romfs,
MINIX, JFFS2, UFS/UFS2, ReiserFS, JFS. ZFS is identified and reported but not
walked. Another twenty-odd filesystems and containers (LUKS, LVM, md RAID, swap)
are identified so the tool can tell you what you are actually looking at.

Each driver reconstructs full paths and describes files as extent lists, so
fragmented files come out intact.

**Deleted-file recovery** works differently on each filesystem, and each driver
implements what actually applies:

| Filesystem | Techniques |
|---|---|
| ext2/3/4 | deleted inodes (`i_dtime`), jbd2 journal mining for extent trees that `unlink()` cleared, directory-entry slack, orphan inode list, backup superblocks |
| NTFS | unused MFT records, `$I30` index slack, `$UsnJrnl` change journal, `$MFTMirr` and backup-boot-sector fallbacks, alternate data streams |
| FAT/VFAT | `0xE5` entries, long-name reassembly, first-character recovery from the LFN checksum, FAT1/FAT2 differencing, directory slack, orphaned cluster chains |
| exFAT | directory entry sets with the in-use bit cleared, contiguous-stream reconstruction |
| Btrfs / APFS | copy-on-write leaves from superseded generations |
| XFS | inodes in released B+tree slots |
| F2FS | obsolete node blocks left by the log-structured writer |

**Carving** — 251 signatures across 15 categories, matched with a single
Aho-Corasick pass over the device rather than one search per signature. Formats
that describe their own length (JPEG, PNG, GIF, TIFF, RIFF, MP4/ISO-BMFF, EBML,
Ogg, FLAC, MP3, AAC, AC-3, MPEG PS/TS, FLV, ASF, ZIP, 7z, RAR, tar, ar, CAB,
SQLite, ELF, PE, Mach-O, pcap/pcapng, EVTX, registry hives, OLE2, PDF, fonts,
WASM, DEX and more) are walked structurally, so files come out at their true
size instead of a fixed guess. Results are entropy-screened, deduplicated by
content hash, and can be restricted to the volume's free space.

**Partitions** — MBR including the extended/EBR chain, GPT with CRC validation
of both copies, and recovery of partitions missing from the table by scanning
for filesystem superblocks and volume boot records.

**RAID** — reads Linux md superblocks (0.90 and 1.x), or works out chunk size,
member order and parity layout when they are gone. Each guess is checked by
following the filesystem's own pointers deep into the assembled array, and where
several geometries still fit, they are ranked by how much end-to-end verifiable
file content each reconstructs.

A chunk size of N and N/2 map the *start* of an array identically, so on an
array holding little data the geometry can be genuinely undecidable. In that
case the engine says so — it reports the alternatives and a low confidence
rather than presenting a guess as a finding. Maps linear, RAID 0/1/5/6/10, and
rebuilds a missing member from parity:

```sh
ghost_recover raid m0.img m1.img missing m3.img \
    --level 5 --chunk 65536 --layout left-symmetric --out array.img
```

**Imaging** — ddrescue-style cloning with a resumable map file, large reads on
the good pass and sector-by-sector retries over the bad areas.

**Repair** — restores ext superblocks, FAT/exFAT boot regions, NTFS boot
sectors and GPT headers from their backups, and can rebuild an MBR from
recovered partitions. Every repair is a dry run unless you pass `apply`, and the
original sectors are saved first.

## Testing

```sh
./tests/verify.sh
```

Builds real ext4/ext2/NTFS/FAT32/exFAT/Btrfs/XFS/ISO/UDF/SquashFS/cramfs/MINIX
filesystems from a known corpus (no mounting, no root), deletes files from some
of them, then checks that the engine identifies each filesystem, finds the
deleted files, and writes every recovered file back out **byte-for-byte
identical** to the original — verified by MD5, not by the engine's own
reporting.

It also covers MBR logical partitions inside an extended partition, partition
recovery after wiping both GPT copies, RAID 0 and RAID 5 geometry recovery from
the data alone, rebuilding a destroyed RAID 5 member from parity, superblock
repair (dry run leaves the volume untouched; applying it restores every file),
bad-sector imaging, the refusal to write onto the source disk, and that corrupt,
truncated and random images are handled without crashing or being
misidentified.

To run it against a sanitizer build:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug && cmake --build build-asan -j
# Preload for the engine only, so the shell tools the suite uses are unaffected.
printf '#!/bin/sh\nexec env LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 ASAN_OPTIONS=detect_leaks=0 %s/build-asan/ghost_recover "$@"\n' "$PWD" > /tmp/gw && chmod +x /tmp/gw
GHOST_BIN=/tmp/gw ./tests/verify.sh
```

## Working safely

* **Never write recovered files back to the disk you are recovering from.**
  Doing so overwrites the free space still holding the rest of your data. The
  engine refuses this outright — for recovery, carving and imaging — rather than
  warning about it.
* If a drive is making noises or throwing I/O errors, clone it first
  (`ghost_recover image`) and recover from the clone.
* Repairs modify the device. Every repair is a dry run unless you pass `apply`,
  and the original sectors are saved first, but image the disk anyway.

## Known limits

Stated plainly, because a recovery tool that overstates itself wastes the one
chance you get at the data:

* **ZFS** is identified but not walked — file recovery needs a full DMU
  traversal plus block decompression. Import the pool read-only instead.
* **exFAT** has a complete driver, but the automated suite cannot populate an
  exFAT volume without mounting (which needs root), so its directory walk is
  exercised only against an empty volume. The FAT, NTFS and exFAT parsers share
  no code, so treat exFAT results as less proven than the rest.
* **APFS, HFS+, F2FS, UFS, ReiserFS, JFS and JFFS2** are implemented but their
  fixtures are empty or unavailable on Linux, so they are verified for
  identification and for not crashing, not for recovery fidelity.
* **Compressed Btrfs/ZFS extents and NTFS compressed streams** are reported and
  located, but their contents are not decompressed.

## Layout

```
include/ghost/   types, I/O, JSON, filesystem, carving, disk, recovery, server headers
src/core/        windowed and cached DiskReader, JSON, hashing, job manager
src/fs/          detection and one file per filesystem family
src/carve/       Aho-Corasick matcher, signature registry, carving engine
src/disk/        device enumeration, partition tables, RAID
src/recover/     extraction, repair, imaging
src/server.cpp   HTTP API
web/             interface (index.html, app.js, styles.css)
tests/           fixture builder and end-to-end verification
```

## API

The interface is a thin client over an HTTP API on `127.0.0.1:3030`. Long
operations return a job id and are polled:

```
GET  /api/health /api/disks /api/filesystems /api/carvers /api/browse
GET  /api/privileges  POST /api/elevate  GET /api/elevate/status
POST /api/detect /api/partitions
POST /api/scan /api/carve /api/deep /api/extract /api/image      -> { job }
GET  /api/job?id= /api/jobs        POST /api/job/cancel
GET  /api/results?job=&offset=&limit=&q=&ext=&only=&sort=
GET  /api/content?job=&index=      /api/hex   /api/fileinfo   /api/file
POST /api/raid/detect /api/raid/assemble /api/repair /api/save
```

`/api/file` only serves paths under the output root; the engine will not read
arbitrary files off the host.
