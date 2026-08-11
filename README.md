<p align="center">
  <img src="assets/banner.svg" width="100%" alt="GHOST//RECOVER"/>
</p>

<p align="center">
  <b>The data recovery engine for Linux.</b><br/>
  Reads filesystem metadata, carves raw sectors, reassembles RAID arrays, clones failing drives,
  and repairs damaged structures &mdash; through a web interface, a CLI, or an HTTP API.
</p>

<p align="center">
  <a href="https://github.com/nkbeast/ghost-recover/actions"><img src="https://img.shields.io/github/actions/workflow/status/nkbeast/ghost-recover/ci.yml?branch=main&label=CI&logo=github" alt="CI"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/nkbeast/ghost-recover" alt="License"/></a>
  <img src="https://img.shields.io/badge/C%2B%2B-17-blue" alt="C++17"/>
  <img src="https://img.shields.io/badge/Platform-Linux-green" alt="Linux"/>
  <a href="https://github.com/nkbeast/ghost-recover/stargazers"><img src="https://img.shields.io/github/stars/nkbeast/ghost-recover?style=social" alt="Stars"/></a>
  <a href="https://github.com/nkbeast/ghost-recover/forks"><img src="https://img.shields.io/github/forks/nkbeast/ghost-recover?style=social" alt="Forks"/></a>
  <img src="https://img.shields.io/badge/tests-73%2F73%20passing-success" alt="73/73 tests"/>
</p>

---

## 📌 What is GHOST//RECOVER?

A **read-only-first** data recovery engine for Linux that combines every technique the professional
suites use &mdash; and some they don't:

* **Filesystem metadata walking** &mdash; 25+ filesystems, full path reconstruction, extent-accurate
  (fragmented files come out **intact**, not corrupted).
* **Deleted-file recovery** &mdash; journal mining, directory slack, orphan inodes, MFT slack,
  FAT1/FAT2 differencing — the techniques, not just "scan for free space".
* **Signature carving** &mdash; 251 formats across 15 categories, one Aho-Corasick pass, structural
  length validation, entropy screening, content-hash dedup.
* **RAID reassembly** &mdash; 0/1/5/6/10 and linear, from md superblocks *or* blind geometry
  brute-force with honest ambiguity reporting, plus parity rebuild of dead members.
* **Imaging** &mdash; ddrescue-style cloning with a resumable map file.
* **Repair** &mdash; ext/FAT/NTFS boot regions and GPT headers restored from backups, every repair
  a dry run until you say `apply`.

> **Everything is read-only unless you explicitly start the engine with `--allow-writes`.**
> GHOST//RECOVER **refuses to write recovered data back onto the disk it came from** — that is how
> recovery attempts destroy the data they're trying to save.

---

## 🗺️ How it works

<p align="center">
  <img src="assets/architecture.svg" width="100%" alt="Engine architecture"/>
</p>

---

## 🚀 Quick start

### Build

Requires a C++17 compiler and CMake &ge; 3.16. zlib is optional (enables SquashFS/cramfs/JFFS2
decompression).

```sh
git clone https://github.com/nkbeast/ghost-recover
cd ghost-recover
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

### Run

```sh
./build/ghost_recover            # opens the interface in a browser
./build/ghost_recover --help     # command-line usage
```

Reading a physical disk needs root. If you pick a locked disk, the interface offers to unlock it:
it launches a privileged copy of itself and hands over the port, so the browser reconnects to the
same page with full disk access. It prefers **pkexec** (your desktop's own authentication dialog —
the password never passes through this program); where polkit is unavailable it falls back to a
sudo password, used once and never stored.

```sh
sudo ghost_recover parts   /dev/sda --deep      # partitions, incl. deleted ones
sudo ghost_recover scan    /dev/sda2 --deleted  # list deleted files
sudo ghost_recover recover /dev/sda2 --out ~/rescued
sudo ghost_recover carve   /dev/sda2 --out ~/carved --categories image,document
sudo ghost_recover image   /dev/sdb  --out ~/sdb.img     # clone a failing drive
     ghost_recover raid    m0.img m1.img m2.img --out ~/array.img
```

Recovered files go to `$GHOST_OUTPUT`, or `~/ghost-recover-output`.

---

## 🧠 Deep dive

### 📁 Filesystem drivers

**25+ filesystems** are identified; 21 are walked with full metadata drivers:

| Family | Filesystems |
|---|---|
| Linux | ext2/3/4, XFS, Btrfs, F2FS, ReiserFS, JFS, MINIX, UFS/UFS2, romfs, cramfs |
| Windows | NTFS, FAT12/16/32, exFAT |
| Apple | APFS, HFS+/HFSX |
| Optical | ISO 9660 (Joliet + Rock Ridge), UDF |
| Embedded | SquashFS, JFFS2 |

ZFS is identified and reported (file recovery needs a full DMU traversal — import the pool
read-only instead). Another twenty-odd filesystems and containers (LUKS, LVM, md RAID, swap) are
identified so the tool can tell you what you are actually looking at.

Every driver reconstructs **full paths** and describes files as **extent lists**, so fragmented
files come out intact.

### 🕵️ Deleted-file recovery

Each filesystem gets the techniques that actually apply to it:

| Filesystem | Techniques |
|---|---|
| ext2/3/4 | deleted inodes (`i_dtime`), **jbd2 journal mining** for extent trees that `unlink()` cleared, directory-entry slack, orphan inode list, backup superblocks |
| NTFS | unused MFT records, `$I30` index slack, `$UsnJrnl` change journal, `$MFTMirr` and backup-boot-sector fallbacks, alternate data streams |
| FAT/VFAT | `0xE5` entries, long-name reassembly, **first-character recovery from the LFN checksum**, FAT1/FAT2 differencing, directory slack, orphaned cluster chains |
| exFAT | directory entry sets with the in-use bit cleared, contiguous-stream reconstruction |
| Btrfs / APFS | copy-on-write leaves from superseded generations |
| XFS | inodes in released B+tree slots |
| F2FS | obsolete node blocks left by the log-structured writer |

### 🪓 Signature carving

**251 signatures across 15 categories**, matched with a **single Aho-Corasick pass** over the
device rather than one search per signature.

Formats that describe their own length (JPEG, PNG, GIF, TIFF, RIFF, MP4/ISO-BMFF, EBML, Ogg,
FLAC, MP3, AAC, AC-3, MPEG PS/TS, FLV, ASF, ZIP, 7z, RAR, tar, ar, CAB, SQLite, ELF, PE, Mach-O,
pcap/pcapng, EVTX, registry hives, OLE2, PDF, fonts, WASM, DEX and more) are **walked
structurally**, so files come out at their **true size** instead of a fixed guess.

Results are **entropy-screened**, **deduplicated by content hash**, and can be restricted to the
volume's free space.

### 💽 Partitions

* MBR including the extended/EBR chain
* GPT with CRC validation of both copies
* **Recovery of partitions missing from the table** by scanning for filesystem superblocks and
  volume boot records

### 🔀 RAID

* Reads Linux md superblocks (**0.90 and 1.x**)
* Or works out **chunk size, member order and parity layout** when they are gone — each guess
  checked by following the filesystem's own pointers deep into the assembled array, ranked by how
  much end-to-end verifiable content each reconstructs
* Maps **linear, RAID 0/1/5/6/10**, and **rebuilds a missing member from parity**

A chunk size of N and N/2 map the *start* of an array identically, so on an array holding little
data the geometry can be genuinely undecidable. In that case the engine **says so** — it reports
the alternatives and a low confidence rather than presenting a guess as a finding.

```sh
ghost_recover raid m0.img m1.img missing m3.img \
    --level 5 --chunk 65536 --layout left-symmetric --out array.img
```

### 💾 Imaging

ddrescue-style cloning with a **resumable map file**, large reads on the good pass and
sector-by-sector retries over the bad areas.

### 🛠️ Repair

Restores ext superblocks, FAT/exFAT boot regions, NTFS boot sectors and GPT headers from their
backups, and can rebuild an MBR from recovered partitions. Every repair is a **dry run** unless
you pass `apply`, and the original sectors are saved first.

---

## 🖥️ Web interface

<p align="center">
  <img src="assets/webui.svg" width="100%" alt="Web interface"/>
</p>

The interface is a thin client over an HTTP API on `127.0.0.1:3030`. Long operations return a job
id and are polled:

```
GET  /api/health /api/disks /api/filesystems /api/carvers /api/browse
GET  /api/privileges  POST /api/elevate  GET /api/elevate/status
POST /api/detect /api/partitions
POST /api/scan /api/carve /api/deep /api/extract /api/image        -> { job }
GET  /api/job?id= /api/jobs        POST /api/job/cancel
GET  /api/results?job=&offset=&limit=&q=&ext=&only=&sort=
GET  /api/content?job=&index=      /api/hex   /api/fileinfo   /api/file
POST /api/raid/detect /api/raid/assemble /api/repair /api/save
```

`/api/file` only serves paths under the output root; the engine will not read arbitrary files off
the host.

---

## 🛡️ Working safely

* **Never write recovered files back to the disk you are recovering from.** Doing so overwrites
  the free space still holding the rest of your data. The engine **refuses this outright** — for
  recovery, carving and imaging — rather than warning about it.
* If a drive is making noises or throwing I/O errors, **clone it first** (`ghost_recover image`)
  and recover from the clone.
* Repairs modify the device. Every repair is a dry run unless you pass `apply`, and the original
  sectors are saved first, but **image the disk anyway**.

---

## 🧪 Testing

```sh
./tests/verify.sh        # end-to-end fixtures: 73 automated checks
./tests/verify.sh /tmp/ghost-fixtures   # reuse a previously built fixture set
```

**73 automated checks, 0 failures.** Builds real ext4/ext2/NTFS/FAT32/exFAT/Btrfs/XFS/ISO/UDF/
SquashFS/cramfs/MINIX/JFFS2 filesystems from a known corpus (no mounting, no root), deletes files
from some of them, then checks that the engine identifies each filesystem, finds the deleted
files, and writes every recovered file back out **byte-for-byte identical** to the original —
verified by **MD5, not by the engine's own reporting**. The Btrfs fixture rewrites real extents
as compressed ones (inline zlib/lzo/zstd, regular zlib extents) and the NTFS fixture stores one
file as an LZNT1 stream, so the compressed-content paths are proven against the same corpus, not
against the engine's own output.

Also covered: MBR logical partitions, partition recovery after wiping both GPT copies, RAID 0/5
geometry recovery from data alone, parity rebuild of a destroyed member, superblock repair (dry
run vs. apply), bad-sector imaging, the refusal to write onto the source disk, and corrupt /
truncated / random images handled without crashing or being misidentified.

Static analysis runs in CI-style fashion via clang-tidy with the `bugprone*`,
`clang-analyzer*` and `misc-const-correctness` groups:

```sh
run-clang-tidy -p build src/
```

The suite also runs under **ASan/UBSan** — this tool parses hostile on-disk structures for a
living, so memory safety is tested, not assumed.

---

## 📁 Project layout

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

---

## 🧭 Roadmap

* NTFS LZX / XPRESS content decompression
* Real-world recovery fidelity tests beyond synthetic fixtures
* Forensics extras: PST/Outlook, browser artifacts, deeper Windows app-data coverage
* Windows and macOS builds
* Bad-block retry heuristics (multi-pass like ddrescue)

*Contributions toward any of these are very welcome.*

---

## 🤝 Contributing

1. Fork it.
2. Create your feature branch: `git checkout -b feat/my-feature`
3. Commit your changes: `git commit -am 'Add my feature'`
4. Push to the branch: `git push origin feat/my-feature`
5. Open a pull request — CI builds and runs the full verification suite automatically.

Before opening a PR, make sure `./tests/verify.sh` passes locally.

---

## 📄 License

[MIT](LICENSE) &copy; 2026 Naveenkumar D. The vendored [cpp-httplib](https://github.com/yhirose/cpp-httplib)
keeps its own MIT notice.
