# Contributing to GHOST//RECOVER

Thanks for wanting to help. This project recovers people's only copy of their
data, so two rules outweigh everything else:

1. **Never break the test suite.** `./tests/verify.sh` must stay green. It
   verifies byte-for-byte recovery against real filesystems, and it is the
   only thing standing between a refactor and silent data corruption.
2. **Be honest about what you did and did not test.** The README's "Known
   limits" section exists because overstating a recovery tool wastes the one
   chance the user gets at their data. Update it when you change reality.

## Getting started

```sh
git clone https://github.com/nkbeast/ghost-recover
cd ghost-recover
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./tests/verify.sh          # must pass before you open a PR
```

For a debug/sanitizer build (recommended while writing parsers):

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan -j
GHOST_BIN=$PWD/build-asan/ghost_recover ./tests/verify.sh
```

## Where things live

```
include/ghost/   headers — types.h is the core vocabulary of the engine
src/core/        DiskReader, JSON, hashing, jobs
src/fs/          one file per filesystem family — start here for FS work
src/carve/       Aho-Corasick matcher + signature registry
src/disk/        devices, partitions, RAID
src/recover/     extraction, repair, imaging
src/server.cpp   HTTP API
web/             the interface (plain JS, no build step)
tests/           fixture builder + end-to-end verification
```

## Finding a good first issue

Look for the `good-first-issue` label. Good candidates that are always welcome:

* **Fixture coverage** — e.g. a populated exFAT volume, or fixtures for the
  drivers currently verified only for identification (APFS, HFS+, F2FS, UFS,
  ReiserFS, JFS, JFFS2). These are worth more than a new feature.
* **Format validators** — a new signature is only as good as its structural
  walker in `src/carve/signatures.cpp`.
* **Robustness** — corrupt a fixture byte by byte and find what crashes.

## How to submit

1. Fork the repository.
2. Create a branch: `git checkout -b fix/descriptive-name`
3. Make your change, one logical change per commit.
4. Add or update tests. A bug fix without a failing-then-passing test is not
   complete.
5. Run `./tests/verify.sh` locally.
6. Push and open a pull request. CI runs the full suite automatically.

## Style

* C++17, `-Wall -Wextra` clean. No new warnings.
* All on-disk field access goes through the bounds-checked `Bytes` helpers in
  `include/ghost/types.h`. Never `memcpy` an on-disk struct.
* Every I/O read that could hit a bad sector must tolerate a short read.
* No comments explaining *what*; comments explaining *why* are welcome and
  this codebase uses them liberally — keep that habit.
* Extent lists, never `(offset, size)` pairs. Fragmented files must come out
  intact or not at all.

## Testing expectations by area

| Area | Minimum bar |
|---|---|
| Filesystem driver | fixture in `tests/build-fixtures.sh`, recovery byte-identical |
| Deleted-file technique | deleted-file case in `tests/verify.sh` |
| Carving signature | validator + verify.sh carve case |
| RAID path | geometry recovery + byte-identical assembly |
| Repair path | dry run leaves volume untouched, apply restores files |
| Server/UI | no regressions on the 52-check suite |

## Questions

Open an issue with the `question` label. If you are proposing a large change,
open an issue *before* writing the code so it can be shaped with feedback.
