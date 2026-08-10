---
name: Bug report
about: Report something that is broken
title: "[BUG] "
labels: bug
assignees: ''
---

## Summary

A clear, one-paragraph description of the bug.

## Repro steps

1. Build: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`
2. Command run:
   ```
   ghost_recover <command> <device-or-image> <options>
   ```
3. What you expected to happen
4. What actually happened (paste output)

## Environment

- GHOST//RECOVER version: (`ghost_recover --version`)
- Linux distribution / kernel: `uname -a`
- Build type: Release / Debug (ASan/UBSan)
- zlib: present / absent

## Source device

- Filesystem(s) on the volume:
- Deleted files / RAID / carving / repair involved: yes/no
- Is this a physical disk, an image file, or a fixture?

> **Never attach a real disk image containing personal data.** If the bug
> needs a sample, reproduce it against a small throwaway image or a fixture
> and attach that instead.

## Expected vs actual

- [ ] Ran `./tests/verify.sh` before reporting — passes / fails
- [ ] Crash / hang / wrong output / other

## Logs

```
paste the output here
```
