# Security Policy

## Reporting a vulnerability

GHOST RECOVER parses hostile on-disk structures for a living, so we take
security reports seriously. If you believe you have found a vulnerability —
a crash on malformed input, memory unsafety, an API flaw, or anything that
could be abused on a host running the engine — please report it privately
**before** opening a public issue.

**Contact:** open a [private security advisory](https://github.com/nkbeast/ghost-recover/security/advisories/new)
or email the maintainer privately through the GitHub security tab.

Please include:

* Which version of the engine you tested (run `ghost_recover --version`)
* A minimal trigger: a small image file, command line, or API request
* Your environment (Linux distribution, kernel, sanitizer status)
* Whether you built with ASan/UBSan (see README: the suite runs on a
  sanitizer build — reports on such builds are especially valuable)

## Scope

* All code under `src/`, `include/` and `web/`
* The HTTP API on `127.0.0.1:3030` and its elevation/handover paths
* Filesystem drivers, the carving engine, RAID assembly, repair, imaging

## Out of scope

* Issues requiring the attacker to already hold root (the engine's own
  privilege-elevation flow is intended)
* Physical access attacks on the machine

## Response

* We acknowledge reports within 48 hours
* We aim for a fix and a release note within 14 days for critical issues
* Security fixes are backported to the maintenance branch when practical

## Disclosing

We prefer coordinated disclosure. After a fix is released, public write-ups
are welcome — we will acknowledge you unless you prefer to stay anonymous.

## Safe-harbor

Testing the engine against your own images and devices is fully supported.
Testing against systems you do not own is not: never run recovery or repair
operations on hardware you do not have permission to access. Reported issues
found under those conditions will not be considered.
