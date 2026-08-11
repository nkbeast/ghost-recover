## What does this change?

One or two sentences: what the PR does and why.

## Fixes

Closes #issue-number (if applicable).

## What was tested

- [ ] `./tests/verify.sh` passes locally (73 checks)
- [ ] Sanitizer build (`-DCMAKE_BUILD_TYPE=Debug`) passes the suite
- [ ] Manual test with a real image / fixture / device (describe it)

## Checklist

- [ ] One logical change per commit
- [ ] No new compiler warnings (`-Wall -Wextra`)
- [ ] New behavior has a test in `tests/` (bug fixes ship with a
      failing-then-passing case)
- [ ] I have not attached any image containing personal data

## Notes for reviewers

Anything unusual, risky, or worth a careful look? If this touches a
filesystem driver or the carver, call out which fixtures cover it.
