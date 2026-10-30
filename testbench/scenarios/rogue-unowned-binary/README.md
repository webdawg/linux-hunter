# rogue-unowned-binary

**Technique**: a dropped binary sitting in a standard system directory that no installed
package put there. This is the "rogue software" case `src/checks/baseline.rs` exists to
catch — see `docs/VERIFICATION_MATRIX.md`'s FS-01 row.

**Plants**: an executable named `rogue` in `/usr/local/bin`, via an overlay rather than a
fake package database — `/usr/local` isn't a location any real pacman/dpkg package installs
to, so the real (unmodified) host database already doesn't own anything there, and this
scenario proves that against the actual real database content coming through the sandbox's
normal read-only root bind, not a synthetic fixture database.

**Expects**: a `baseline` finding whose summary contains "is executable but not owned by any
installed package".

**Check under test**: `src/checks/baseline.rs::check_unowned_executables`.
