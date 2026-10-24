# shadow-libc-soname

**Technique**: smuggling a malicious shared object into a system library
directory under a plausible-but-wrong soname (e.g. a fake `libc.so.5`
sitting next to the real `libc.so.6`). This is the technique from the
Spring 2026 2600 Magazine "Anti-Revisionist Malware" article that
prompted `src/checks/libraries.rs` to exist at all -- see the case study
in `docs/research/malware-case-studies.md` and the citation in
`docs/research/sources.md`.

**Plants**: a fake `libc.so.5` inside a real, non-symlink `LIBRARY_DIRS`
directory picked at runtime (`pick_existing_library_dir` in
`testbench/lib/sandbox.sh`). The directory gets a real overlayfs
(`--overlay-src`/`--tmp-overlay`): its actual contents as the read-only
lower layer, writes going to a throwaway tmpfs upper
(`plant_fake_library_in_existing_dir`), so the real `libc.so.6` (and
everything else hunter's own dynamic linking needs) is still present
without binding its ~5,900 entries individually -- a first attempt at
that blew past bwrap's argument cap. On a merged-usr distro like Arch,
`/lib` is just a symlink to `/usr/lib`, which is part of the read-only
root bind, so there's no writable parent to create a brand-new directory
under either; overlaying an existing real directory sidesteps that too.

**Expects**: a `libraries` finding whose summary contains `"soname
versions of libc.so"`.

**Check under test**: `src/checks/libraries.rs::check_shadow_libraries`.
