# pam-sufficient-permit

**Technique**: an `auth sufficient pam_permit.so` line, which
unconditionally succeeds and ends the PAM stack immediately — the same
shape as the authentication bypass Plague, Orbit, Skidmap, and Azazel
have used via malicious PAM modules. See
`docs/research/persistence-techniques.md` §5 ("Malicious PAM module" /
"Modified PAM config").

**Plants**: `/etc/pam.d/sshd` with `auth sufficient pam_permit.so` as its
first line (named `sshd` specifically to simulate the highest-value
real-world target, remote login, rather than a local-only utility).

**Expects**: a `pam` finding whose summary contains "sufficient module
in the auth stack".

**Check under test**: `src/checks/pam.rs::check_pam_config`. Also a
negative-control case in practice: this check's allowlist was tuned
*against* real distro-shipped `pam_rootok.so`/`pam_rhosts.so` lines
(see the module's doc comment) specifically so this scenario's
`pam_permit.so` line stands out rather than being lost in an
over-broad "flag everything" heuristic.
