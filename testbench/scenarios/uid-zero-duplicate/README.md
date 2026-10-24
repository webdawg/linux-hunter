# uid-zero-duplicate

**Technique**: a second root-equivalent account -- a simple, classic
backdoor. See `docs/research/persistence-techniques.md` §5 ("New /
modified accounts").

**Plants**: an `/etc/passwd` with two `uid 0` entries (`root` and
`evil`).

**Expects**: an `accounts` finding whose summary contains "more than one
account has uid 0".

**Check under test**: `src/checks/accounts.rs::check_uid_zero_duplicates`.
