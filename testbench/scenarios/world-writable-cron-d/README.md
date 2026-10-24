# world-writable-cron-d

**Technique**: a world-writable persistence directory. Any local user can
drop a cron entry that runs as whatever account cron itself runs as
(often root). See `docs/research/persistence-techniques.md` §1 and the
"universal detection approach" note at the top of that file.

**Plants**: `/etc/cron.d` with mode `0777`.

**Expects**: a `persistence` finding whose summary contains
`"/etc/cron.d is world-writable"`.

**Check under test**: `src/checks/persistence.rs::check_world_writable_dirs`.
