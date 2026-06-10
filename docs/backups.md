# Backups

[← Docs index](README.md)

Once your [cloud lockers](cloud-lockers.md) are configured, `master_backup` is the everyday
"keep my data safe" command.

## Back up Local → remotes

Pushes the authoritative **Local** locker out to the remotes. Additive by default (it never
deletes on the remote), one confirmation then unattended. It batches uploads and refreshes the
remote hash sidecar (`.locker_hashes.db`) automatically after a successful sync.

```bash
# Default: Local -> Hetzner + Gdrive
master_backup

# Dry run first
master_backup --pretend_run --verbose

# Only one destination
master_backup -r Hetzner

# Several destinations
master_backup -r "Hetzner,Gdrive,External"
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-l`, `--local_locker` | `Local` | Authoritative source locker |
| `-r`, `--remote_lockers` | `Hetzner,Gdrive` | Comma-separated destinations |
| `--recycle_orphans` | off | Move remote files missing from source into `.recycle_bin` (turns additive backup into a mirror) |
| `--skip_cache` | off | Rebuild hash maps fresh, ignoring the 24h cache |
| `--no_rebuild_sidecars` | off | Skip refreshing the remote hash sidecar afterwards |

Full breakdown: [`master_backup`](../Scripts/docs/man/master_backup.md).

## Hash sidecars

SFTP remotes (Hetzner) can't do reliable server-side hashing, so JoyBox keeps a
`.locker_hashes.db` SQLite manifest at the remote root as the source of truth for diffing.
`master_backup` refreshes it automatically, so you rarely touch it directly. When you do:

```bash
# Rebuild a remote's sidecar from local content — run AFTER a sync, never before
rebuild_hash_sidecars -l Local -d Hetzner -v

# Find files on the remote that aren't in the sidecar
find_missing_hash_sidecars -l Hetzner -v
```

References: [`rebuild_hash_sidecars`](../Scripts/docs/man/rebuild_hash_sidecars.md) ·
[`find_missing_hash_sidecars`](../Scripts/docs/man/find_missing_hash_sidecars.md).

## Remote-to-remote and lower-level sync

- [`locker_sync_tool`](../Scripts/docs/man/locker_sync_tool.md) — interactively sync a primary
  locker to one or more secondaries (e.g. Hetzner → Gdrive + External), with editor-driven
  approval.
- [`sync_tool`](../Scripts/docs/man/sync_tool.md) — lower-level synchronize between local
  storage and a remote locker.
- [`backup_tool`](../Scripts/docs/man/backup_tool.md) — copy/archive files between paths with
  optional encryption.

## Reference

- [`master_backup`](../Scripts/docs/man/master_backup.md)
- [`locker_sync_tool`](../Scripts/docs/man/locker_sync_tool.md)
- [`rebuild_hash_sidecars`](../Scripts/docs/man/rebuild_hash_sidecars.md)
- [`find_missing_hash_sidecars`](../Scripts/docs/man/find_missing_hash_sidecars.md)
- [`sync_tool`](../Scripts/docs/man/sync_tool.md)
- [`backup_tool`](../Scripts/docs/man/backup_tool.md)
