# master_backup

Back up the local locker (authoritative source) to one or more remote lockers in a
single confirm-and-go run, and refresh the remote hash sidecars.

## Synopsis

```
master_backup [-l <local_locker>] [-r <remote_lockers>] [options]
```

## Description

`master_backup` is the "data safety" entrypoint: it treats the **Local** locker as the
authoritative source and pushes new/changed files to each remote locker
(default **Hetzner** and **Gdrive**). It is **additive by default** — files removed
locally are kept on the remotes (use `--recycle_orphans` to change that).

It is a thin orchestrator over `lockersync` run non-interactively: one confirmation,
then it runs unattended. Per destination it:

1. Builds a hash map of the source and the destination, and computes the differences.
2. Uploads new/changed files (one batched transfer per cryption group — see Batching).
3. Refreshes the destination's hash sidecar from the authoritative local content
   (only for remotes that need one, e.g. Hetzner/SFTP).

Encryption is honored per locker: destinations marked `encrypted = true` (e.g. Hetzner)
have each file encrypted with JoyBox's `cryption` module before upload; unencrypted
destinations (e.g. Gdrive) are copied as-is. Each destination's configured
`excluded_dirs` are respected.

## Options

| Option | Description |
|--------|-------------|
| `-l, --local_locker` | Authoritative source locker (default: `Local`) |
| `-r, --remote_lockers` | Comma-separated backup destinations (default: `Hetzner,Gdrive`) |
| `--recycle_orphans` | Recycle remote files missing from the source to `.recycle_bin` (default: keep — additive only) |
| `--no_rebuild_sidecars` | Skip refreshing remote hash sidecars after syncing |
| `--skip_cache` | Rebuild hash maps fresh instead of using the 24h cache |
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Batching

Uploads are batched to avoid per-file overhead:
- **Unencrypted destination** (Gdrive): all new/changed files go in one `rclone copy`
  using `--files-from`, preserving directory structure.
- **Encrypted destination** (Hetzner): all changed files are encrypted into a temporary
  staging tree (mirroring the destination layout, encrypted leaf names), then uploaded
  in one transfer.

The hash sidecar (`.locker_hashes.db`) is updated **once per destination** at the end
of its sync, not once per file. This replaces older per-file behavior that re-uploaded
the entire sidecar database after every file.

## Examples

### Back up local to Hetzner and Gdrive

```bash
master_backup
```

### Dry run (see what would happen)

```bash
master_backup --pretend_run --verbose
```

### Back up to a single destination

```bash
master_backup -r Hetzner
```

### Mirror instead of additive (recycle remote orphans)

```bash
master_backup --recycle_orphans
```

### Force fresh hash maps (ignore cache)

```bash
master_backup --skip_cache
```

## Notes

- Additive by default: a master backup never deletes remote data unless
  `--recycle_orphans` is given (and even then it recycles, not hard-deletes).
- The sidecar refresh is derived from authoritative local content, so it only runs when
  the source is the local locker and the destination relies on a sidecar (Hetzner/SFTP).
  It is skipped for a destination if any of its uploads failed, so the next run retries.
- For Hetzner, the rclone remote must have `disable_hashcheck = true` (SFTP can't run
  `md5sum` for transfer verification) — see `rebuild_hash_sidecars`.

## See Also

- `locker_sync_tool` - Interactive sync between primary and secondary lockers
- `rebuild_hash_sidecars` - Rebuild the hash sidecar database on a remote
- `sync_tool` - Lower-level synchronize between local storage and a remote locker
