# rebuild_hash_sidecars

Rebuild the hash sidecar database (`.locker_hashes.db`) on a remote locker from local content.

## Synopsis

```
rebuild_hash_sidecars [-l <source_locker>] [-d <dest_locker>] [options]
```

## Description

`rebuild_hash_sidecars` walks a local directory tree, computes MD5 hashes for every
file in parallel, and writes them into a SQLite hash database (`.locker_hashes.db`)
that is uploaded to the root of a remote locker.

This sidecar database is the **authoritative source of hashes** for remotes that do not
support reliable server-side hashing (notably SFTP/Hetzner). Tools like
`locker_sync_tool` read it via the sidecar path instead of trusting `rclone check`,
so the sidecar must be kept current for hash-based diffing to be correct.

The tool downloads any existing `.locker_hashes.db`, merges in the freshly computed
entries, and re-uploads the database.

## Options

### Lockers

| Option | Description |
|--------|-------------|
| `-l, --source_locker` | Source locker to hash from (default: `Local`) |
| `-d, --dest_locker` | Destination locker the sidecar is written to (default: `Hetzner`) |
| `--path` | Limit to a subpath, e.g. `Gaming/Roms` (default: whole locker root) |

Locker values: `Local`, `Hetzner`, `Gdrive`, `External`.

### Rebuild Behavior

| Option | Description |
|--------|-------------|
| `-c, --clear` | Clear existing sidecars at the destination root before rebuilding |
| `-s, --skip_existing` | Only add entries for file paths not already in the database (see below) |
| `-r, --parallel_dirs` | Number of directories to hash in parallel (default: `4`) |
| `-f, --parallel_files` | Number of files to hash in parallel per directory (default: `4`) |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## `--skip_existing` semantics

`--skip_existing` controls whether files already recorded in the remote
`.locker_hashes.db` get re-added. The behavior is subtler than the name suggests:

- **Keyed on file *path*, not content.** If a file already has an entry, its existing
  database row is left untouched — even if the file's bytes changed since. Use it to
  incrementally add *new* files (or resume an interrupted rebuild), **not** to pick up
  modifications. To refresh changed files, run **without** `--skip_existing`, or do a
  full rebuild with `--clear`.
- **It does not save hashing time.** Every local file is still hashed regardless; the
  flag only skips the database *insert* for already-known paths. The saving is in DB
  writes, not CPU/IO.
- **It is a no-op if the existing database can't be downloaded.** If the prior
  `.locker_hashes.db` fails to download, the tool starts from an empty database, so
  there are no existing paths to skip and everything is added.

Rule of thumb:
- Files may have **changed** since the last good sidecar → omit `--skip_existing`.
- You only want to fill in **newly added** files quickly → use `--skip_existing`.

## Hetzner / SFTP hashing (important)

Hetzner Storage Box is an SFTP remote whose restricted shell does **not** provide a
usable `md5sum` command. If the rclone remote is configured with `md5sum_command` /
`sha1sum_command`, rclone tries to verify every transfer by running `md5sum` over SSH,
which fails and produces misleading errors like:

```
ERROR : .locker_hashes.db: Failed to calculate src hash: ... ssh: command md5sum ... failed
ERROR : .locker_hashes.db.<id>.partial: corrupted on transfer: md5 hashes differ
        src(...) "" vs dst(...) "<hash>"
```

The `corrupted on transfer` label is a **false alarm** — the bytes transfer fine
(100%), but rclone can't fetch a hash to verify them, so it conservatively discards
the copy and deletes the `.partial`. On **upload** this means the regenerated
`.locker_hashes.db` is rejected and removed, and the run ends in `Rebuild failed`
without the sidecar actually landing on the remote.

**Fix:** disable SSH-based hash checks for the SFTP remote. In the rclone config for
the Hetzner remote, set:

```ini
disable_hashcheck = true
```

and remove any `md5sum_command` / `sha1sum_command` entries. This is wired into the
Hetzner config template in `Shared/joybox/tools/rclone.py`; the live config at
`RClone/<platform>/rclone.conf` is regenerated from that template by the RClone setup
step. With `disable_hashcheck` on, transfers verify by size instead and the
`corrupted on transfer` errors stop.

## Examples

### Rebuild the Hetzner sidecar from local content

```bash
rebuild_hash_sidecars --source_locker Local --dest_locker Hetzner -v
```

### Add only newly added files (skip existing paths)

```bash
rebuild_hash_sidecars --source_locker Local --skip_existing -v
```

### Full rebuild of a subtree

```bash
rebuild_hash_sidecars --path "Gaming/Roms" --clear -v
```

### Dry run

```bash
rebuild_hash_sidecars --source_locker Local -p -v
```

## Notes

- The sidecar is a SQLite database stored at the destination locker root as
  `.locker_hashes.db`, not flat per-file checksum files.
- The tool uses rclone for the download/upload of the database.
- Large directories (many files or very large total size) are processed sequentially
  before smaller directories are processed in parallel.
- Re-run after any change to the source content, since hash-based diffing
  (`locker_sync_tool`) is only as fresh as this sidecar.

## See Also

- `sync_tool` - Synchronize files between local storage and remote lockers
- `locker_sync_tool` - Sync between primary and secondary lockers using hash maps
