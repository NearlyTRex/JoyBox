# locker_sync_tool

Interactively sync a primary locker to one or more secondary lockers using hash maps.

## Synopsis

```
locker_sync_tool [-l <primary_locker>] [-s <secondary_lockers>] [options]
```

## Description

`locker_sync_tool` treats one locker as the authoritative **primary** (default
**Hetzner**) and brings each **secondary** locker (default **Gdrive,External**) into
agreement with it. It diffs the primary against each secondary by content hash and lets
you approve the resulting actions in a text editor before anything is transferred.

For each secondary it:

1. Builds a hash map of the primary and the secondary. Maps are computed with rclone
   `lsjson --hash` where the backend supports it, and fall back to the sidecar
   (`.locker_hashes.db`) for remotes that cannot hash server-side. SFTP remotes
   (Hetzner) always read from the sidecar. Hash maps are cached per locker for 24 hours.
2. Computes sync actions: **COPY** for files only on the primary, **UPDATE** for files
   whose hashes differ, and **RECYCLE** for orphans present only on the secondary
   (orphans are written to the secondary's `.recycle_bin`, never hard-deleted; the
   `.recycle_bin` itself is excluded from diffing).
3. Opens an editor pre-filled with the proposed actions. NEW and UPDATED entries are
   active; ORPHAN/RECYCLE entries are commented out by default (uncomment to recycle,
   leave commented to keep). Deleting all lines aborts that secondary.
4. Executes the approved actions as one batched transfer per cryption group.

Encryption is honored per direction: copying from an encrypted locker to an unencrypted
one decrypts (using the primary's passphrase); copying the other way encrypts (using the
secondary's passphrase). Each secondary's configured `excluded_dirs` are respected on
both the diff and the writes.

After a successful sync, the secondary's cached hash map is updated to reflect the
uploaded files (so a re-run within the cache window does not re-detect them), and — only
when the primary is the **Local** locker and the secondary is a sidecar-only remote
(SFTP/Hetzner) — the secondary's `.locker_hashes.db` sidecar is refreshed from local
content. The sidecar refresh is skipped on partial failure so the next run retries.

Use this when you want a guided, reviewable sync. For an unattended, additive
local-to-remote backup, use `master_backup` instead.

## Options

### Lockers

| Option | Description |
|--------|-------------|
| `-l, --primary_locker` | Primary (authoritative) locker (default: `Hetzner`) |
| `-s, --secondary_lockers` | Comma-separated secondary lockers (default: `Gdrive,External`) |

Locker values: `All`, `Local`, `Hetzner`, `Gdrive`, `External`.

### Cache

| Option | Description |
|--------|-------------|
| `--skip_cache` | Skip using cached hash maps and rebuild them fresh |
| `--clear_cache` | Clear all cached hash maps before running |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making permanent changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Examples

### Sync Hetzner to Gdrive and External (defaults)

```bash
locker_sync_tool
```

### Sync a specific primary to a single secondary

```bash
locker_sync_tool --primary_locker Local --secondary_lockers Gdrive
```

### Force fresh hash maps (ignore the 24h cache)

```bash
locker_sync_tool --skip_cache -v
```

### Clear the cache, then sync

```bash
locker_sync_tool --clear_cache
```

### Dry run to preview actions without transferring

```bash
locker_sync_tool -p -v
```

## Notes

- Orphans (files only on a secondary) are commented out in the action editor by default,
  so the tool is additive unless you explicitly uncomment them; recycled orphans go to
  the secondary's `.recycle_bin` rather than being deleted.
- Hash maps are cached per locker for 24 hours; use `--skip_cache` to rebuild fresh or
  `--clear_cache` to wipe the cache first. Caches are written even on pretend runs, since
  hashing is read-only.
- For SFTP/Hetzner, the diff relies entirely on the `.locker_hashes.db` sidecar, so it is
  only as accurate as the last sidecar rebuild. Keep it current with `master_backup` or
  `rebuild_hash_sidecars`.
- The sidecar is refreshed automatically only when the primary is the **Local** locker
  (authoritative plaintext) and the secondary is a sidecar-only remote.

## See Also

- `master_backup` - Unattended additive backup from local to remote lockers
- `rebuild_hash_sidecars` - Rebuild the hash sidecar database on a remote
- `find_missing_hash_sidecars` - List remote files missing from the sidecar database
- `sync_tool` - Lower-level synchronize between local storage and a remote locker
