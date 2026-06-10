# find_missing_hash_sidecars

List files present on a remote locker but missing from its hash sidecar database.

## Synopsis

```
find_missing_hash_sidecars [-l <locker_type>] [--path <subpath>] [-r <report>] [options]
```

## Description

`find_missing_hash_sidecars` audits a remote locker's `.locker_hashes.db` sidecar for
coverage gaps. It lists every file actually present on the remote and compares that set
against the paths recorded in the sidecar, reporting any file that is on the remote but
has no sidecar entry.

This matters for sidecar-only remotes such as SFTP/Hetzner, where the sidecar is the
source of truth for hash-based diffing (see `locker_sync_tool`). A file that exists on
the remote but is absent from the sidecar is effectively invisible to hash diffing, so
this tool surfaces those before they cause a sync to misbehave.

It performs the following steps:

1. Resolves the remote locker (default **Hetzner**) and verifies the rclone remote is
   configured.
2. Lists all files on the remote under the chosen path (the `.locker_hashes.db` file
   itself is excluded from the listing).
3. Reads the sidecar database from the locker root (always the root, regardless of
   `--path`).
4. Reports every remote file whose relative path is not present in the sidecar. When
   `--path` is given, remote paths are prefixed with the subpath before comparison so
   they line up with the root-relative keys in the sidecar.

Up to 20 missing files are printed to the log with a total count; pass `--report` to
write the complete list to a file.

If everything is covered, it logs "All files have hash sidecars". The tool is read-only
— it does not modify the sidecar. To repair gaps, run `rebuild_hash_sidecars` (or
`master_backup`, which refreshes the sidecar automatically).

## Options

### Locker

| Option | Description |
|--------|-------------|
| `-l, --locker_type` | Remote locker to check (default: `Hetzner`) |
| `--path` | Subpath to check, e.g. `Gaming/Roms` (default: empty = whole locker root) |

Locker values: `All`, `Local`, `Hetzner`, `Gdrive`, `External`.

### Report

| Option | Description |
|--------|-------------|
| `-r, --report` | Path to write the full list of missing files (default: none; log-only) |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making permanent changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Examples

### Check the whole Hetzner locker

```bash
find_missing_hash_sidecars
```

### Check a specific subtree

```bash
find_missing_hash_sidecars --path "Gaming/Roms" -v
```

### Write the full missing list to a report file

```bash
find_missing_hash_sidecars -r /tmp/missing_sidecars.txt
```

### Audit a different locker verbosely

```bash
find_missing_hash_sidecars --locker_type Hetzner --verbose
```

## Notes

- The sidecar database (`.locker_hashes.db`) is always read from the locker **root**,
  even when `--path` limits the remote listing to a subtree.
- Only the first 20 missing files are shown in the log; use `--report` to capture the
  complete list.
- This tool reports gaps only — it does not fix them. Rebuild coverage with
  `rebuild_hash_sidecars` or let `master_backup` refresh the sidecar after a sync.
- The check is most meaningful for sidecar-only remotes (SFTP/Hetzner), which cannot hash
  server-side and rely on the sidecar as the source of truth.

## See Also

- `rebuild_hash_sidecars` - Rebuild the hash sidecar database on a remote
- `master_backup` - Unattended additive backup that refreshes the sidecar automatically
- `locker_sync_tool` - Sync between primary and secondary lockers using hash maps
