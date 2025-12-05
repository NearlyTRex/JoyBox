# sync_tool

Synchronize files between local storage and remote lockers (cloud storage).

## Synopsis

```
sync_tool -a <action> -t <locker_type> [options]
```

## Description

`sync_tool` manages file synchronization between a local directory and a remote locker (cloud storage). It uses rclone under the hood and supports various sync operations including upload, download, bidirectional merge, and diff comparison.

The tool reads locker configuration (remote name, paths, credentials) from user settings.

## Actions

| Action | Description |
|--------|-------------|
| `Init` | Initialize/configure the remote connection |
| `Download` | Download files from remote to local (overwrites local) |
| `Upload` | Upload files from local to remote (overwrites remote) |
| `Pull` | Download only newer files from remote |
| `Push` | Upload only newer files to remote |
| `Merge` | Bidirectional sync - sync changes both ways |
| `Diff` | Compare local and remote, output differences to files |
| `DiffSync` | Sync based on previously generated diff files |
| `EmptyRecycle` | Empty the remote recycle bin folder |
| `List` | List files on the remote |
| `Mount` | Mount the remote as a local filesystem |

## Options

### Required

| Option | Description |
|--------|-------------|
| `-a, --action` | Sync action to perform (see Actions above) |
| `-t, --locker_type` | Locker to sync with: `Hetzner` or `Gdrive` |

### Sync Behavior

| Option | Description |
|--------|-------------|
| `-e, --resync` | Force full resync (for Merge action) |
| `-i, --interactive` | Prompt before each file operation |
| `-q, --quick` | Quick mode - skip checksums, use size/time only |
| `--excludes` | Comma-separated paths to exclude (default: `Gaming/Roms/**,Gaming/DLC/**,Gaming/Updates/**`) |

### Recycle Bin

| Option | Description |
|--------|-------------|
| `-r, --recycle_missing` | Move remote-only files to recycle bin instead of downloading |
| `--recycle_folder` | Recycle bin folder name on remote (default: `.recycle_bin`) |

### Diff Options

| Option | Description |
|--------|-------------|
| `--diff_dir` | Directory containing diff files (for DiffSync) |
| `--diff_combined_path` | Output file for all differences (default: `diff_combined.txt`) |
| `--diff_intersected_path` | Output file for files present in both (default: `diff_intersected.txt`) |
| `--diff_missing_src_path` | Output file for files missing from local (default: `diff_missing_src.txt`) |
| `--diff_missing_dest_path` | Output file for files missing from remote (default: `diff_missing_dest.txt`) |
| `--diff_error_path` | Output file for errors (default: `diff_errors.txt`) |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Initialize a locker connection

Set up the remote connection for the first time:

```bash
sync_tool -a Init -t Hetzner
```

### Download all files from remote

Download everything from remote to local (excluding ROMs/DLC/Updates):

```bash
sync_tool -a Download -t Hetzner
```

### Upload local changes to remote

Upload local files to remote:

```bash
sync_tool -a Upload -t Hetzner
```

### Pull only newer files

Download only files that are newer on remote:

```bash
sync_tool -a Pull -t Hetzner
```

### Push only newer files

Upload only files that are newer locally:

```bash
sync_tool -a Push -t Hetzner
```

### Bidirectional merge

Sync changes both ways (newest wins):

```bash
sync_tool -a Merge -t Hetzner
```

### Force full resync

Force a complete bidirectional resync:

```bash
sync_tool -a Merge -t Hetzner -e
```

### Compare local and remote

Generate diff files showing what's different:

```bash
sync_tool -a Diff -t Hetzner
```

This creates files like `diff_missing_src.txt` (files only on remote) and `diff_missing_dest.txt` (files only locally).

### Quick diff (faster, less accurate)

Compare using only file size and modification time:

```bash
sync_tool -a Diff -t Hetzner -q
```

### Sync based on diff files

After reviewing diff files, sync the differences:

```bash
sync_tool -a DiffSync -t Hetzner --diff_dir /path/to/diff/files
```

### Move remote-only files to recycle

Instead of downloading files that only exist on remote, move them to a recycle bin:

```bash
sync_tool -a DiffSync -t Hetzner -r
```

### Empty the remote recycle bin

Permanently delete files in the remote recycle bin:

```bash
sync_tool -a EmptyRecycle -t Hetzner
```

### List remote files

List all files on the remote:

```bash
sync_tool -a List -t Hetzner
```

### Mount remote as filesystem

Mount the remote storage as a local directory:

```bash
sync_tool -a Mount -t Hetzner
```

### Dry run

Preview what would happen without making changes:

```bash
sync_tool -a Upload -t Hetzner -p -v
```

### Include ROMs in sync

Override the default excludes to include ROMs:

```bash
sync_tool -a Download -t Hetzner --excludes ""
```

## Default Excludes

By default, the following paths are excluded from sync operations:

- `Gaming/Roms/**`
- `Gaming/DLC/**`
- `Gaming/Updates/**`

This is because these are typically large files that are handled separately via `upload_game_files` and `backup_tool`.

## Notes

- The tool uses rclone for remote operations
- Locker configuration (credentials, paths) is read from user settings
- The `Merge` action uses rclone's bisync feature
- `Diff` is useful for reviewing changes before syncing
- The recycle bin feature helps prevent accidental data loss

## See Also

- `backup_tool` - Backup files with optional encryption/decryption
- `upload_game_files` - Upload and encrypt game files to remote locker
