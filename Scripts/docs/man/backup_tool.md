# backup_tool

Backup files between directories with optional encryption or decryption.

## Synopsis

```
backup_tool -i <input_path> -o <output_path> [options]
```

## Description

`backup_tool` copies files from a source directory to a destination directory. It supports plain copying, archiving to 7z format, and encryption/decryption using GPG with AES-256.

When using encryption or decryption, the passphrase is retrieved from the configured locker settings.

## Options

### Required

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Source directory path |
| `-o, --output_path` | Destination directory path |

### Backup Type

| Option | Description |
|--------|-------------|
| `-b, --backup_type` | `Copy` (default) or `Archive` (creates 7z archives) |

### Encryption/Decryption

| Option | Description |
|--------|-------------|
| `-r, --cryption_type` | `None` (default), `Encrypt`, or `Decrypt` |
| `-k, --locker_type` | Locker for passphrase: `Hetzner` (default) or `Gdrive` |
| `-d, --delete_original` | Delete source files after encrypt/decrypt |

### File Handling

| Option | Description |
|--------|-------------|
| `-e, --skip_existing` | Skip files that already exist at destination |
| `-a, --skip_identical` | Skip files that are identical at destination |
| `-w, --exclude_paths` | Comma-separated list of paths to exclude |

### Game Path Resolution

These options build paths relative to the locker root directory. When no explicit input/output paths are provided, the tool resolves paths based on game categories:

| Option | Description |
|--------|-------------|
| `-u, --game_supercategory` | Supercategory (e.g., `Roms`, `Saves`, `DLC`) |
| `-c, --game_category` | Category (e.g., `Nintendo`, `Sony`, `Computer`) |
| `-s, --game_subcategory` | Subcategory (e.g., `Nintendo Switch`, `Steam`) |
| `-g, --game_offset` | Additional path offset |
| `-l, --source_type` | Source location: `Local` (default) or `Remote` (mounted) |
| `-q, --destination_type` | Destination location: `Local` (default) or `Remote` (mounted) |

**Note:** The `Remote` source/destination type requires the remote locker to be mounted first using `sync_tool -a Mount`. This allows copying between local and mounted remote storage.

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Basic copy

Copy files from one directory to another:

```bash
backup_tool -i /path/to/source -o /path/to/destination
```

### Decrypt files from locker to external drive

Decrypt encrypted files (uploaded via `upload_game_files`) to a local drive:

```bash
backup_tool -i /path/to/locker/encrypted/files -o /mnt/external/games -r Decrypt
```

### Encrypt files before backup

Encrypt files when copying to a backup location:

```bash
backup_tool -i /path/to/local/files -o /path/to/backup -r Encrypt
```

### Skip existing files

Resume an interrupted backup by skipping files that already exist:

```bash
backup_tool -i /source -o /destination -e
```

### Backup with game path resolution

Backup Nintendo Switch ROMs from local locker:

```bash
backup_tool -o /mnt/external/backup -u Roms -c Nintendo -s "Nintendo Switch"
```

### Dry run

Preview what would be copied without making changes:

```bash
backup_tool -i /source -o /destination -p -v
```

### Decrypt and delete originals

Decrypt files and remove the encrypted originals after successful decryption:

```bash
backup_tool -i /encrypted -o /decrypted -r Decrypt -d
```

### Copy from mounted remote to local

First mount the remote locker, then copy and decrypt files:

```bash
# Mount the remote locker
sync_tool -a Mount -t Hetzner

# Copy from remote (mounted) to local, decrypting in the process
backup_tool -l Remote -q Local -u Roms -c Nintendo -s "Nintendo Switch" -r Decrypt
```

### Copy from local to mounted remote

Encrypt and copy local files to the mounted remote:

```bash
# Mount the remote locker
sync_tool -a Mount -t Hetzner

# Copy from local to remote (mounted), encrypting in the process
backup_tool -l Local -q Remote -u Roms -c Nintendo -s "Nintendo Switch" -r Encrypt
```

## Notes

- When decrypting, the original filename is restored from the encrypted file's metadata
- Encrypted files use the `.enc` extension with MD5-hashed filenames
- The encryption passphrase comes from the locker configuration (not specified on command line)
- Directory structure is preserved during copy operations
- When using `--skip_identical` with encryption/decryption, the tool decrypts to a temp directory first to compare file contents, then moves or skips accordingly. This avoids re-encrypting or re-decrypting files that haven't changed.

## See Also

- `upload_game_files` - Upload and encrypt game files to remote locker
- `crypt_tool` - Standalone encryption/decryption tool
- `sync_tool` - Remote synchronization tool
