# upload_game_files

Encrypt and upload game files to a remote locker.

## Synopsis

```
upload_game_files -c <category> -s <subcategory> -n <game_name> -t <locker_type> [options]
```

## Description

`upload_game_files` encrypts game files using GPG (AES-256) and uploads them to a remote locker (cloud storage). The original unencrypted files are deleted after encryption.

The upload process:
1. Encrypts all files in the game directory (deletes originals)
2. Generates hash files for integrity verification
3. Uploads encrypted files to the remote locker

Encrypted files use MD5-hashed filenames with the `.enc` extension. The original filename is embedded in the encrypted file's metadata and can be recovered during decryption.

## Options

### Game Selection

| Option | Description |
|--------|-------------|
| `-u, --game_supercategory` | Supercategory: `Roms` (default), `DLC`, `Updates`, `Saves`, etc. |
| `-c, --game_category` | Category: `Nintendo`, `Sony`, `Microsoft`, `Computer`, `Other` |
| `-s, --game_subcategory` | Subcategory/platform (e.g., `Nintendo Switch`, `Steam`) |
| `-n, --game_name` | Name of the game |

### Input/Output

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Custom input path (overrides default game directory) |
| `-l, --source_type` | Source location: `Local` (default) or `Remote` |
| `-t, --locker_type` | Target locker: `Hetzner` or `Gdrive` |

### Generation Mode

| Option | Description |
|--------|-------------|
| `-m, --generation_mode` | `Standard` (default) or `Custom` |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Upload a specific game

Upload a Nintendo Switch game to Hetzner:

```bash
upload_game_files -c Nintendo -s "Nintendo Switch" -n "Game Name" -t Hetzner
```

### Upload a Steam game

Upload a PC game from the Steam subcategory:

```bash
upload_game_files -c Computer -s Steam -n "Game Name" -t Hetzner
```

### Upload DLC

Upload DLC files for a game:

```bash
upload_game_files -u DLC -c Nintendo -s "Nintendo Switch" -n "Game Name" -t Hetzner
```

### Upload from custom path

Upload files from a specific directory:

```bash
upload_game_files -i /path/to/game/files -c Nintendo -s "Nintendo Switch" -n "Game Name" -t Hetzner
```

### Dry run

Preview what would be uploaded without making changes:

```bash
upload_game_files -c Nintendo -s "Nintendo Switch" -n "Game Name" -t Hetzner -p -v
```

## File Structure

### Before upload

```
GameName/
├── game.nsp
├── update.nsp
└── dlc.nsp
```

### After upload (local)

```
GameName/
├── a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.enc
├── b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7.enc
├── c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8.enc
└── hashes.txt
```

The same encrypted files are uploaded to the remote locker.

## Recovering Files

To decrypt uploaded files back to their original form, use `crypt_tool`:

```bash
crypt_tool -i /path/to/encrypted/files -d -t Locker
```

Or use `backup_tool` to decrypt while copying to another location:

```bash
backup_tool -i /path/to/encrypted/files -o /path/to/output -r Decrypt
```

## Notes

- Original files are **deleted** after encryption - ensure you have backups if needed
- The passphrase is read from locker configuration, not specified on command line
- Hash files are generated for integrity verification
- Encrypted filenames are MD5 hashes of the original filenames
- Original filenames are preserved in the encrypted file metadata

## See Also

- `backup_tool` - Backup/restore files with encryption/decryption
- `sync_tool` - Synchronize files with remote lockers
- `crypt_tool` - Standalone encryption/decryption tool
