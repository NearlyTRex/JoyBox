# crypt_tool

Encrypt or decrypt files in place using GPG.

## Synopsis

```
crypt_tool -i <input_path> -e|-d -t <passphrase_type> [options]
```

## Description

`crypt_tool` encrypts or decrypts files using GPG with AES-256 symmetric encryption. It operates on files in place, optionally deleting the originals after processing.

Encrypted files use MD5-hashed filenames with the `.enc` extension. The original filename is embedded in the encrypted file's metadata and is automatically restored during decryption.

## Options

### Required

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Path to file or directory to process |
| `-e, --encrypt` | Encrypt files |
| `-d, --decrypt` | Decrypt files |
| `-t, --passphrase_type` | Passphrase source: `General` or `Locker` |

### Optional

| Option | Description |
|--------|-------------|
| `-k, --keep_originals` | Keep original files after encrypt/decrypt |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Passphrase Types

| Type | Description |
|------|-------------|
| `General` | General-purpose passphrase from user configuration |
| `Locker` | Locker passphrase (same as used by `upload_game_files`) |

## Examples

### Encrypt a directory

Encrypt all files in a directory using the locker passphrase:

```bash
crypt_tool -i /path/to/files -e -t Locker
```

### Decrypt files

Decrypt previously encrypted files:

```bash
crypt_tool -i /path/to/encrypted/files -d -t Locker
```

### Encrypt and keep originals

Encrypt files but keep the unencrypted originals:

```bash
crypt_tool -i /path/to/files -e -t Locker -k
```

### Encrypt a single file

Encrypt just one file:

```bash
crypt_tool -i /path/to/file.txt -e -t General
```

### Dry run

Preview what would happen without making changes:

```bash
crypt_tool -i /path/to/files -e -t Locker -p -v
```

## File Transformation

### Encryption

```
Original:   document.pdf
Encrypted:  a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.enc
```

The original filename is stored inside the encrypted file.

### Decryption

```
Encrypted:  a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.enc
Decrypted:  document.pdf
```

The original filename is automatically recovered from the encrypted file's metadata.

## Notes

- By default, original files are **deleted** after processing (use `-k` to keep them)
- The passphrase is read from user configuration, not specified on command line
- Files are processed in place (same directory)
- Use `backup_tool` if you need to encrypt/decrypt while copying to a different location
- Encrypted files from `upload_game_files` can be decrypted with `-t Locker`

## See Also

- `backup_tool` - Backup files with encryption/decryption to a different location
- `upload_game_files` - Encrypt and upload game files to remote locker
- `sync_tool` - Synchronize files with remote lockers
