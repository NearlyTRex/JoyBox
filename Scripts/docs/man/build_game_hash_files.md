# build_game_hash_files

Compute and record file hashes for game files in a locker, writing them to the
per-subcategory hash metadata file.

## Synopsis

```
build_game_hash_files [-c <category>] [-s <subcategory>] [-n <game_name>] [-l <locker_type>] [-d] [options]
```

## Description

`build_game_hash_files` walks each selected game's files and writes their hashes into
the subcategory's JSON hash file (the hash sidecar source). For each game it resolves
the game's root directory in one of three ways, in priority order:

1. `-i, --input_path`, if given.
2. The game's offset under `-b, --locker_base_dir`, if given.
3. The default locker gaming directory for the selected `-l, --locker_type`.

Hashes are computed in JSON format, including encryption fields derived from the target
locker's passphrase, so the records line up with encrypted remote content.

With `-d, --delete_missing`, after hashing the tool also prunes hash entries that no
longer correspond to an existing file (once per affected subcategory).

Games are selected with the standard category / subcategory / name flags; omitting them
processes every matching game with a JSON entry. The preview lists the game roots to be
hashed unless `--no-preview` is given.

## Options

### Game Selection

| Option | Description |
|--------|-------------|
| `-u, --game_supercategory` | Supercategory (default: `Roms`) |
| `-c, --game_category` | Category: `Computer`, `Microsoft`, `Nintendo`, `Other`, `Sony` |
| `-s, --game_subcategory` | Subcategory/platform (e.g., `Nintendo Switch`, `Sony PlayStation 2`) |
| `-n, --game_name` | Name of a specific game (optional - if omitted, processes all matching games) |

### Input/Output

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Explicit game root to hash (overrides locker resolution) |
| `-l, --locker_type` | Source locker: `All`, `Local`, `Hetzner`, `Gdrive`, `External` |
| `-b, --locker_base_dir` | Alternate locker base directory (overrides default locker path) |

### Generation Mode

| Option | Description |
|--------|-------------|
| `-m, --generation_mode` | `Standard` (default) or `Custom` |

### Behavior

| Option | Description |
|--------|-------------|
| `-d, --delete_missing` | Remove hash entries for files that no longer exist |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Build hashes for a platform from the local locker

```bash
build_game_hash_files -c Nintendo -s "Nintendo Switch" -l Local
```

### Build hashes for one game

```bash
build_game_hash_files -c Sony -s "Sony PlayStation 2" -n "Game Name" -l Local
```

### Build hashes and prune stale entries

```bash
build_game_hash_files -c Nintendo -s "Nintendo Switch" -l Local -d
```

### Hash files from a custom base directory

```bash
build_game_hash_files -c Nintendo -s "Nintendo Switch" -b /mnt/backup/locker
```

## Notes

- Hash records include encryption fields tied to the target locker's passphrase, so
  select the `-l` locker that matches the content you are hashing.
- `--delete_missing` cleans each affected subcategory once, not once per game.
- These per-subcategory hash files are the source used when rebuilding remote hash
  sidecars.

## See Also

- `rebuild_hash_sidecars` - Rebuild the hash sidecar database on a remote locker
- `build_game_json_files` - Build JSON metadata from locker files
- `upload_game_files` - Encrypt and upload game files to a remote locker
