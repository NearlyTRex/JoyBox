# build_game_json_files

Build JSON metadata files for games in a locker.

## Synopsis

```
build_game_json_files [options]
```

## Description

`build_game_json_files` scans game directories in a locker and creates corresponding JSON metadata files in the GameMetadata repository. These JSON files store game information used by other JoyBox tools.

The build process:
1. Scans the specified locker for game directories
2. Creates JSON metadata files for each game found
3. Updates existing JSON files with file information from the locker

This command is useful when:
- Adding new games to your locker that don't have JSON metadata yet
- Rebuilding JSON files after changes to game files
- Syncing metadata between lockers

## Options

### Game Selection

| Option | Description |
|--------|-------------|
| `-u, --game_supercategory` | Supercategory: `Roms` (default), `DLC`, `Updates`, `Saves`, etc. |
| `-c, --game_category` | Category: `Nintendo`, `Sony`, `Microsoft`, `Computer`, `Other` |
| `-s, --game_subcategory` | Subcategory/platform (e.g., `Nintendo Switch`, `Steam`) |
| `-n, --game_name` | Name of a specific game (optional - if omitted, processes all games) |

### Input/Output

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Custom input path (only used with `-n` for a specific game) |
| `-l, --source_type` | Source locker: `Remote` (default) or `Local` |
| `-t, --locker_type` | Locker type: `Hetzner` or `Gdrive` (for remote sources) |

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

### Build JSON for a specific game

Build JSON for a new Nintendo Switch update from the local locker:

```bash
build_game_json_files -u Updates -c Nintendo -s "Nintendo Switch" -n "Pokemon Legends Z-A (World)" -l Local
```

### Build JSON for all games in a category

Build JSON files for all Nintendo Switch ROMs from the remote locker:

```bash
build_game_json_files -c Nintendo -s "Nintendo Switch" -l Remote -t Hetzner
```

### Build JSON for all DLC

Build JSON for all DLC across all platforms from local locker:

```bash
build_game_json_files -u DLC -l Local
```

### Build JSON from custom path

Build JSON for a specific game using files from a custom directory:

```bash
build_game_json_files -i /path/to/game/files -c Nintendo -s "Nintendo Switch" -n "Game Name" -l Local
```

### Dry run

Preview what JSON files would be created without making changes:

```bash
build_game_json_files -c Nintendo -s "Nintendo Switch" -l Local -p -v
```

## Output

JSON files are created in the GameMetadata repository at:

```
GameMetadata/Json/<supercategory>/<category>/<subcategory>/<game_name>/<game_name>.json
```

For example:
```
GameMetadata/Json/Updates/Nintendo/Nintendo Switch/Pokemon Legends Z-A (World)/Pokemon Legends Z-A (World).json
```

## Common Use Cases

### New game added to locker

When you add a new game to your locker and `upload_game_files` fails with "Unable to find associated json file":

```bash
build_game_json_files -u <supercategory> -c <category> -s "<subcategory>" -n "<game_name>" -l Local
```

### Sync metadata after bulk import

After importing many games, build JSON for all of them:

```bash
build_game_json_files -c Nintendo -s "Nintendo Switch" -l Local
```

## Notes

- The source locker must contain the game files for the JSON to be built
- Existing JSON files are updated, not overwritten
- Use `-l Local` when building from your local locker, `-l Remote` for cloud storage
- The `-t` locker type is only needed when using `-l Remote`

## See Also

- `upload_game_files` - Upload game files to remote locker (requires JSON to exist)
- `clean_game_json_files` - Remove orphaned or invalid JSON files
- `analyze_game_json_files` - Analyze and validate JSON metadata
