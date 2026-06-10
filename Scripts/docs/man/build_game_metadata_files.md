# build_game_metadata_files

Build Pegasus metadata entries for games from their JSON data, filling in downloadable
fields from stores and metadata sources.

## Synopsis

```
build_game_metadata_files [-c <category>] [-s <subcategory>] [-n <game_name>] [-m <generation_mode>] [options]
```

## Description

`build_game_metadata_files` creates and populates the per-subcategory metadata files
consumed by the frontend. For each selected game (found from the existing JSON files)
it:

1. **Creates** a metadata entry in the subcategory's metadata file if one does not yet
   exist, seeding it with the platform, category data, the JSON file path, and sensible
   defaults (`players=1`, `coop=No`, `playable=Yes`, plus the store URL when present).
2. **Updates** the entry by checking for missing downloadable fields and, if any are
   missing, fetching the latest metadata — from the game's store when it is a store
   platform, otherwise from the configured metadata sources (TheGamesDB, GameFAQs) — and
   merging it in (including asset references).

Games are selected with the standard category / subcategory / name flags. With no
`-n`, every game with a JSON file in the selection is processed. Metadata building only
applies to the `Roms` supercategory.

The preview lists the metadata files that will be touched unless `--no-preview` is
given.

## Options

### Game Selection

| Option | Description |
|--------|-------------|
| `-u, --game_supercategory` | Supercategory (default: `Roms`) |
| `-c, --game_category` | Category: `Computer`, `Microsoft`, `Nintendo`, `Other`, `Sony` |
| `-s, --game_subcategory` | Subcategory/platform (e.g., `Nintendo Switch`, `Steam`, `Sony PlayStation 2`) |
| `-n, --game_name` | Name of a specific game (optional - if omitted, processes all matching games) |

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

### Build metadata for one game

```bash
build_game_metadata_files -c Nintendo -s "Nintendo Switch" -n "Pokemon Legends Z-A (World)"
```

### Build metadata for an entire platform

```bash
build_game_metadata_files -c Sony -s "Sony PlayStation 2"
```

### Build metadata for all games

```bash
build_game_metadata_files
```

### Dry run

```bash
build_game_metadata_files -c Computer -s Steam -p -v
```

## Notes

- Only games that already have a JSON file are processed; run `build_game_json_files`
  or `build_game_store_purchases` first to create the JSON.
- An existing metadata entry is not recreated; it is only updated when it is missing
  downloadable fields.
- Metadata is only built for the `Roms` supercategory.

## See Also

- `build_game_json_files` - Build JSON metadata from locker files
- `download_game_metadata_assets` - Download artwork/video assets referenced by metadata
- `sort_game_metadata` - Normalize the ordering of metadata files
- `publish_game_metadata_files` - Render metadata to browsable HTML
