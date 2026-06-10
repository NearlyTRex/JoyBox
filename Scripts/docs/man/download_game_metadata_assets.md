# download_game_metadata_assets

Download artwork and video assets for games and back them up to a locker.

## Synopsis

```
download_game_metadata_assets [-c <category>] [-s <subcategory>] [-n <game_name>] [-t <asset_type>] [-e] [-l <locker_type>] [options]
```

## Description

`download_game_metadata_assets` fetches metadata assets (box art, screenshots, video,
etc.) for each selected game. For every game it resolves the asset URL — from the
game's store when it is a store platform, otherwise from the configured metadata asset
sources — downloads it, converts and cleans it to the expected format, then backs the
final file up to the locker (`-l, --locker_type`).

With `-t, --asset_type` you target a single asset kind; without it the download
function is invoked per game for the asset type given (when omitted the preview reports
"all types"). With `-e, --skip_existing` a game whose asset already exists in the locker
is left untouched.

Games are selected with the standard category / subcategory / name flags; omitting them
processes every matching game with a JSON entry. The preview shows the assets root
directory unless `--no-preview` is given.

## Options

### Game Selection

| Option | Description |
|--------|-------------|
| `-u, --game_supercategory` | Supercategory (default: `Roms`) |
| `-c, --game_category` | Category: `Computer`, `Microsoft`, `Nintendo`, `Other`, `Sony` |
| `-s, --game_subcategory` | Subcategory/platform (e.g., `Nintendo Switch`, `Steam`) |
| `-n, --game_name` | Name of a specific game (optional - if omitted, processes all matching games) |

### Asset Options

| Option | Description |
|--------|-------------|
| `-t, --asset_type` | Asset type: `Background`, `BoxBack`, `BoxFront`, `Label`, `Screenshot`, `Video` |
| `-e, --skip_existing` | Skip games whose asset already exists in the locker |

### Output

| Option | Description |
|--------|-------------|
| `-l, --locker_type` | Backup destination locker: `All` (default), `Local`, `Hetzner`, `Gdrive`, `External` |

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

### Download box-front art for a platform

```bash
download_game_metadata_assets -c Nintendo -s "Nintendo Switch" -t BoxFront -l Local
```

### Download a single game's screenshot

```bash
download_game_metadata_assets -c Computer -s Steam -n "Hades (World)" -t Screenshot -l Local
```

### Download missing assets only

```bash
download_game_metadata_assets -c Sony -s "Sony PlayStation 2" -t BoxFront -e -l Local
```

### Dry run for all selected games

```bash
download_game_metadata_assets -c Nintendo -s "Nintendo Switch" -t BoxFront -p -v
```

## Notes

- Each downloaded asset is converted and cleaned to the asset type's expected format
  before being backed up.
- `--skip_existing` checks the locker for an existing asset and skips the download when
  found.
- Run `build_game_metadata_files` first so asset identifiers/URLs are present in the
  metadata.

## See Also

- `build_game_metadata_files` - Build metadata entries that reference these assets
- `login_game_stores` - Authenticate with a store before fetching store-hosted assets
- `publish_game_metadata_files` - Render metadata to browsable HTML
