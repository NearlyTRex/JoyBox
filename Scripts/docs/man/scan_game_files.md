# scan_game_files

Run the full metadata pipeline end to end: store purchases, JSON files, metadata
entries, optional assets, and HTML publishing.

## Synopsis

```
scan_game_files [-c <categories>] [-s <subcategories>] [-l <locker_type>] [-a] [-m] [-k <keys>] [options]
```

## Description

`scan_game_files` is a wrapper that drives the whole collection-building workflow in one
pass. In order, it:

1. **Loads the manifest** (only when `-m, --load_manifest` is given).
2. **Builds store purchases** — imports/updates purchases for every selected store.
3. **Builds JSON files** — scans the selected `-l, --locker_type` and (re)builds JSON
   metadata from the locker's game files.
4. **Builds metadata entries** — populates the per-subcategory metadata files.
5. **Downloads metadata assets** — only when `-a, --download_assets` is given; runs with
   skip-existing enabled.
6. **Publishes metadata** — renders the metadata to HTML.

Because this tool covers multiple steps, its selection flags are **list flags**, not the
single-value `-c`/`-s` used by the other game tools:

- `-c, --categories` takes a comma-separated list of categories.
- `-s, --subcategories` takes a comma-separated list of subcategories.

Omitting them processes all categories/subcategories. A preview of the JSON, metadata,
and published directories is shown unless `--no-preview` is given.

## Options

### Selection (list flags)

| Option | Description |
|--------|-------------|
| `-c, --categories` | Comma-separated categories (e.g., `Nintendo,Sony`) |
| `-s, --subcategories` | Comma-separated subcategories (e.g., `Nintendo Switch,Steam`) |
| `-l, --locker_type` | Source locker for the JSON build: `All`, `Local`, `Hetzner`, `Gdrive`, `External` |

### Pipeline Steps

| Option | Description |
|--------|-------------|
| `-a, --download_assets` | Also download metadata assets (skip-existing) |
| `-m, --load_manifest` | Load the manifest before running the pipeline |
| `-k, --keys` | Keys to use (comma-separated) |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Run the full pipeline for everything

```bash
scan_game_files -l Local
```

### Scan specific categories

```bash
scan_game_files -c Nintendo,Sony -l Local
```

### Scan specific subcategories and download assets

```bash
scan_game_files -s "Nintendo Switch,Steam" -l Local -a
```

### Load the manifest, then scan

```bash
scan_game_files -m -l Local
```

### Dry run

```bash
scan_game_files -l Local -p -v
```

## Notes

- Unlike the single-value `-c`/`-s` on the other game tools, here `-c, --categories` and
  `-s, --subcategories` are comma-separated **lists**.
- Asset downloading is opt-in via `-a, --download_assets`; otherwise that step is
  skipped.
- This wrapper runs the same steps as `build_game_store_purchases`,
  `build_game_json_files`, `build_game_metadata_files`,
  `download_game_metadata_assets`, and `publish_game_metadata_files` in sequence.

## See Also

- `build_game_store_purchases` - Import store purchase lists (step 2)
- `build_game_json_files` - Build JSON metadata from locker files (step 3)
- `build_game_metadata_files` - Build metadata entries (step 4)
- `download_game_metadata_assets` - Download artwork/video assets (step 5)
- `publish_game_metadata_files` - Render metadata to HTML (step 6)
