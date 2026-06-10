# publish_game_metadata_files

Render the game metadata into browsable HTML pages, one per category.

## Synopsis

```
publish_game_metadata_files [options]
```

## Description

`publish_game_metadata_files` reads the per-subcategory metadata files and generates an
HTML page for each category in the published metadata directory. For every category it
iterates the metadata entries (sorted by platform and name), emits a table row per game
using alternating odd/even row templates with the game's name, platform, player count
and co-op flag, and writes the result to `<Category>.html`. Only the `Roms`
supercategory is published.

This tool takes no game-selection flags — it publishes all categories unconditionally. A
preview of the published metadata directory is shown unless `--no-preview` is given.

Run this as the final step after building/updating metadata (it is also the last step of
`scan_game_files`).

## Options

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Publish all metadata to HTML

```bash
publish_game_metadata_files
```

### Publish without the confirmation prompt

```bash
publish_game_metadata_files --no-preview
```

### Dry run

```bash
publish_game_metadata_files -p -v
```

## Output

One HTML file per category is written to the published metadata directory:

```
<published_metadata_dir>/<Category>.html
```

For example: `Nintendo.html`, `Sony.html`, `Computer.html`.

## Notes

- There are no category/subcategory/name selectors — every category is published.
- Only `Roms` metadata is included in the output.
- `scan_game_files` runs this same publish step at the end of its pipeline.

## See Also

- `build_game_metadata_files` - Build the metadata entries that get published
- `sort_game_metadata` - Normalize metadata file ordering before publishing
- `scan_game_files` - Full pipeline that ends with this publish step
