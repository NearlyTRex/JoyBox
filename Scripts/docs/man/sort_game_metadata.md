# sort_game_metadata

Normalize every Pegasus game metadata file by re-importing and re-exporting it in sorted
order.

## Synopsis

```
sort_game_metadata [options]
```

## Description

`sort_game_metadata` walks the Pegasus metadata directory, finds every game metadata
file, and rewrites each one in canonical sorted form. For each file it imports the
metadata into memory and exports it back to the same path (without appending to existing
content), which normalizes entry ordering and formatting.

This tool takes no game-selection flags — it processes all metadata files
unconditionally. A preview showing the metadata directory and the number of files to
sort is displayed unless `--no-preview` is given. With `-p, --pretend_run` the files are
listed but not rewritten.

Use this to keep metadata files tidy and produce clean diffs after bulk edits.

## Options

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run — list files without rewriting them |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Sort all metadata files

```bash
sort_game_metadata
```

### Preview which files would be sorted

```bash
sort_game_metadata -p
```

### Sort with verbose output and no prompt

```bash
sort_game_metadata -v --no-preview
```

## Notes

- There are no category/subcategory/name selectors — every metadata file is processed.
- Run this after bulk metadata changes to keep entry ordering consistent and diffs
  minimal.

## See Also

- `build_game_metadata_files` - Build metadata entries from JSON data
- `publish_game_metadata_files` - Render metadata to browsable HTML
