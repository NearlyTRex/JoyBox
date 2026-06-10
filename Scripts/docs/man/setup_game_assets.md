# setup_game_assets

Create the asset symlinks that point the Pegasus frontend at the locker's artwork.

## Synopsis

```
setup_game_assets [options]
```

## Description

`setup_game_assets` walks every game category and subcategory and, for each asset type
(box art, screenshots, backgrounds, etc.), creates a symlink from the Pegasus metadata
asset directory to the corresponding artwork directory in the locker. Missing source
directories are created first so the link always has a target.

Run it after building game metadata (so the frontend's asset folders resolve to the
locker's artwork), or any time the asset directory layout changes.

## Options

This tool takes only the common options.

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Create all asset symlinks

```bash
setup_game_assets -v
```

### Preview without making changes

```bash
setup_game_assets --pretend_run --verbose
```

## Notes

- Symlink support must be enabled on your system (the shared requirement check enforces this).
- Source artwork directories are created when absent, so the command is safe to re-run.

## See Also

- `download_game_metadata_assets` - Download the artwork/video assets themselves
- `setup_tools` - Install/update third-party tools
- `setup_game_emulators` - Install/update emulators
