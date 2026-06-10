# generate_playlist

Generate `.m3u` playlists from a directory tree of media files.

## Synopsis

```
generate_playlist -i <input_path> [-o <output_path>] -f <file_types> [-t <playlist_type>] [options]
```

## Description

`generate_playlist` walks an input directory and builds `.m3u` playlists from
files matching the requested extensions. It supports two playlist types:

- **Tree** (default): recursively scans the input directory and writes a single
  combined playlist to the given output file, covering the whole tree.
- **Local**: scans each directory under the input path and, for any directory
  that directly contains matching files, writes a per-directory `.m3u` next to
  the files (named after the directory, with relative/end-only paths).

The `--file_types` value is a comma-delimited list of extensions and is split on
commas to form the extension filter.

## Options

### Selection

| Option | Description |
|--------|-------------|
| `-t, --playlist_type` | Playlist type (default: `Tree`). Allowed: `Tree`, `Local`. |
| `-f, --file_types` | Comma-delimited list of file types/extensions to include |

### Input/Output

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Source directory to scan (must exist) |
| `-o, --output_path` | Output playlist file (used by `Tree`; `Local` writes a `.m3u` into each matching directory) |

### Behavior Flags

| Option | Description |
|--------|-------------|
| `--allow_empty_lists` | Allow writing playlists that contain no entries |
| `--allow_single_lists` | Allow writing playlists that contain only a single entry |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Examples

### Build one tree playlist for an audio folder

```bash
generate_playlist -t Tree -i "/path/to/music" -o "/path/to/music/all.m3u" -f "mp3,flac"
```

### Build a per-directory playlist for each album

```bash
generate_playlist -t Local -i "/path/to/music" -f "mp3"
```

### Include multiple media extensions

```bash
generate_playlist -t Tree -i "/path/to/media" -o "/path/to/media/playlist.m3u" -f "mp3,m4a,flac,ogg"
```

### Keep empty and single-entry playlists

```bash
generate_playlist -t Local -i "/path/to/music" -f "mp3" --allow_empty_lists --allow_single_lists
```

### Dry run

```bash
generate_playlist -t Local -i "/path/to/music" -f "mp3" -p -v
```

## Notes

- `--file_types` is required in practice: the tool splits its value on commas to
  build the extension filter, so omitting it has no extension list to match.
- By default, playlists that would be empty or contain only one entry are
  skipped; use `--allow_empty_lists` / `--allow_single_lists` to keep them.
- `Tree` produces one combined playlist at `--output_path`; `Local` produces one
  `.m3u` per matching directory and does not use `--output_path`.

## See Also

- `download_audio_files` - Download audio into the locker music tree
- `audio_metadata_tool` - Scan, clear, and apply ID3 tags for audio files
- `audio_conversion_tool` - Convert Audible AAX/AA files to M4A
