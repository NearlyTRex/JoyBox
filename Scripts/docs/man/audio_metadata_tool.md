# audio_metadata_tool

Scan, clear, and apply ID3 tags for albums in a locker's music tree, using JSON
sidecar files as the source of truth.

## Synopsis

```
audio_metadata_tool [-a <action>] [-g <genre>] [-b <album>] [-r <artist>] [options]
```

## Description

`audio_metadata_tool` manages audio metadata for albums stored under a genre
directory in the local locker music tree. It operates on whole albums (a folder
of audio files), and uses a per-album JSON metadata file as the intermediate
representation that ties the three actions together:

- **Tag** (default): scans each album's audio files and extracts their tags into
  a JSON metadata file (one JSON per album).
- **Apply**: reads the album's JSON metadata file and writes those tags back into
  the audio files.
- **Clear**: strips existing tags from the album's audio files.

Album directories are discovered under the genre's music directory. If no
`--album` is given, every album under the genre is processed; the tool also
detects a two-level `artist/album` structure and treats the parent folder name
as the artist when it differs from the genre name.

## Options

### Action and Selection

| Option | Description |
|--------|-------------|
| `-a, --action` | Action to perform (default: `Tag`). Allowed: `Tag`, `Clear`, `Apply`. |
| `-g, --genre` | Music genre directory (default: `Regular`). Allowed: `ASMR`, `Audiobook`, `Classical`, `Game`, `Radio`, `Regular`, `Soundtrack`, `Story`, `Therapy`. |
| `-b, --album` | Specific album name to process (if omitted, all albums under the genre are processed) |
| `-r, --artist` | Specific artist name, for albums stored under an `artist/album` structure |

### Behavior Flags

| Option | Description |
|--------|-------------|
| `--preserve_artwork` | When clearing tags (`Clear`), keep embedded artwork |
| `--clear_existing` | When applying tags (`Apply`), clear existing tags before writing the new ones |
| `--exclude_comments` | When extracting tags (`Tag`), exclude comment frames from the JSON |
| `--use_index_for_track_number` | When extracting tags (`Tag`), override track numbers with the file's index in the album |
| `--set <field>=<value>` | When extracting tags (`Tag`), force a curated tag to a fixed value on every track. Repeatable; overrides whatever is read from the files. |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Examples

### Extract tags to JSON for every album in a genre

```bash
audio_metadata_tool -a Tag -g Soundtrack
```

### Extract tags for one album, ignoring comments

```bash
audio_metadata_tool -a Tag -g Regular -b "Some Album" --exclude_comments
```

### Renumber tracks by file order while extracting

```bash
audio_metadata_tool -a Tag -g Audiobook -b "Some Book" --use_index_for_track_number
```

### Force fields to fixed values while extracting

```bash
audio_metadata_tool -a Tag -g Regular -b "Some Album" \
  --set genre=Regular --set album_artist="Various Artists"
```

### Apply the JSON tags back into the files

```bash
audio_metadata_tool -a Apply -g Soundtrack -b "Some Album"
```

### Apply tags after wiping the existing ones

```bash
audio_metadata_tool -a Apply -g Regular -b "Some Album" --clear_existing
```

### Clear all tags but keep the cover art

```bash
audio_metadata_tool -a Clear -g Regular -b "Some Album" --preserve_artwork
```

### Process an album under an artist folder

```bash
audio_metadata_tool -a Tag -g Regular -r "Some Artist" -b "Some Album"
```

## Notes

- The default action is `Tag`, so running the tool with no `-a` extracts metadata
  into JSON rather than modifying audio files.
- `Apply` requires the album's JSON metadata file to already exist; run `Tag`
  first to create it. If the JSON is missing, the apply step fails.
- The JSON metadata file is written one per album, keyed by genre, album, and
  (when present) detected artist.
- `--set` applies to `Tag` only. Each override is written to every track and to
  the album-level info, winning over the value read from the file (and over
  `--use_index_for_track_number` when forcing `track_number`). It can be given
  more than once to force multiple fields. The field must be one of the curated
  tags: `title`, `artist`, `album`, `year`, `genre`, `album_artist`,
  `track_number`, `disc_number`, `bpm`, `key`, `conductor`; an unknown field or a
  value missing the `=` separator is rejected before any album is scanned.

## See Also

- `download_audio_files` - Download audio into the locker music tree
- `audio_conversion_tool` - Convert Audible AAX/AA files to M4A
- `generate_playlist` - Build `.m3u` playlists from an audio tree
