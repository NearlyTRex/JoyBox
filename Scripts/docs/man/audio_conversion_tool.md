# audio_conversion_tool

Convert Audible AAX/AA audiobooks to M4A by decrypting them with activation bytes
via FFMpeg.

## Synopsis

```
audio_conversion_tool -i <input_path> [-o <output_path>] [-a <action>] [options]
```

## Description

`audio_conversion_tool` converts between audio formats. The only conversion
action currently implemented is `AaxToM4a`, which decrypts Audible `.aax` / `.aa`
files into `.m4a` using FFMpeg's `-activation_bytes` flag with stream copy
(`-c copy`), preserving quality and chapters without re-encoding.

The input path may be a single file or a directory:

- **File**: decrypts the one `.aax` / `.aa` file. If no output path is given, the
  output is the input path with a `.m4a` extension.
- **Directory**: finds `.aax` / `.aa` files in the directory (recursively with
  `-r`) and decrypts each. If no output path is given, output files are written
  next to (or into) the input directory.

### Activation bytes resolution

When `--activation_bytes` is not passed on the command line, the tool resolves
the Audible activation bytes by checking these sources in order and using the
first 8-hex-character value it finds:

1. The `[UserData.Audible] audible_activation_bytes` value in the JoyBox ini.
2. The file given by `-f, --authcode_file`.
3. The `AUDIBLE_ACTIVATION_BYTES` environment variable.
4. The default file `~/.audible_authcode`.

The resolved value must be exactly 8 hexadecimal characters or the conversion is
rejected.

## Options

### Action

| Option | Description |
|--------|-------------|
| `-a, --action` | Conversion action (default: `AaxToM4a`). Allowed: `AaxToM4a`. |

### Input/Output

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Input `.aax`/`.aa` file or a directory of them (required; must exist) |
| `-o, --output_path` | Output file or directory (optional; defaults next to the input) |

### Decryption

| Option | Description |
|--------|-------------|
| `-k, --activation_bytes` | Audible activation bytes (8 hex characters); skips automatic resolution |
| `-f, --authcode_file` | Path to a file containing the activation bytes |
| `-r, --recursive` | Recurse into subdirectories when the input is a directory |
| `--overwrite` | Overwrite existing output files (otherwise existing outputs are skipped) |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Examples

### Convert a single AAX file (activation bytes auto-resolved)

```bash
audio_conversion_tool -i "/path/to/book.aax"
```

### Convert a single file with explicit activation bytes and output path

```bash
audio_conversion_tool -i "/path/to/book.aax" -o "/path/to/book.m4a" -k 1a2b3c4d
```

### Convert every AAX file in a directory

```bash
audio_conversion_tool -i "/path/to/audiobooks"
```

### Convert recursively, overwriting existing M4A files

```bash
audio_conversion_tool -i "/path/to/audiobooks" -r --overwrite
```

### Use an authcode file for the activation bytes

```bash
audio_conversion_tool -i "/path/to/book.aax" -f "/path/to/authcode.txt"
```

### Dry run

```bash
audio_conversion_tool -i "/path/to/audiobooks" -r -p -v
```

## Notes

- Requires FFMpeg to be installed; if it is missing the conversion fails.
- Input files must have a `.aax` or `.aa` extension.
- Without `--overwrite`, an existing output file is treated as already done and
  skipped (reported as success).
- Decryption uses `-c copy`, so chapters and audio quality are preserved and the
  conversion is fast.

## See Also

- `audio_metadata_tool` - Scan, clear, and apply ID3 tags for audio files
- `download_audio_files` - Download audio into the locker music tree
- `generate_playlist` - Build `.m3u` playlists from an audio tree
