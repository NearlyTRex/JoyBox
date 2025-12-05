# claude_tool

Process files in bulk using Claude AI.

## Synopsis

```
claude_tool -i <input_dir> -o <output_dir> -f <prompt_file> [options]
```

## Description

`claude_tool` processes files through the Anthropic Claude API using a customizable prompt template. It iterates over files in an input directory, sends each file's content to Claude with your prompt, and writes the responses to a mirrored output directory structure.

This tool is useful for bulk file transformations such as:
- Code cleanup and refactoring
- Documentation generation
- Format conversion
- Decompiled code cleanup (e.g., Ghidra output)

## Options

### Required

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Input directory containing files to process |
| `-o, --output_path` | Output directory for processed files |
| `-f, --prompt_file` | Path to prompt template file (markdown or text) |

### Optional

| Option | Description |
|--------|-------------|
| `-m, --model` | Claude model to use (default: `claude-sonnet-4-20250514`) |
| `-w, --extensions` | Comma-separated file extensions to process (e.g., `.cpp,.h`) |
| `-t, --max_tokens` | Maximum tokens in response (default: 8192) |
| `-e, --skip_existing` | Skip files that already exist in output directory |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes or API calls |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Prompt Template

The prompt file is a text or markdown file with variable placeholders that get substituted for each file:

| Variable | Description |
|----------|-------------|
| `{file_content}` | The full content of the input file |
| `{filename}` | The filename with extension (e.g., `main.cpp`) |
| `{file_basename}` | The filename without extension (e.g., `main`) |
| `{file_extension}` | The file extension (e.g., `.cpp`) |
| `{input_file}` | Full path to the input file |
| `{input_dir}` | The input directory path |
| `{output_dir}` | The output directory path |

### Example Prompt File

```markdown
You are a code cleanup assistant specializing in C++ decompiled code.

Clean up the following Ghidra decompiled C++ code:
- Fix variable naming (replace generic names like `local_` with meaningful names)
- Add proper indentation
- Fix type declarations
- Remove unnecessary casts
- Make it compilable, proper C++

Input file: {filename}

Code to clean:

{file_content}

Output only the cleaned code with no explanations or markdown formatting.
```

## Configuration

Before using this tool, add your Anthropic API key to `JoyBox.ini`:

```ini
[UserData.Anthropic]
anthropic_api_key = sk-ant-...
```

Or run the bootstrap script to be prompted for the key.

## Examples

### Process all files in a directory

```bash
claude_tool -i ./input -o ./output -f prompt.md
```

### Process only C++ files

```bash
claude_tool -i ./src -o ./cleaned -f ghidra_cleanup.md -w ".cpp,.h,.c"
```

### Clean up Ghidra decompiled code

```bash
claude_tool -i /path/to/NocturneDecomp/src -o /path/to/cleaned -f prompts/ghidra_cleanup.md -w ".cpp"
```

### Use a specific model

```bash
claude_tool -i ./input -o ./output -f prompt.md -m claude-sonnet-4-20250514
```

### Resume interrupted processing

Skip files that were already processed:

```bash
claude_tool -i ./input -o ./output -f prompt.md -e
```

### Dry run

Preview what would be processed without making API calls:

```bash
claude_tool -i ./input -o ./output -f prompt.md -p -v
```

### Increase response length

For large files that need longer responses:

```bash
claude_tool -i ./input -o ./output -f prompt.md -t 16384
```

## Output Structure

The output directory mirrors the input directory structure:

```
input/                      output/
├── main.cpp          ->    ├── main.cpp
├── utils/                  ├── utils/
│   ├── helper.cpp    ->    │   ├── helper.cpp
│   └── helper.h      ->    │   └── helper.h
└── game/                   └── game/
    └── player.cpp    ->        └── player.cpp
```

## Notes

- Files are processed one at a time to avoid rate limits
- The Anthropic Python package must be installed: `pip install anthropic`
- API costs apply based on token usage
- Large files may require increasing `--max_tokens`
- Use `--skip_existing` to resume interrupted batch processing

## See Also

- `crypt_tool` - Encrypt/decrypt files
- `backup_tool` - Backup files with optional encryption
