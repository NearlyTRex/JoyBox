# ollama_tool

Discover, pull, and manage Ollama models sized to your hardware, and launch Claude
Code against a local Ollama model as its backend.

## Synopsis

```
ollama_tool <action> [-p <purpose>] [-m <model>] [--all] [options]
```

## Description

`ollama_tool` wraps a running [Ollama](https://ollama.com) server. It detects your GPU
VRAM and system RAM, classifies each model by how it *fits* that hardware, and helps you
find, download, and run models — including using one as the backend for Claude Code.

Hardware is detected automatically: NVIDIA (via `nvidia-smi`), then AMD / Intel Arc (via
the Linux DRM sysfs interface, with `rocm-smi` as a fallback). The primary GPU is the card
with the most VRAM.

Models are annotated with a **fit** marker relative to your hardware:

| Marker | Fit | Meaning |
|--------|-----|---------|
| `[+]` | GPU | Fits entirely in VRAM (fastest) |
| `[~]` | offload | Exceeds VRAM but fits in system RAM (CPU offload, slower) |
| `[C]` | cloud | Cloud-hosted; not downloaded or run locally |
| `[-]` | none | Too large for both VRAM and RAM |
| `[*]` | — | Already installed |

The Ollama server URL is read from the `[Tools.Ollama] ollama_api_base` setting in
`JoyBox.ini` (default `http://localhost:11434`), so you can point the tool at a remote or
containerized Ollama without editing code.

## Actions

The first positional argument selects the action:

| Action | Description |
|--------|-------------|
| `list` | List models already installed on the Ollama server |
| `available` | Show catalog models with fit classification for your hardware, and optionally pull one. Filter with `-p`. |
| `best` | Auto-pick the best locally-runnable model for a purpose (highest fit tier, then largest parameter count) and offer to pull it |
| `pull` | Download a model. With a base name it prompts for the quantization; with a full tag it pulls directly (see Notes) |
| `delete` | Remove an installed model (prompts to select if `-m` is omitted) |
| `info` | Show `ollama show` details for a model (prompts to select if `-m` is omitted) |
| `claude` | Launch Claude Code using an installed Ollama model as the backend |

## Options

| Option | Description |
|--------|-------------|
| `-p, --purpose` | Filter/target a purpose category. Allowed: `chat`, `tools`, `reasoning`, `vision`, `embedding`, `cloud`. If omitted where relevant, you're prompted to pick one. |
| `-m, --model` | Model name for `pull` / `delete` / `info` / `claude`. A base name (e.g. `qwen2.5-coder:7b`) lists quantizations; a full tag (e.g. `qwen2.5-coder:7b-instruct-q4_K_M`) targets one exactly. |
| `--all` | In `available`, also show models too large for your system (`[-]`) instead of hiding them |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Claude Code backend

`ollama_tool claude` runs Claude Code pointed at your local Ollama server. It sets:

- `ANTHROPIC_BASE_URL` = the configured `ollama_api_base`
- `ANTHROPIC_API_KEY` = `ollama`
- `ANTHROPIC_AUTH_TOKEN` = *(empty)*

then execs `claude --model <model> --bare`. Ollama serves the Anthropic-compatible
`/v1/messages` endpoint, so Claude Code talks to it directly.

Before launching, the model's advertised context window is checked against Claude Code's
recommended minimum (64K tokens). If it falls short, you're warned and asked whether to
launch anyway — this is expected, not an error.

## Examples

### List installed models

```bash
ollama_tool list
```

### Browse tool-capable models for your hardware

```bash
ollama_tool available -p tools
```

### Let the tool pick the best model for coding/agentic use

```bash
ollama_tool best -p tools
```

### Pull a model (choose a quantization interactively)

```bash
ollama_tool pull -m qwen2.5-coder:7b
```

### Pull a specific quantization without the picker

```bash
ollama_tool pull -m qwen2.5-coder:7b-instruct-q4_K_M
```

### Run Claude Code on a local model

```bash
ollama_tool claude -m qwen2.5-coder:7b
```

### Delete or inspect a model

```bash
ollama_tool delete -m qwen2.5-coder:7b
ollama_tool info -m qwen2.5-coder:7b
```

## Notes

- **The quantization picker is intentional.** Passing a *base* model name (e.g.
  `qwen2.5-coder:7b`) lists every matching tag — all the quant levels and `-base` /
  `-instruct` variants — and prompts you to choose, since more than one matches. Type the
  number of the variant you want, or `0` to cancel. To skip the picker, pass a
  **fully-qualified tag** so exactly one option matches (e.g.
  `qwen2.5-coder:7b-instruct-q4_K_M`); it pulls immediately.
- **Downloads stream live progress** — a `pull` shows Ollama's native progress bar.
- **Context window vs. runtime context.** The context figure shown for each tag is the
  model's *advertised* maximum. Ollama's *runtime* `num_ctx` defaults to a much smaller
  value regardless of that maximum; for long Claude Code sessions, start the server with a
  larger window, e.g. `OLLAMA_CONTEXT_LENGTH=65536 ollama serve` (or bake `num_ctx` into a
  Modelfile).
- **Server URL** comes from `[Tools.Ollama] ollama_api_base` in `JoyBox.ini`. Point it at a
  remote host to manage/run models there.
- **Local models are weaker at agentic tool use** than hosted Claude — useful for
  experimenting, not a drop-in replacement.

## See Also

- `claude_tool` - Process files in bulk using Claude AI
- [Ollama library](https://ollama.com/library) - Browse available models
