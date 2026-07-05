# ollama_tool

Discover, pull, and manage Ollama models sized to your hardware, and launch Claude
Code against a local Ollama model as its backend.

## Synopsis

```
ollama_tool <action> [-p <purpose>] [-m <model>] [-H <harness>] [--all] [options]
```

## Description

`ollama_tool` wraps a running [Ollama](https://ollama.com) server. It detects your GPU
VRAM and system RAM, classifies each model by how it *fits* that hardware, and helps you
find, download, and run models — including using one as the backend for a coding-agent
harness such as Claude Code.

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
| `harness` | Launch a coding-agent harness (`-H`, default Claude Code) using an installed Ollama model as the backend |

## Options

| Option | Description |
|--------|-------------|
| `-p, --purpose` | Filter/target a purpose category. Allowed: `chat`, `tools`, `reasoning`, `vision`, `embedding`, `cloud`. If omitted where relevant, you're prompted to pick one. |
| `-m, --model` | Model name for `pull` / `delete` / `info` / `harness`. A base name (e.g. `qwen2.5-coder:7b`) lists quantizations; a full tag (e.g. `qwen2.5-coder:7b-instruct-q4_K_M`) targets one exactly. |
| `-H, --harness` | Coding-agent harness for the `harness` action: `claude_code`, `codex`, `opencode` (default: `claude_code`) |
| `--all` | In `available`, also show models too large for your system (`[-]`) instead of hiding them |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Coding-agent harnesses

`ollama_tool harness` runs a coding-agent harness pointed at your local Ollama server.
Pick one with `-H` (default `claude_code`). Each harness sets the environment that routes
it to Ollama and runs its CLI against the chosen model:

| Harness (`-H`) | Backend | Env → Ollama | Command | Min ctx |
|----------------|---------|--------------|---------|---------|
| `claude_code` | Anthropic `/v1/messages` | `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY=ollama` | `claude --model <m> --bare` | 64K |
| `codex` | OpenAI `/v1` | `OPENAI_BASE_URL=<base>/v1`, `OPENAI_API_KEY=ollama` | `codex -m <m>` | 8K |
| `opencode` | OpenAI `/v1` | `OPENAI_BASE_URL=<base>/v1`, `OPENAI_API_KEY=ollama` | `opencode --model <m>` | 8K |

Ollama serves both the Anthropic (`/v1/messages`) and OpenAI (`/v1/chat/completions`)
compatible endpoints, so these harnesses talk to it directly.

Before launching, the model's advertised context window is checked against the chosen
harness's recommended minimum. If it falls short, you're warned and asked whether to launch
anyway — this is expected, not an error. Claude Code assumes a large context window and
strong tool-calling, so it needs a capable model; the OpenAI-compatible harnesses have a
lower context floor.

If the harness's CLI isn't installed, the tool reports it with an install hint. The
`codex` / `opencode` entries are **best-effort**: they point those tools at Ollama's
OpenAI-compatible endpoint, but the tools may also need their own provider config and their
exact launch flags vary by version. The harness registry (`HARNESSES` in
`Shared/joybox/ollama.py`) is the place to adjust commands or add new harnesses.

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
ollama_tool harness -m qwen2.5-coder:7b            # default harness = claude_code
```

### Run a different harness (OpenAI-compatible)

```bash
ollama_tool harness -H codex -m qwen2.5-coder:7b
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
