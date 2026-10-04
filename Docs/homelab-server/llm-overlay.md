# The LLM Server Image

[← Docs index](../README.md)

`Scripts/autoinstall/homelab_llm.yaml` is an overlay that turns the autoinstall image into a GPU
server running ollama. How overlays work in general is in [Autoinstall Images](autoinstall.md#load-the-machine-with-software);
building and installing it step by step is [Homelab Server Setup](../setup/homelab-server.md).

There is one of these in the tree, ready to build from:

```bash
build_autoinstall_iso -y Scripts/autoinstall/homelab_llm.yaml -t llm -n llm.iso
```

It installs the signed `580-server` NVIDIA driver from Ubuntu's archive, with its closed kernel
modules, and adds the tools worth having on a box whose job is to feed a card: `nvtop`, `btop`,
build tooling and a Python environment. On a machine with no NVIDIA card the driver packages are
installed but nothing loads, and the rest still applies.

ollama itself goes in on first boot, from its own installer, because that installer wants a
systemd to talk to. A drop-in written beforehand settles how it runs:

```text
OLLAMA_HOST=0.0.0.0:11434     listen on the network, not just on localhost
OLLAMA_MODELS=/var/lib/ollama/models
OLLAMA_KEEP_ALIVE=-1          keep a model loaded until another is asked for
OLLAMA_NUM_PARALLEL=2
OLLAMA_MAX_LOADED_MODELS=2
```

The machine comes up with `llama3.1:8b` already pulled, `ufw` allowing only SSH, the API port and
the helper's port, and a `gpu-status` command that prints what the card is doing. Change the model
on the last line of the overlay, or drop the line to choose later.

## The helper

`ollama-helper` runs beside ollama for the two things its API does not do. Its source is
`Scripts/autoinstall/ollama_helper.py`, which the overlay carries inline; a test fails if the two
drift apart.

**Which GPUs ollama uses.** Each time ollama starts, `ollama-helper select` writes
`CUDA_VISIBLE_DEVICES` into `/run/ollama/gpus.env` for it: every NVIDIA card except the one the
firmware drew the console on (`boot_vga` in sysfs). A display card added only so the machine has a
screen stays out of the way, and a compute card added later is picked up by a reboot with nothing
to edit. A machine whose only card drives the display still computes on it.

**What the server has.** `ollama-helper serve` answers `GET http://<server>:11435/hardware` with
the cards, which of them compute, their VRAM and the machine's RAM. `ollama_tool` and `llm_chat`
read it to size models against the server rather than the machine they run on:

```bash
curl http://<server>:11435/hardware
```

## Coding against it

On the computer you code on, point `[Tools.Ollama] ollama_api_base` in `~/JoyBox.ini` at the
server (`http://<server>:11434`). Then, in the project you are working on:

```bash
ollama_tool code          # Claude Code on the best coding model the server can hold
ollama_tool code -H aider # aider, which suits local models better
llm_chat --code -a file   # or a chat with the same model, seeded with files
```

The first run picks the most capable model from a ranked list (`CODING_MODELS` in
`Shared/joybox/ollama.py`) whose weights, context and load overhead fit the computing cards,
pulls it, builds the context into a `-ctxNNk` variant, and loads it to check it sits wholly in
VRAM, falling back to the next model if it does not. Later runs reuse the prepared model and start
at once; a better one that fits is offered first, so more cards move the pick up the list.

Only Claude Code and Hermes Agent need a 64K window. The other agents and `llm_chat --code` get
32K, which leaves room for a stronger model: on one 32 GB card, Claude Code and Hermes Agent get
`qwen3-coder:30b` and the rest get the dense `devstral-small-2:24b`; on three cards, `gpt-oss:120b`.

`-H` picks the agent: `claude_code` (the default), `aider`, `opencode`, `codex` or `hermes`.
aider and opencode send far less with each request than Claude Code, which suits local models; for
a question about code rather than a change to it, `llm_chat --code -a <files>` is the most reliable,
since the model sees exactly the files given and has nothing to find on its own.

**The API has no authentication.** Anything that can reach port 11434 can use the models and read
what is asked of them, so this belongs on a network you control — not on a machine with a public
address and not behind a router forwarding the port. Put it behind something that authenticates
if it needs to be reachable from elsewhere.

**Secure Boot** and NVIDIA need a word. The drivers from Ubuntu's archive are signed by Canonical
and load with Secure Boot on; drivers built by DKMS from NVIDIA's own installer are not, and
enrolling a key for them is a blue screen at the console asking for a password — on a machine
nobody is sitting at. The overlay stays on the archive drivers for that reason.

The driver is named rather than left to subiquity's `drivers: install: true`, which picks the
newest branch with its open kernel modules. The open modules only drive Turing and later cards,
and 580 is the last branch to drive Volta at all, so a V100 sits on the bus unused under anything
newer. `580-server` with the closed modules drives both. If the box only ever carries Turing or
newer cards, a newer branch is fine.

`nvidia-utils-580-server` matters too: it is what puts `nvidia-smi` on the machine. The ollama
installer reads a missing `nvidia-smi` as no driver at all and adds NVIDIA's repository and its
DKMS driver on top, leaving the archive module loaded against newer libraries.

Everything in the file is ordinary overlay syntax, so it is also a worked example of the merge:
it extends `packages` and reaches into `user-data` for `write_files` and
`runcmd` without disturbing the account, the disk layout or the SSH hardening underneath.
