# The LLM Server Image

[← Docs index](../README.md)

`Scripts/autoinstall/homelab_llm.yaml` is an overlay that turns the autoinstall image into a GPU
server running ollama. How overlays work in general is in [Autoinstall Images](autoinstall.md#load-the-machine-with-software);
building and installing it step by step is [Homelab Server Setup](../setup/homelab-server.md).

There is one of these in the tree, ready to build from:

```bash
build_autoinstall_iso -y Scripts/autoinstall/homelab_llm.yaml -t llm -n llm.iso
```

It asks subiquity to install the third-party drivers it detects, which on an NVIDIA machine is
the signed `-server` driver, and adds the tools worth having on a box whose job is to feed a
card: `nvtop`, `btop`, build tooling and a Python environment. On a machine with no card it
recognises, nothing driver-shaped is installed and the rest still applies.

ollama itself goes in on first boot, from its own installer, because that installer wants a
systemd to talk to. A drop-in written beforehand settles how it runs:

```
OLLAMA_HOST=0.0.0.0:11434     listen on the network, not just on localhost
OLLAMA_MODELS=/var/lib/ollama/models
OLLAMA_KEEP_ALIVE=30m         hold a model in vram between questions
OLLAMA_NUM_PARALLEL=2
OLLAMA_MAX_LOADED_MODELS=2
```

The machine comes up with `llama3.1:8b` already pulled, `ufw` allowing only SSH and the API port,
and a `gpu-status` command that prints what the card is doing. Change the model on the last line
of the overlay, or drop the line to choose later.

**The API has no authentication.** Anything that can reach port 11434 can use the models and read
what is asked of them, so this belongs on a network you control — not on a machine with a public
address and not behind a router forwarding the port. Put it behind something that authenticates
if it needs to be reachable from elsewhere.

**Secure Boot** and NVIDIA need a word. The drivers from Ubuntu's archive are signed by Canonical
and load with Secure Boot on; drivers built by DKMS from NVIDIA's own installer are not, and
enrolling a key for them is a blue screen at the console asking for a password — on a machine
nobody is sitting at. The overlay stays on the archive drivers for that reason.

Everything in the file is ordinary overlay syntax, so it is also a worked example of the merge:
it adds `drivers`, extends `packages`, and reaches into `user-data` for `write_files` and
`runcmd` without disturbing the account, the disk layout or the SSH hardening underneath.
