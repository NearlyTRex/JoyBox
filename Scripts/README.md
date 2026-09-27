# JoyBox Scripts

Files the commands read from disk:

- `autoinstall/` — overlays for `build_autoinstall_iso` (`homelab_llm.yaml`)
- `icons/` — icons used when packaging tools (BostonIcons)

The commands themselves live in `Shared/joybox/cli` and are installed into `~/.venv/bin` by pip
from `[project.scripts]` in `pyproject.toml`.

- [Using the Tools](../Docs/guides/using-the-tools.md)
- [Command Reference](../Docs/reference/man/README.md) — generated from each command's `--help`
  by `build_man_pages`
- [All documentation](../Docs/README.md)
