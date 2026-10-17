# Dotfiles

[← Docs index](../README.md)

The `dotfiles` component manages your shell config **non-destructively**:

- It installs the JoyBox shell config into `~/.joybox/` (`shell.sh`, `aliases.sh`,
  `functions.sh`, `completions.sh`).
- It injects a single marker-delimited block into `~/.bashrc` / `~/.bash_profile` that
  sources those files. Everything outside the block (your own edits, things added by other
  installers such as the `deno` line) is left untouched:

  ```bash
  # >>> JOYBOX MANAGED BLOCK >>>
  export JOYBOX_ROOT="..."
  case $- in *i*) ... source ~/.joybox/*.sh ... esac
  # <<< JOYBOX MANAGED BLOCK <<<
  ```

  The first time it touches an existing `~/.bashrc`/`~/.bash_profile` it keeps a one-shot
  copy at `*.joybox.backup`.

## Backup / capture

`-a backup` snapshots your managed top-level dotfiles (`.gitconfig`, `.tmux.conf`, `.vimrc`,
`.inputrc`) into `Bootstrap/dotfiles/captured/`. Review and commit that directory to version
them. The shell files (`.bashrc`/`.bash_profile`) are **not** captured — they're managed by
the block plus `~/.joybox/shell.sh`, so a whole-file copy would just duplicate them.

On `setup`, any file present in `captured/` is restored to your home directory (existing
files are backed up to `*.joybox.backup` first). To manage additional dotfiles, add them to
`self.managed_dotfiles` in `Shared/joybox/bootstrap/installers/installer_dotfiles.py`.

## VSCodium

The `vscodium` component works the same way for the editor. `-a backup` captures
`settings.json` and `keybindings.json` from `~/.config/VSCodium/User/`, and the installed
extensions as `extensions.txt`, into `Bootstrap/vscodium/`:

```bash
python3 bootstrap.py -a backup -t local_ubuntu --components vscodium
```

On `setup` it installs VSCodium if needed, writes any captured file that differs (keeping the
first copy it replaces at `*.joybox.backup`) and installs any missing extension. It counts as
installed only once all of that matches, so re-running `setup` brings an existing machine up to
date as well. The repo is public: look over a capture before committing it.
