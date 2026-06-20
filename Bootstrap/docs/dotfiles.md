# Dotfiles

[← Docs index](README.md)

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
`self.managed_dotfiles` in `installers/installer_dotfiles.py`.
