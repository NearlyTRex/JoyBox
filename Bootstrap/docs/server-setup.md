# Web Server Setup

[← Docs index](README.md)

For setting up my website on a fresh Ubuntu server. Uses the `remote_ubuntu` target and a server
entry from `JoyBox.ini` (selected with `-s`).

```bash
# Requires server settings in JoyBox.ini (host, user, password)
python3 bootstrap.py -a setup -t remote_ubuntu -s 0
```

Or specific services:

```bash
# Just web server + SSL + management UI
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components nginx certbot cockpit

# Add WordPress site
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components wordpress
```

## Available Components (Server)

| Component | What it does |
|-----------|--------------|
| `config` | Configuration setup |
| `dotfiles` | Dot files installation |
| `githooks` | Activate the repo's git hooks (secret-scanning pre-commit) |
| `python` | Python venv + pip packages |
| `wrappers` | Script wrappers |
| `aptget` | System packages |
| `awscli` | AWS CLI |
| `flatpak` | Flatpak apps |
| `nginx` | Nginx with config templates |
| `certbot` | Let's Encrypt SSL certs |
| `node` | Global npm packages (ccusage) |
| `claude` | Claude Code CLI |
| `cockpit` | Server management web UI |
| `wordpress` | WordPress — serves the apex domain |
| `audiobookshelf` | Audiobook streaming |
| `navidrome` | Music streaming |
| `filebrowser` | Web file manager |
| `jenkins` | CI/CD server |
| `kanboard` | Project management |
| `gh` | GitHub CLI (adds repo) |
| `ghidra` | Reverse engineering tools |
| `ollama` | Ollama local LLM runtime |

## The website

WordPress serves the **apex domain**. `www` 301s to it, and both are on the certificate.

Ownership of the apex is handled through an nginx snippet rather than competing `server` blocks:
the `nginx` component installs a static `apex-root.conf`, and `wordpress` replaces it with a
proxy block, restoring the static one on teardown. Two components therefore never claim the same
`server_name`, and re-running either in isolation is safe.

### Seeded content

After the site is healthy, setup runs `Bootstrap/wordpress/seed.sh` inside the official
`wordpress:cli` container. It sets the title, tagline and permalinks, removes the stock "Hello
world!" post and Sample Page, and creates the pages listed at the bottom of the script from the
HTML fragments in `Bootstrap/wordpress/content/`.

The script is idempotent and runs on every setup. Pages are tracked by the post meta key
`_joybox_seed_id`, not by slug or title — so renaming a page in wp-admin does not cause a
duplicate to be created. **Existing pages are left alone**; your edits in wp-admin win over the
repo unless you run with `SEED_OVERWRITE=1`.

To add content, drop a fragment in `content/` and add a `seed_page` line to `seed.sh`. Set
`wordpress_seed_enabled = False` to turn seeding off entirely.

## Backups

See [Backup and Restore](backup.md). In short:

```bash
python3 bootstrap.py -a backup -t remote_ubuntu -s 0
```

Teardown keeps your data by default — volumes survive and the app directory is renamed rather
than deleted. Pass `--purge-data` to actually destroy it.

## Notes

- Server components use Docker Compose (v2) for isolation.
- Container image versions are pinned in `Bootstrap/packages/images.py`; `--list-images` shows
  them. See [Configuration](configuration.md#container-image-pins).
- See [Configuration](configuration.md) for the `[UserData.Servers]`, WordPress, and Cockpit
  keys these commands read.
