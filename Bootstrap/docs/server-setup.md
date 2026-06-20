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
| `ccusage` | Claude Code usage monitoring |
| `claude` | Claude Code CLI |
| `cockpit` | Server management web UI |
| `wordpress` | WordPress via Docker |
| `audiobookshelf` | Audiobook streaming |
| `navidrome` | Music streaming |
| `filebrowser` | Web file manager |
| `jenkins` | CI/CD server |
| `kanboard` | Project management |
| `gh` | GitHub CLI (adds repo) |
| `ghidra` | Reverse engineering tools |
| `ollama` | Ollama local LLM runtime |

## Notes

- Server components use Docker Compose for isolation.
- See [Configuration](configuration.md) for the `[UserData.Servers]`, WordPress, and Cockpit
  keys these commands read.
