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
| `ollama` | Ollama local LLM runtime |
| `oscar` | Open OSCAR Server — self-hosted AIM/ICQ |

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

## AIM / OSCAR server

The `oscar` component builds [Open OSCAR Server](https://github.com/mk6i/open-oscar-server) from
a pinned git tag — upstream publishes no container image — and serves classic AIM and ICQ
clients.

Clients connect to `<oscar_subdomain>.<domain>` on port **5190**.

```ini
[UserData.Oscar]
oscar_subdomain = aim
oscar_port_public = 5190
oscar_port_bos = 15190
oscar_port_api = 18080
oscar_log_level = info
```

`oscar_port_public` is the port clients dial. `oscar_port_bos` and `oscar_port_api` are
host-side loopback ports that nginx proxies to — you rarely need to change them.

### Why nginx fronts a raw TCP port

The container binds to `127.0.0.1` only, and nginx's `stream` module publishes 5190.
**Docker's published ports bypass ufw**, so binding the container to `0.0.0.0` would put the
port on the internet whatever the firewall says. Routing through nginx is what makes
`ufw` actually govern it. The stream config uses a one-hour `proxy_timeout`: an OSCAR session
stays open as long as the user is signed in, so a short timeout would silently drop clients.

### Creating screen names

Accounts are **not** auto-created. `DISABLE_AUTH` is off, so an unknown screen name is rejected
rather than claimed — otherwise anyone reaching port 5190 could take any name, including yours.

Create accounts through the management API, which is proxied over HTTPS on the same subdomain
behind the shared `.htpasswd`:

```bash
curl -u <htpasswd-user> -X POST https://aim.example.com/user \
    -H 'Content-Type: application/json' \
    -d '{"screen_name":"myname","password":"..."}'

# List accounts
curl -u <htpasswd-user> https://aim.example.com/user
```

Set up the htpasswd user first with `Bootstrap/scripts/init_htpasswd.sh` if you have not
already.

### Connecting a client

Point the client's server setting at `aim.example.com` port `5190`. The server advertises that
hostname to clients after login, so it must resolve and be reachable from wherever the client
runs — a client that signs in and then hangs is almost always a wrong advertised host.

TOC, WebAPI and legacy ICQ are disabled: TOC is bound to container loopback (the server requires
the setting), the others are switched off.

### Data

Everything — accounts, buddy lists, offline messages — lives in a single SQLite file on the
`oscar_data` volume, captured by `-a backup --components oscar`. The archive is taken from the
live file, so a write in flight could in principle produce a torn copy; for a server this size
the window is negligible, but a backup taken while the service is stopped is strictly safer.

## Backups

See [Backup and Restore](backup.md). In short:

```bash
python3 bootstrap.py -a backup -t remote_ubuntu -s 0
```

Teardown keeps your data by default — volumes survive and the app directory is renamed rather
than deleted. Pass `--purge-data` to actually destroy it.

## Hardening

### Containers bind to loopback, never 0.0.0.0

Every app's compose file publishes as `127.0.0.1:<port>:<container-port>`, and nginx
is the only thing listening on a public interface.

This is not a style preference. **Docker's published ports bypass ufw** — its DNAT
rules sit ahead of ufw's chains in `FORWARD`, so a port published on `0.0.0.0` is
reachable from the internet whatever `ufw status` claims. A container reachable
directly is a container reached *without* nginx, which means without TLS, without
the shared `.htpasswd`, without ModSecurity and without rate limiting.

Any new installer must follow this. `Scripts/bin/verify_server.py` checks it.

### SSH is key-only

`init_sshd.sh --user <name>` disables password and root login via a drop-in at
`/etc/ssh/sshd_config.d/99-joybox.conf`.

It is a day-0 script rather than a `bootstrap.py` component on purpose: locking SSH
from inside a run that is itself connected over SSH is the obvious way to lock
yourself out. Before running it, set `server_N_key_filepath` in `JoyBox.ini` and
confirm `bootstrap.py` connects with the key — otherwise the next deploy cannot
reach the box.

Rehearse it on a VM first: see [Local Testing](local-testing.md#the-ssh-lockout-drill).

### Backups are encrypted at rest

Set `backup_age_recipient` to an `age` public key and archives are encrypted before
they reach the Storage Box. The server holds only the public half, so a compromised
box cannot read back its own backup history. See [Backup and Restore](backup.md).

## Notes

- Server components use Docker Compose (v2) for isolation.
- Container image versions are pinned in `Bootstrap/packages/images.py`; `--list-images` shows
  them. See [Configuration](configuration.md#container-image-pins).
- See [Configuration](configuration.md) for the `[UserData.Servers]`, WordPress, and Cockpit
  keys these commands read.
