# Remote Server Hardening

[← Docs index](../README.md)

The rules every service on the server follows, and why. `verify_server` checks them from your
computer — see [Remote Server Setup](../setup/remote-server.md) step 5.

## Containers bind to loopback, never 0.0.0.0

Every app's compose file publishes as `127.0.0.1:<port>:<container-port>`, and nginx
is the only thing listening on a public interface.

This is not a style preference. **Docker's published ports bypass ufw** — its DNAT
rules sit ahead of ufw's chains in `FORWARD`, so a port published on `0.0.0.0` is
reachable from the internet whatever `ufw status` claims. A container reachable
directly is a container reached *without* nginx, which means without TLS, without
the shared `.htpasswd`, without ModSecurity and without rate limiting.

Any new installer must follow this. `verify_server` checks it.

## SSH is key-only

`init_sshd.sh --user <name>` disables password and root login via a drop-in at
`/etc/ssh/sshd_config.d/99-joybox.conf`.

It is a day-0 script rather than a `bootstrap.py` component on purpose: locking SSH
from inside a run that is itself connected over SSH is the obvious way to lock
yourself out. Before running it, set `server_N_key_filepath` in `JoyBox.ini` and
confirm `bootstrap.py` connects with the key — otherwise the next deploy cannot
reach the box.

Rehearse it on a VM first: see [Testing the Remote Server](../testing/remote-server.md#the-ssh-lockout-drill).

## Backups are encrypted at rest

Set `backup_age_recipient` to an `age` public key and archives are encrypted before
they reach the Storage Box. The server holds only the public half, so a compromised
box cannot read back its own backup history. See [Backup and Restore](backup-restore.md).
