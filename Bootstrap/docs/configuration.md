# Configuration

[← Docs index](README.md)

The first `setup` run creates `~/JoyBox.ini` from the platform defaults if it doesn't exist yet.
After that you edit it directly. Key settings:

```ini
[UserData.Servers]
server_0_host = myserver.com
server_0_port = 22
server_0_user = myuser
server_0_pass = ...

[UserData.Wordpress]
wordpress_subdomain = blog
wordpress_port = 8080

[UserData.Cockpit]
cockpit_subdomain = manage
cockpit_port = 9090
```

Servers are numbered (`server_0_*`, `server_1_*`, …); the number is what you pass to `-s` when
targeting `remote_ubuntu`. See [Web Server Setup](server-setup.md).

To point at a config file somewhere other than `~/JoyBox.ini`, pass `-c /path/to/JoyBox.ini`.
