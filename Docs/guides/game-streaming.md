# Game Streaming

[← Docs index](../README.md)

One computer runs the games and streams them with **Sunshine**. Another, such as a mini PC in the
living room, plays them with **Moonlight**. Both are installed by `setup_tools`. The bootstrap
starts each one at login, opens the host's firewall to the LAN, and lets Sunshine create virtual
controllers.

| Machine | Program | Command |
|---------|---------|---------|
| Host (has the games and the GPU) | Sunshine | [`launch_sunshine`](../reference/man/launch_sunshine.md) |
| Client (the TV) | Moonlight | [`launch_moonlight`](../reference/man/launch_moonlight.md) |

## The host

In `~/JoyBox.ini`:

```ini
[Tools.Sunshine]
sunshine_streaming_host = True
sunshine_allowed_subnet = 192.168.1.0/24
```

Then install and configure Sunshine, and the bootstrap pieces around it:

```bash
setup_tools -k Sunshine -c
python3 bootstrap.py -a setup -t local_ubuntu --components udev,ufw,autostart
```

- `setup_tools -c` writes the apps a client can start: **Desktop**, **Pegasus** (through
  `launch_pegasus`) and **Steam Big Picture**. Running it again replaces any apps added in
  Sunshine's web page. Settings saved in the web page are kept.
- `udev` lets the logged-in user create the virtual controllers and keyboards a client's input
  arrives through.
- `ufw` allows Sunshine's ports (TCP 47984, 47989, 47990, 48010 and UDP 47998–48000) from
  `sunshine_allowed_subnet` only. The rules apply once ufw is enabled.
- `autostart` starts `launch_sunshine` at every desktop login.

Log out and back in (or run `launch_sunshine`). Then open `https://localhost:47990`, accept the
self-signed certificate and choose the web page's username and password.

## The client

In the client's `~/JoyBox.ini`:

```ini
[Tools.Moonlight]
moonlight_host = 192.168.1.20
moonlight_app = Pegasus
moonlight_autostart = True
```

```bash
setup_tools -k Moonlight
python3 bootstrap.py -a setup -t local_ubuntu --components autostart
```

Pair once:

```bash
launch_moonlight --pair
```

Moonlight shows a PIN. Enter it on the host's web page under **PIN**. After that,
`launch_moonlight` (and every login, with `moonlight_autostart`) goes straight into
`moonlight_app` on the host. Pass `--app "Steam Big Picture"` or `--app Desktop` to pick another
one. Clear `moonlight_host` to get Moonlight's host list instead.
