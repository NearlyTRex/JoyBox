# Game Streaming

[← Docs index](../README.md)

One computer runs the games and streams them with **Sunshine**. Another, such as a mini PC in the
living room, plays them with **Moonlight**. `setup_tools` installs them, and its configure step
(`-c`) adds the one each machine's role uses to the app menu. The bootstrap starts it at login,
opens the host's firewall to the LAN, and lets Sunshine create virtual controllers.

| Machine | Program | Command |
|---------|---------|---------|
| Host (has the games and the GPU) | Sunshine | [`launch_sunshine`](../reference/man/launch_sunshine.md) |
| Client (the TV) | Moonlight | [`launch_moonlight`](../reference/man/launch_moonlight.md) |

A new `~/JoyBox.ini` asks which of these a machine is and fills in the settings below, so on a
fresh machine the `curl … | bash` install sets up the bootstrap side: answer the streaming
question and take every component, then run the `setup_tools` line below. For an existing ini,
`python3 bootstrap.py -t local_ubuntu --recreate-config` asks again and keeps everything else.

## The host

In `~/JoyBox.ini`:

```ini
[Tools.Sunshine]
sunshine_streaming_host = True
sunshine_allowed_subnet = 192.168.1.0/24
```

Then set it up:

```bash
setup_tools -k Sunshine -c
python3 bootstrap.py -a setup -t local_ubuntu --components udev,ufw,autostart
```

- `setup_tools -c` writes the apps a client can start, from `streaming_apps` in
  `Shared/joybox/config/streaming.py`: **Desktop**, **Pegasus** (through `launch_pegasus`) and
  **Steam Big Picture** to begin with. Edit that list to offer other apps, or fewer, then run it
  again. It also adds Sunshine to the app menu. Running it replaces any apps added in Sunshine's
  web page; settings saved in the web page are kept.
- `udev` lets the logged-in user create the virtual controllers and keyboards a client's input
  arrives through.
- `ufw` allows Sunshine's ports (TCP 47984, 47989, 47990, 48010 and UDP 47998–48000) from
  `sunshine_allowed_subnet` only. The rules apply once ufw is enabled.
- `autostart` starts `launch_sunshine` at every desktop login.

`setup_tools -c` also writes the web page's login, from the 1Password fields
`UserData.Streaming/sunshine_user` and `sunshine_pass` (the `[UserData.Streaming]` settings).
Sunshine keeps only a salted hash of the password, and its paired clients are left as they were.
Without those fields, the web page asks you to choose a login the first time you open it.

Log out and back in (or run `launch_sunshine`). Then open `https://localhost:47990`, accept the
self-signed certificate and sign in.

## The client

In the client's `~/JoyBox.ini` (answering **client** when the ini is created sets these;
`moonlight_autostart` is the answer to whether to stream at every login):

```ini
[Tools.Moonlight]
moonlight_client = True
moonlight_host = 192.168.1.12
moonlight_app = Pegasus
moonlight_autostart = True
```

`192.168.1.12` is the host's address by default, so give the host that address with a DHCP
reservation on the router, or set `moonlight_host` to wherever it is.

```bash
setup_tools -k Moonlight -c
python3 bootstrap.py -a setup -t local_ubuntu --components autostart
```

`setup_tools -c` installs Moonlight and adds it to the app menu, and `autostart` starts it at
every login when `moonlight_autostart` is on.

Pair once:

```bash
launch_moonlight --pair
```

Moonlight shows a PIN. Enter it on the host's web page under **PIN**. After that,
`launch_moonlight` (and every login, with `moonlight_autostart`) goes straight into
`moonlight_app` on the host. Pass `--app "Steam Big Picture"` or `--app Desktop` to pick another
one, or set `moonlight_app` to make it the default. `launch_moonlight --list` shows the apps the
host offers, the names those take. Clear `moonlight_host` to get Moonlight's host list instead.
