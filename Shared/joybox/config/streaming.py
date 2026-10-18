# Streaming apps
# What Sunshine offers a Moonlight client, written into its app list by
# setup_tools -k Sunshine -c. Each app has the name a client asks for it by,
# and how it starts:
# - "command": a JoyBox command, which Sunshine runs and waits on; the stream
#   ends when it exits
# - "detached" and "undo": per-platform commands Sunshine starts and leaves
#   running, and the one it runs when the stream ends
# - neither: the desktop itself
# "image" is the box art Moonlight shows, from Sunshine's own assets.
streaming_apps = [
    {
        "name": "Desktop",
        "image": "desktop.png"
    },
    {
        "name": "Pegasus",
        "command": "launch_pegasus"
    },
    {
        "name": "Steam Big Picture",
        "detached": {
            "linux": "setsid steam steam://open/bigpicture",
            "windows": "steam://open/bigpicture"
        },
        "undo": {
            "linux": "setsid steam steam://close/bigpicture",
            "windows": "steam://close/bigpicture"
        },
        "image": "steam.png"
    }
]
