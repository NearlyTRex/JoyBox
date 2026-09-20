# Local imports
from joybox import config


###########################################################
# Shared values for the sync suite
#
# sync.py is large enough that its tests are split by area. Anything more than
# one file needs lives here, so a helper cannot drift between files or shadow
# another file's copy of itself.
###########################################################

REMOTE = "hetzner"
REMOTE_TYPE = config.RemoteType.members()[0]
LOCAL = "/locker/Gaming/Roms"
REMOTE_PATH = "/Gaming/Roms"


# Everything up to the first flag: the subcommand and the paths it acts on
def positional_arguments(cmd):
    arguments = []
    for part in cmd[1:]:
        if str(part).startswith("-"):
            break
        arguments.append(part)
    return arguments


# Record what a wrapper would run instead of running it
def record(monkeypatch, returncode = 0, output = ""):
    from fakes import RecordingCommand

    return RecordingCommand(monkeypatch, returncode = returncode, output = output)
