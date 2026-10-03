# Imports
from joybox import serverinfo
from joybox.bootstrap import provision
from fakes import RecordingConnection

SECTION = serverinfo.SECTION


###########################################################
# Shared values for the provisioning suite
#
# One command takes a server entry from nothing to hardened. The same stages
# run against a real host and a test guest, so the rules pinned here are what
# stands between a rehearsal and a locked-out server: the account is proven
# before root is closed, secrets never sit readable, and a rerun resumes.
###########################################################

def server():
    return serverinfo.ServerInfo(1)


class World:
    # Which logins the target accepts, changing as stages run
    def __init__(self, logins, tweak = None):
        self.logins = dict(logins)
        self.connections = []
        self.tweak = tweak

    def connect(self, username):
        world = self

        class Login(RecordingConnection):
            def try_setup(self, timeout = 15):
                return world.logins.get(username, False)

            def teardown(self):
                pass

        connection = Login()
        connection.username = username
        if self.tweak:
            self.tweak(connection)
        self.connections.append(connection)
        return connection

    def commands_as(self, username):
        return [cmd for connection in self.connections if connection.username == username
                for cmd in connection.commands]

    def calls_as(self, username):
        return [call for connection in self.connections if connection.username == username
                for call in connection.calls]


def build(world, stages = None, entry_server = None):
    provisioner = provision.Provisioner(
        server = entry_server or server(),
        stages = stages,
        wait_for_port = lambda host, port: True)
    provisioner.build_connection = world.connect
    return provisioner


def flat(cmd):
    return " ".join(cmd)


def fail_on(**codes):
    def tweak(connection):
        connection.return_codes = dict(codes)
    return tweak


def always_logs_in(provisioner):
    provisioner.can_log_in = lambda username: True
    return provisioner
