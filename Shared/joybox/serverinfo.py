# A configured server entry.
#
# The connection details for one of the servers under [UserData.Servers],
# read by index. Kept here rather than in the caller so bootstrap.py and the
# tools that check a server agree on what an entry contains.

# Local imports
import joybox.settings as settings

# Section holding the server entries
SECTION = "UserData.Servers"

# Port assumed when an entry does not name one
DEFAULT_PORT = 22

# Server info
class ServerInfo:

    # Constructor
    def __init__(self, server_index = 0):
        self.server_index = server_index
        prefix = "server_%s" % server_index
        self.host = self.read("%s_host" % prefix)
        self.port = settings.get_integer_value(
            SECTION, "%s_port" % prefix, default_value = DEFAULT_PORT,
            throw_exception = False) or DEFAULT_PORT
        self.user = self.read("%s_user" % prefix)
        self.password = self.read("%s_pass" % prefix)

        # Optional: entries written before key auth existed have no such key
        self.key_filepath = self.read("%s_key_filepath" % prefix)

    # Read one field of this entry
    def read(self, field):
        return settings.get_value(
            SECTION, field, default_value = "", throw_exception = False) or None

    def get_index(self):
        return self.server_index

    def get_host(self):
        return self.host

    def get_port(self):
        return self.port

    def get_user(self):
        return self.user

    def get_password(self):
        return self.password

    def get_key_filepath(self):
        return self.key_filepath

    # Check if this entry names a server at all
    def is_configured(self):
        return bool(self.host)

    # The keyword arguments a ConnectionSSH takes
    def get_connection_options(self):
        return {
            "ssh_host": self.host,
            "ssh_port": self.port,
            "ssh_user": self.user,
            "ssh_password": self.password,
            "ssh_key_filepath": self.key_filepath,
        }

# Read the domain the server stack is configured for
def get_domain_name():
    return settings.get_value(
        SECTION, "domain_name", default_value = "", throw_exception = False) or None

# Build a connection to a server entry, or to this machine when none is named
def get_connection(server_index = None, flags = None, options = None):
    from joybox.connection import ConnectionLocal, ConnectionSSH
    from joybox import runoptions
    if flags is None:
        flags = runoptions.RunFlags()
    if options is None:
        options = runoptions.RunOptions()
    if server_index is None:
        return ConnectionLocal(flags = flags, options = options)
    server = ServerInfo(server_index)
    if not server.is_configured():
        return None
    return ConnectionSSH(flags = flags, options = options,
                         **server.get_connection_options())
