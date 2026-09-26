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

# Certificate mode assumed when an entry does not name one
DEFAULT_TLS_MODE = "letsencrypt"

# Where the server chosen for this run is recorded
SELECTION_SECTION = "UserData.General"
SELECTION_FIELD = "server_index"

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

        # What the server serves, and how its certificate is obtained
        self.domain_name = self.read("%s_domain_name" % prefix)
        self.domain_contact = self.read("%s_domain_contact" % prefix)
        self.tls_mode = (self.read("%s_tls_mode" % prefix) or DEFAULT_TLS_MODE).strip().lower()

        # The local test guest this entry points at, when it is one
        self.vm_name = self.read("%s_vm" % prefix)

        # The login guarding the admin pages
        self.htpasswd_user = self.read("%s_htpasswd_user" % prefix)
        self.htpasswd_password = self.read("%s_htpasswd_pass" % prefix)

        # The Storage Box mounted at /mnt/storage; without one, local storage stands in
        self.storage_user = self.read("%s_storage_user" % prefix)
        self.storage_host = self.read("%s_storage_host" % prefix)
        self.storage_password = self.read("%s_storage_pass" % prefix)

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

    def get_domain_name(self):
        return self.domain_name

    def get_domain_contact(self):
        return self.domain_contact

    def get_tls_mode(self):
        return self.tls_mode

    def get_vm_name(self):
        return self.vm_name

    def get_htpasswd_user(self):
        return self.htpasswd_user

    def get_htpasswd_password(self):
        return self.htpasswd_password

    def get_storage_user(self):
        return self.storage_user

    def get_storage_host(self):
        return self.storage_host

    def get_storage_password(self):
        return self.storage_password

    # Check if this entry is a local test guest rather than a real host
    def is_local_vm(self):
        return bool(self.vm_name)

    # Check if this entry mounts a Storage Box
    def has_storage_box(self):
        return bool(self.storage_user and self.storage_host)

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

# Record the server this run targets, for the installers that configure it
def select_server(server_index):
    settings.set_value(SELECTION_SECTION, SELECTION_FIELD, server_index)

# Get the server this run targets, or None when none was chosen
def get_selected_server():
    server_index = settings.get_value(
        SELECTION_SECTION, SELECTION_FIELD, default_value = None, throw_exception = False)
    if server_index is None:
        return None
    return ServerInfo(server_index)

# Get the domain of the server this run targets
def get_domain_name():
    server = get_selected_server()
    return server.get_domain_name() if server else None

# Get the certificate contact of the server this run targets
def get_domain_contact():
    server = get_selected_server()
    return server.get_domain_contact() if server else None

# Get the certificate mode of the server this run targets
def get_tls_mode():
    server = get_selected_server()
    return server.get_tls_mode() if server else DEFAULT_TLS_MODE

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
