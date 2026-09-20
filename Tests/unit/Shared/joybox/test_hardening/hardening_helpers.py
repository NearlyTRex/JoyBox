# A server that answers the hardening checks.
#
# Stands in for a connection to a real host: it holds the output each command
# should produce and the files that exist, so a check can be driven into any
# state without one.

# Local imports
from joybox import hardening


class FakeServer:

    def __init__(self):
        self.commands = {}
        self.codes = {}
        self.files = {}
        self.present = set()
        self.ran = []

    # Say a command exists and what it prints
    def install(self, name, output = "", code = 0):
        self.present.add(name)
        self.commands[name] = output
        self.codes[name] = code
        return self

    # Say a file exists and what it holds
    def add_file(self, path, contents):
        self.files[path] = contents
        return self

    ###########################################################
    # The connection interface the checks use
    ###########################################################

    def run_output(self, cmd, sudo = False):
        self.ran.append(list(cmd))
        if cmd[:2] == ["command", "-v"]:
            return cmd[2] if cmd[2] in self.present else ""
        return self.commands.get(cmd[0], "")

    def run_return_code(self, cmd, sudo = False):
        self.ran.append(list(cmd))
        if cmd[:2] == ["command", "-v"]:
            return 0 if cmd[2] in self.present else 1
        return self.codes.get(cmd[0], 0)

    def does_file_or_directory_exist(self, src):
        return src in self.files

    def read_file(self, src, sudo = False):
        return self.files.get(src)


# A server with everything hardened correctly
def hardened_server(domain = "joybox.test"):
    server = FakeServer()
    server.install("docker", "")
    server.install("ss", "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
                         "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n")
    server.install("ufw", "Status: active\n22/tcp ALLOW Anywhere\n")
    server.install("sshd", "passwordauthentication no\npermitrootlogin prohibit-password\n")
    server.install("fail2ban-client", "", code = 0)
    server.install("nginx", "limit_req_zone $binary_remote_addr zone=mylimit:10m rate=5r/s;\n"
                            "    limit_req zone=mylimit burst=20 nodelay;\n"
                            "server_tokens off;\n")
    server.install("curl", "503")
    server.commands["docker"] = "/var/lib/docker/165536.165536"
    server.add_file("/etc/docker/daemon.json",
                    '{"userns-remap": "default", "no-new-privileges": true}')
    server.add_file("/etc/apt/apt.conf.d/52-joybox-unattended",
                    'APT::Periodic::Unattended-Upgrade "1";\n'
                    'Unattended-Upgrade::Automatic-Reboot "true";\n')
    return server


# The outcomes of a set of results, keyed by message
def outcomes(results):
    return {result.message: result.outcome for result in results}


# Whether every result passed
def all_passed(results):
    return all(result.outcome == hardening.PASS for result in results)
