# A disposable machine for running the shell under Bootstrap/.
#
# The scripts are written for a fresh server: they run as root and write to
# /etc, /var, /home and the rest. Each run here happens in a user namespace
# where the caller is root, with no network, and with those directories
# replaced by empty ones the test owns, so whatever a script writes lands in
# the sandbox and can be read back.
#
# PATH holds only recording stubs and an allowlist of harmless real tools, so
# a command nobody planned for fails with "command not found" rather than
# running for real. Every run is traced for shell coverage.

# Imports
import os
import shutil
import subprocess
import uuid

# Third-party imports
import pytest

# Directories a script sees as empty and its own, in the order they are hidden
HIDDEN_DIRS = ["/home", "/root", "/var", "/usr/local", "/opt", "/mnt", "/srv", "/etc", "/tmp"]

# Where the directories that must stay reachable are staged while the rest are hidden
STAGING_DIR = "/media"

# Real tools a script may run: they only read and write files it could anyway
ALLOWED_TOOLS = [
    "bash", "sh", "env", "cat", "cp", "mv", "rm", "ln", "mkdir", "rmdir", "chmod", "ls",
    "grep", "sed", "awk", "sort", "uniq", "head", "tail", "tr", "cut", "wc", "basename",
    "dirname", "readlink", "realpath", "mktemp", "touch", "stat", "find", "xargs", "tee",
    "date", "sleep", "id", "whoami", "getent", "seq", "true", "false", "diff", "cmp",
    "install", "sha256sum", "base64", "printf", "test", "[", "expr", "comm", "paste",
    "tac", "yes", "timeout", "openssl", "uname", "nproc", "od", "fold",
]

# Commands every sandbox stubs: they change the machine, reach the network or
# need privileges the namespace does not have
DEFAULT_STUBS = [
    "systemctl", "service", "apt-get", "apt", "dpkg", "dpkg-query", "ufw", "netplan",
    "nginx", "docker", "certbot", "sshd", "fail2ban-client", "useradd", "usermod",
    "userdel", "adduser", "groupadd", "chown", "chgrp", "chpasswd", "passwd", "visudo",
    "curl", "wget", "git", "python3", "pip", "pip3", "mount", "umount", "mountpoint",
    "sshfs", "fusermount", "su", "keytool", "wp", "htpasswd", "hostnamectl",
    "timedatectl", "reboot", "shutdown", "crontab", "ssh", "ssh-keygen", "loginctl",
    "update-alternatives", "snap", "flatpak", "iptables", "mkcert",
]

# sudo runs its command directly: the sandbox is already root
SUDO_STUB = """while [ $# -gt 0 ]; do
    case "$1" in
        -u|-g|-C|-D|-h|-p|-r|-t|-U) shift 2 ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
exec "$@"
"""

# Accounts every sandbox starts with
BASE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
BASE_GROUP = (
    "root:x:0:\n"
    "daemon:x:1:\n"
    "adm:x:4:\n"
    "sudo:x:27:\n"
    "www-data:x:33:\n"
    "users:x:100:\n"
    "docker:x:999:\n"
    "nogroup:x:65534:\n")

# What of the real /etc a program needs to start at all
HOST_ETC_FILES = ["ld.so.cache", "ld.so.conf", "localtime", "os-release", "ssl/openssl.cnf"]
HOST_ETC_DIRS = ["ld.so.conf.d", "alternatives"]

_namespace_support = {}


# Check once whether this machine lets an unprivileged user build the sandbox
def check_namespace_support():
    if "error" not in _namespace_support:
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--net", "true"],
            capture_output = True, text = True, check = False)
        _namespace_support["error"] = None if result.returncode == 0 else (result.stderr.strip() or "unshare failed")
    return _namespace_support["error"]


class ShellSandbox:

    def __init__(self, work_dir, repo_root, trace_dir, hook_file):
        self.work_dir = str(work_dir)
        self.repo_root = repo_root
        self.trace_dir = trace_dir
        self.hook_file = hook_file
        self.root_dir = os.path.join(self.work_dir, "root")
        self.stub_dir = os.path.join(self.work_dir, "stubs")
        self.tool_dir = os.path.join(self.work_dir, "tools")
        self.calls_log = os.path.join(self.work_dir, "calls.log")
        self.build_root()
        self.build_tools()
        for name in DEFAULT_STUBS:
            self.stub(name)
        self.stub("sudo", script = SUDO_STUB)

    ###########################################################
    # Building
    ###########################################################

    def build_root(self):
        for directory in HIDDEN_DIRS:
            os.makedirs(self.host_path(directory), exist_ok = True)
        for directory in ["/var/lib", "/var/log", "/var/tmp", "/var/www", "/usr/local/bin", "/etc/systemd/system"]:
            os.makedirs(self.host_path(directory), exist_ok = True)
        os.chmod(self.host_path("/tmp"), 0o1777)
        etc_dir = self.host_path("/etc")
        for name in HOST_ETC_FILES:
            source = os.path.join("/etc", name)
            if os.path.lexists(source):
                os.makedirs(os.path.dirname(os.path.join(etc_dir, name)), exist_ok = True)
                shutil.copy2(source, os.path.join(etc_dir, name), follow_symlinks = False)
        for name in HOST_ETC_DIRS:
            source = os.path.join("/etc", name)
            if os.path.isdir(source):
                shutil.copytree(source, os.path.join(etc_dir, name), symlinks = True)
        self.write("/etc/passwd", BASE_PASSWD)
        self.write("/etc/group", BASE_GROUP)
        self.write("/etc/nsswitch.conf", "passwd: files\ngroup: files\nhosts: files\n")
        self.write("/etc/hosts", "127.0.0.1 localhost\n")
        os.symlink("/proc/self/mounts", os.path.join(etc_dir, "mtab"))

    def build_tools(self):
        os.makedirs(self.stub_dir)
        os.makedirs(self.tool_dir)
        for name in ALLOWED_TOOLS:
            found = shutil.which(name)
            if found:
                os.symlink(os.path.realpath(found), os.path.join(self.tool_dir, name))

    ###########################################################
    # Arranging
    ###########################################################

    # Where a path inside the sandbox lives on this machine
    def host_path(self, path):
        return os.path.join(self.root_dir, path.lstrip("/"))

    def write(self, path, contents, mode = None):
        target = self.host_path(path)
        os.makedirs(os.path.dirname(target), exist_ok = True)
        with open(target, "w") as handle:
            handle.write(contents)
        if mode is not None:
            os.chmod(target, mode)
        return target

    def read(self, path):
        with open(self.host_path(path)) as handle:
            return handle.read()

    def exists(self, path):
        return os.path.lexists(self.host_path(path))

    def add_user(self, name, uid = 1000, groups = ()):
        with open(self.host_path("/etc/passwd"), "a") as passwd:
            passwd.write("%s:x:%d:%d::/home/%s:/bin/bash\n" % (name, uid, uid, name))
        with open(self.host_path("/etc/group"), "a") as group:
            group.write("%s:x:%d:\n" % (name, uid))
        if groups:
            lines = self.read("/etc/group").splitlines()
            for index, line in enumerate(lines):
                fields = line.split(":")
                if fields[0] in groups:
                    members = [member for member in fields[3].split(",") if member] + [name]
                    lines[index] = ":".join(fields[:3] + [",".join(members)])
            self.write("/etc/group", "\n".join(lines) + "\n")
        os.makedirs(self.host_path("/home/%s" % name), exist_ok = True)

    # Replace a command with one that records its arguments, prints stdout and
    # exits with code, or runs script after recording when one is given
    def stub(self, name, stdout = "", code = 0, script = None):
        stdout_file = os.path.join(self.stub_dir, ".%s.stdout" % name)
        with open(stdout_file, "w") as handle:
            handle.write(stdout)
        body = script if script is not None else 'cat "%s"\nexit %d\n' % (stdout_file, code)
        path = os.path.join(self.stub_dir, name)
        with open(path, "w") as handle:
            handle.write("#!/bin/bash\n")
            handle.write("{ printf '%%s\\0' \"${0##*/}\" \"$@\"; printf '\\036'; } >> \"%s\"\n" % self.calls_log)
            handle.write(body)
        os.chmod(path, 0o755)

    ###########################################################
    # Running
    ###########################################################

    def build_launcher(self, command, env):
        keep = [self.work_dir, self.repo_root, self.trace_dir, os.path.dirname(self.hook_file)]
        lines = ["set -e", "mount -t tmpfs tmpfs %s" % STAGING_DIR]
        for index, path in enumerate(keep):
            lines.append("mkdir -p %s/keep%d && mount --bind %s %s/keep%d" % (
                STAGING_DIR, index, quote(path), STAGING_DIR, index))
        staged_root = "%s/keep0/root" % STAGING_DIR
        for directory in HIDDEN_DIRS:
            lines.append("mount --bind %s%s %s" % (staged_root, directory, directory))
        for index, path in enumerate(keep):
            lines.append("mkdir -p %s && mount --bind %s/keep%d %s" % (
                quote(path), STAGING_DIR, index, quote(path)))
        lines.append("cd /root")
        assignments = " ".join("%s=%s" % (key, quote(value)) for key, value in env.items())
        lines.append("exec env -i %s %s" % (assignments, " ".join(quote(part) for part in command)))
        return "\n".join(lines) + "\n"

    # Run a script from the repository, by its path relative to the root
    def run(self, script, *args, env = None, input = None, timeout = 60):
        return self.run_command(["bash", os.path.join(self.repo_root, script)] + [str(arg) for arg in args],
                                env = env, input = input, timeout = timeout)

    # Run a command line inside the sandbox
    def run_command(self, command, env = None, input = None, timeout = 60):
        error = check_namespace_support()
        if error:
            pytest.skip("user namespaces are unavailable here: %s" % error)
        full_env = {
            "PATH": "%s:%s" % (self.stub_dir, self.tool_dir),
            "HOME": "/root",
            "USER": "root",
            "LANG": "C.UTF-8",
            "TERM": "dumb",
            "BASH_ENV": self.hook_file,
            "JOYBOX_SHELL_TRACE": os.path.join(self.trace_dir, "%s.trace" % uuid.uuid4().hex),
        }
        full_env.update(env or {})
        launcher = os.path.join(self.work_dir, "launcher.sh")
        with open(launcher, "w") as handle:
            handle.write(self.build_launcher(command, full_env))
        return subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--net", "--fork", "/bin/bash", launcher],
            input = input, capture_output = True, text = True, timeout = timeout, check = False,
            env = {"PATH": "/usr/bin:/bin"})

    ###########################################################
    # Reading back
    ###########################################################

    # Every stubbed command run, as argument lists, optionally of one command
    def calls(self, name = None):
        if not os.path.exists(self.calls_log):
            return []
        with open(self.calls_log, "rb") as handle:
            records = handle.read().split(b"\x1e")
        found = []
        for record in records:
            if not record:
                continue
            fields = [field.decode(errors = "replace") for field in record.split(b"\0")[:-1]]
            if name is None or fields[0] == name:
                found.append(fields if name is None else fields[1:])
        return found

    # Whether a stubbed command ran with these arguments, in order, among its own
    def ran(self, name, *args):
        wanted = list(args)
        return any(call[:len(wanted)] == wanted for call in self.calls(name))


def quote(value):
    import shlex
    return shlex.quote(str(value))
