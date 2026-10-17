# Known SSH hosts
#
# The keys of the servers JoyBox reaches over SSH, kept in ssh's own
# known_hosts so ssh, paramiko and rclone all check against the same record. A
# server is trusted the first time it is seen and held to that key after, as
# ssh's StrictHostKeyChecking=accept-new does: a key that later changes is
# refused by whichever of them connects.

# Imports
import os

# Local imports
import joybox.command as command
import joybox.fileops as fileops
import joybox.logger as logger
import joybox.paths as paths

# How long to wait for a server to show its key
SCAN_TIMEOUT_SECONDS = 10

# Hosts already checked this run, so a host used by many commands is looked up once
_checked = set()

# Get where the keys of servers already seen are kept
def get_known_hosts_path():
    return os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")

# Get the name a host is recorded under, which carries the port unless it is ssh's own
def get_host_entry(host, port = 22):
    return host if int(port) == 22 else "[%s]:%s" % (host, port)

# Check whether a host's key is already recorded
def is_host_known(host, port = 22):
    known_hosts_path = get_known_hosts_path()
    if not paths.does_path_exist(known_hosts_path):
        return False
    output = command.run_output_command(["ssh-keygen", "-F", get_host_entry(host, port), "-f", known_hosts_path])
    return bool((output or "").strip())

# Record a host's key the first time it is seen
def remember_host(host, port = 22, verbose = False, pretend_run = False, exit_on_failure = False):
    entry = get_host_entry(host, port)
    if entry in _checked or is_host_known(host, port):
        _checked.add(entry)
        return True

    # Ask the server for its keys
    if pretend_run:
        logger.log_info("Would trust the host key of %s, seen for the first time" % entry)
        return True
    output = command.run_output_command(
        ["ssh-keyscan", "-T", str(SCAN_TIMEOUT_SECONDS), "-p", str(port), host],
        verbose = verbose)
    lines = [line for line in (output or "").splitlines() if line.strip() and not line.startswith("#")]
    if not lines:
        logger.log_error("Unable to read the host key of %s; it is not trusted, so connecting to it will fail" % entry)
        return False

    # Write them into known_hosts, making ~/.ssh private when it is new
    known_hosts_dir = os.path.dirname(get_known_hosts_path())
    if not paths.does_path_exist(known_hosts_dir):
        fileops.make_directory(known_hosts_dir)
        fileops.chmod_file_or_directory(known_hosts_dir, "700")
    if not fileops.touch_file(
        get_known_hosts_path(),
        contents = "\n".join(lines) + "\n",
        contents_mode = "a",
        verbose = verbose,
        exit_on_failure = exit_on_failure):
        logger.log_error("Unable to record the host key of %s in %s" % (entry, get_known_hosts_path()))
        return False
    _checked.add(entry)
    logger.log_info("Trusting the host key of %s, seen for the first time" % entry)
    return True
