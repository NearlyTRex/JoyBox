# Provisioning a server entry end to end.
#
# The steps of a fresh server, in order, driven from the workstation: the local
# test guest when the entry is one, the account on first contact as root, the
# day-0 scripts, the deploy, the sshd hardening and the verification. Each stage
# checks what is already done, so a second run resumes rather than repeats.
#
# Each stage opens the connection it needs, as root or as the account, and
# closes it before the next, so no stage leaves a session behind.

# Imports
import contextlib
import importlib.util
import os
import shlex
import socket
import time
import uuid

# Local imports
from joybox import bootstrap
from joybox.bootstrap import constants
from joybox.bootstrap import runner
from joybox import command
from joybox import commandbase
from joybox import paths
from joybox import hardening
from joybox import hostsfile
from joybox import logger
from joybox import runtime
from joybox import serverinfo
from joybox import terminal
from joybox import virtualmachine
from joybox import runoptions
from joybox.connection import ConnectionSSH

# Stages, in the order they run
STAGES = ["vm", "login", "day0", "deploy", "sshd", "verify"]

# Snapshots taken on a test guest
SNAPSHOT_FRESH = "provision-fresh"
SNAPSHOT_PRE_SSHD = "pre-sshd"

# How long a new guest may take to answer on ssh
BOOT_TIMEOUT_SECONDS = 600
BOOT_POLL_SECONDS = 5

###########################################################
# Commands run on the target
###########################################################

# Create the account on first contact, with root's keys, the way the setup
# guide does it by hand
def build_create_user_command(username):
    user = shlex.quote(username)
    script = "\n".join([
        "set -e",
        "id -u %s >/dev/null 2>&1 || adduser --disabled-password --gecos '' %s" % (user, user),
        "usermod -aG sudo %s" % user,
        "install -d -m 700 -o %s -g %s /home/%s/.ssh" % (user, user, user),
        "install -m 600 -o %s -g %s /root/.ssh/authorized_keys /home/%s/.ssh/authorized_keys" % (user, user, user),
    ])
    return ["bash", "-c", script]

# Set a password from a file, removing the file whatever happens
def build_set_password_command(secret_path):
    path = shlex.quote(secret_path)
    return ["bash", "-c", "chpasswd < %s; status=$?; rm -f %s; exit $status" % (path, path)]

# The day-0 scripts for an entry, in order, as (label, command) pairs
def build_day0_commands(server, scripts_dir, secret_paths = None):
    secret_paths = secret_paths or {}
    user = server.get_user()
    def script(name):
        return "%s/%s" % (scripts_dir, name)
    commands = [
        ("sudoers", [script("init_sudoers.sh"), "--action", "setup", "--user", user]),
        ("docker", [script("init_docker.sh"), "--user", user]),
        ("nginx", [script("init_nginx.sh")]),
        ("htpasswd", [
            script("init_htpasswd.sh"), "--action", "setup",
            "--user", server.get_htpasswd_user() or user,
            "--password-file", secret_paths.get("htpasswd", "")]),
    ]
    if server.has_storage_box():
        commands.append(("storage", [
            script("init_storagebox.sh"), "--user", user,
            "--storage-user", server.get_storage_user(),
            "--storage-host", server.get_storage_host(),
            "--password-file", secret_paths.get("storage", "")]))
    else:
        commands.append(("storage", [script("init_localstorage.sh"), "--user", user]))
    return commands

# Find what an entry is missing before anything touches the target
def get_missing_settings(server, stages):
    prefix = "server_%s" % server.get_index()
    missing = []
    for field, value in [("host", server.get_host()), ("user", server.get_user()),
                         ("key_filepath", server.get_key_filepath())]:
        if not value:
            missing.append("%s_%s" % (prefix, field))
    if "day0" in stages:
        if not server.get_htpasswd_password():
            missing.append("%s_htpasswd_pass" % prefix)
        if server.has_storage_box() and not server.get_storage_password():
            missing.append("%s_storage_pass" % prefix)
    if ("deploy" in stages or "verify" in stages) and not server.get_domain_name():
        missing.append("%s_domain_name" % prefix)
    return missing

###########################################################
# Workstation checks
###########################################################

# Check the port answers, for a guest still booting
def is_port_open(host, port, timeout = 3):
    try:
        with socket.create_connection((host, port), timeout = timeout):
            return True
    except OSError:
        return False

# Check the local certificate authority is trusted here, for mkcert entries
def is_mkcert_ready():
    if not paths.is_runnable_command("mkcert"):
        return False
    output = command.run_output_command(
        cmd = ["mkcert", "-CAROOT"],
        options = commandbase.create_command_options(suppress_output = True))
    if isinstance(output, bytes):
        output = output.decode()
    ca_root = (output or "").strip()
    return bool(ca_root) and os.path.isfile(os.path.join(ca_root, "rootCA.pem"))

###########################################################
# Provisioner
###########################################################

# Runs the provisioning stages for one server entry, from the workstation over ssh
class Provisioner:
    def __init__(
        self,
        server,
        components = None,
        stages = None,
        flags = None,
        wait_for_port = is_port_open):
        self.server = server
        self.components = components
        self.stages = [stage for stage in STAGES if stage in (stages or STAGES)]
        self.flags = flags if flags is not None else runoptions.RunFlags()
        self.wait_for_port = wait_for_port
        self.verify_failures = 0

    ###########################################################
    # Connections
    ###########################################################

    # An unopened ssh connection to the server as the given user, that does not exit on failure
    def build_connection(self, username):
        flags = self.flags.copy()
        flags.set(exit_on_failure = False)
        return ConnectionSSH(
            ssh_host = self.server.get_host(),
            ssh_port = self.server.get_port(),
            ssh_user = username,
            ssh_key_filepath = self.server.get_key_filepath(),
            flags = flags,
            options = runoptions.RunOptions())

    # Open a login for the length of a block; None when it is refused
    @contextlib.contextmanager
    def session(self, username):
        connection = self.build_connection(username)
        if not connection.try_setup():
            yield None
            return
        try:
            yield connection
        finally:
            connection.teardown()

    # Whether user can login
    def can_log_in(self, username):
        with self.session(username) as connection:
            return connection is not None

    # Keep trying a login until a deadline, for a guest still finishing first boot
    def wait_for_login(self, username, deadline):
        while not self.can_log_in(username):
            if time.monotonic() > deadline:
                return False
            time.sleep(BOOT_POLL_SECONDS)
        return True

    ###########################################################
    # Target helpers
    ###########################################################

    # Write a secret readable only by its owner; the file is created with that
    # mode before the secret goes in, so it is never readable by anyone else
    def put_secret(self, connection, path, contents):
        if connection.run_return_code(["install", "-m", "600", "/dev/null", path]) != 0:
            return False
        return connection.write_file(path, contents)

    # Run a command on the target, logging it by label; False on a nonzero exit
    def run_step(self, connection, label, cmd):
        logger.log_info("Running %s" % label)
        code = connection.run_blocking(cmd)
        if code != 0:
            logger.log_error("%s failed with exit code %s" % (label, code))
            return False
        return True

    # Ship the day-0 scripts from this checkout
    def push_day0_scripts(self, connection):
        remote_dir = "/root/joybox-day0-%s" % uuid.uuid4().hex[:8]
        if connection.run_return_code(["install", "-d", "-m", "700", remote_dir]) != 0:
            logger.log_error("Unable to create %s on the server" % remote_dir)
            return None
        for name in ["scripts", "managers"]:
            if not connection.transfer_files(
                os.path.join(bootstrap.get_data_dir(), name), "%s/%s" % (remote_dir, name)):
                logger.log_error("Unable to copy %s to the server" % name)
                return None
        connection.run_return_code(["bash", "-c", "chmod +x %s/scripts/*.sh %s/managers/*.sh" % (
            shlex.quote(remote_dir), shlex.quote(remote_dir))])
        return remote_dir

    # Remove day-0 scripts
    def remove_day0_scripts(self, connection, remote_dir):
        if remote_dir:
            connection.run_return_code(["rm", "-rf", remote_dir])

    ###########################################################
    # Stages
    ###########################################################

    # The local test guest: built when absent, started when stopped, reachable
    # at the entry's address, and the domain pointed at it on this machine
    def run_vm(self):
        if not self.server.is_local_vm():
            logger.log_info("Not a test guest; skipping")
            return True
        name = self.server.get_vm_name()
        address = self.server.get_host()
        verbose = self.flags.verbose

        # Build or start it
        created = not virtualmachine.does_vm_exist(name, verbose = verbose)
        if created:
            if not self._create_vm(name, address, verbose):
                return False
        elif not self._start_existing_vm(name, address, verbose):
            return False

        # Wait for it to answer
        logger.log_info("Waiting for %s to answer on ssh" % address)
        deadline = time.monotonic() + BOOT_TIMEOUT_SECONDS
        if not self.wait_for_ssh(address, deadline):
            return False

        # A new guest finishes first boot before anything else runs, and that
        # state is kept to come back to
        if created and not self._finish_first_boot(name, deadline, verbose):
            return False

        # Point the domain at it here
        domain = self.server.get_domain_name()
        if domain:
            hostsfile.set_entries(address = address, domain = domain, sudo = True, verbose = True)
        return True

    # Reserve the guest's fixed address and start it; False for a guest built before fixed addresses
    def _start_existing_vm(self, name, address, verbose):
        actual_mac = virtualmachine.get_vm_interface_mac(name, verbose = verbose)
        if actual_mac and actual_mac != virtualmachine.get_vm_mac(name):
            logger.log_error(
                "%s was built before fixed addresses and will not come up at %s; "
                "remove it with 'testvm destroy' and run this again" % (name, address))
            return False
        if not virtualmachine.reserve_address(name, address, verbose = verbose):
            return False
        virtualmachine.start_vm(name, verbose = verbose)
        return True

    # Build the guest at its address, authorizing the entry's public key when one sits beside it
    def _create_vm(self, name, address, verbose):
        key_file = self.server.get_key_filepath()
        public_key = key_file + ".pub" if key_file and os.path.isfile(key_file + ".pub") else None
        return virtualmachine.create_vm(
            vm_name = name, ssh_key_file = public_key, address = address,
            verbose = verbose, exit_on_failure = False)

    # Poll the ssh port until it answers; False once the deadline passes
    def wait_for_ssh(self, address, deadline):
        while not self.wait_for_port(address, self.server.get_port()):
            if time.monotonic() > deadline:
                logger.log_error("%s did not answer within %d seconds" % (address, BOOT_TIMEOUT_SECONDS))
                return False
            time.sleep(BOOT_POLL_SECONDS)
        return True

    # Wait out cloud-init as root, then snapshot the fresh guest. sshd answers
    # before cloud-init has written root's key, so the first logins can be refused.
    def _finish_first_boot(self, name, deadline, verbose):
        if not self.wait_for_login("root", deadline):
            logger.log_error("root cannot log in to the new guest with %s" % self.server.get_key_filepath())
            return False
        with self.session("root") as connection:
            if not connection:
                logger.log_error("root cannot log in to the new guest with %s" % self.server.get_key_filepath())
                return False
            connection.run_blocking(["cloud-init", "status", "--wait"])
        virtualmachine.snapshot_vm(name, SNAPSHOT_FRESH, verbose = verbose)
        return True

    # The account, created on first contact as root
    def run_login(self):
        user = self.server.get_user()
        if self.can_log_in(user):
            logger.log_info("%s can log in" % user)
            return True
        with self.session("root") as connection:
            if not connection:
                logger.log_error("Neither %s nor root can log in with %s" % (user, self.server.get_key_filepath()))
                return False
            if not self._create_account(connection, user):
                return False
        if not self.can_log_in(user):
            logger.log_error("%s still cannot log in after being created" % user)
            return False
        return True

    # Create the account over a root connection and set its password when one
    # is configured
    def _create_account(self, connection, user):
        if not self.run_step(connection, "account creation", build_create_user_command(user)):
            return False
        password = self.server.get_password()
        if not password:
            return True
        secret_path = "/root/.joybox-account-%s" % uuid.uuid4().hex[:8]
        if not self.put_secret(connection, secret_path, "%s:%s\n" % (user, password)):
            return False
        return self.run_step(connection, "account password", build_set_password_command(secret_path))

    # The day-0 scripts, run as root; once hardening has closed root login they
    # are done and are skipped
    def run_day0(self):
        with self.session("root") as connection:
            if not connection:
                if self.can_log_in(self.server.get_user()):
                    logger.log_info("root login is closed, so the server is hardened; skipping day-0")
                    return True
                logger.log_error("root cannot log in to run the day-0 scripts")
                return False
            remote_dir = self.push_day0_scripts(connection)
            if not remote_dir:
                return False
            secret_paths = {"htpasswd": "%s/htpasswd.secret" % remote_dir}
            try:
                if not self._run_day0_steps(connection, remote_dir, secret_paths):
                    return False
            finally:
                if "storage" in secret_paths:
                    connection.run_return_code(["rm", "-f", secret_paths["storage"]])
                self.remove_day0_scripts(connection, remote_dir)
        return True

    # Stage the secrets, recording each path in secret_paths, then run every day-0
    # step; False at the first failure
    def _run_day0_steps(self, connection, remote_dir, secret_paths):
        if not self.put_secret(connection, secret_paths["htpasswd"], self.server.get_htpasswd_password()):
            return False

        # The Storage Box password is read by the account rather than
        # root, so it cannot sit in root's directory; the script hands
        # it to the account, and it is removed afterwards
        if self.server.has_storage_box():
            secret_paths["storage"] = "/run/joybox-storage-%s" % uuid.uuid4().hex[:8]
            if not self.put_secret(connection, secret_paths["storage"], self.server.get_storage_password()):
                return False
        for label, cmd in build_day0_commands(self.server, remote_dir + "/scripts", secret_paths):
            if not self.run_step(connection, label, cmd):
                return False
        return True

    # The components, deployed as the account, the same way bootstrap.py does
    def run_deploy(self):
        if self.server.get_tls_mode() == "mkcert" and not is_mkcert_ready():
            if not paths.is_runnable_command("mkcert"):
                logger.log_error(
                    "mkcert is not installed; run: python3 bootstrap.py -a setup "
                    "-t local_ubuntu --components aptget")
                return False
            logger.log_info("Trusting mkcert's local certificate authority on this machine")
            code = command.run_interactive_command(cmd = ["mkcert", "-install"])
            if code != 0:
                return False
        environment = runner.create_environment(
            environment_type = constants.EnvironmentType.REMOTE_UBUNTU,
            server_index = self.server.get_index(),
            flags = self.flags)
        if not environment:
            return False
        try:
            if self.components:
                environment.set_components_to_process(self.components)
            return environment.setup()
        finally:
            environment.disconnect()

    # The sshd hardening, which closes root and password login. The account's
    # key login is proven first and again after, and a test guest is
    # snapshotted so a lockout costs a revert rather than a rebuild.
    def run_sshd(self):
        user = self.server.get_user()
        if not self.can_log_in(user):
            logger.log_error("%s cannot log in with its key; refusing to disable the other ways in" % user)
            return False
        if not self.can_log_in("root"):
            logger.log_info("root login is already closed; skipping")
            return True
        name = self.server.get_vm_name()
        if self.server.is_local_vm():
            virtualmachine.delete_snapshot(name, SNAPSHOT_PRE_SSHD, verbose = self.flags.verbose)
            virtualmachine.snapshot_vm(name, SNAPSHOT_PRE_SSHD, verbose = self.flags.verbose)
        if not self._run_sshd_hardening(user):
            return False
        return self._check_sshd_hardened(user, name)

    # Push the day-0 scripts as root and run the sshd hardening script
    def _run_sshd_hardening(self, user):
        with self.session("root") as connection:
            if not connection:
                return False
            remote_dir = self.push_day0_scripts(connection)
            if not remote_dir:
                return False
            try:
                return self.run_step(connection, "sshd hardening", [
                    remote_dir + "/scripts/init_sshd.sh", "--user", user])
            finally:
                self.remove_day0_scripts(connection, remote_dir)

    # After hardening the account must still log in and root must not; a test
    # guest that lost the account's login is reverted to its pre-sshd snapshot
    def _check_sshd_hardened(self, user, name):
        if not self.can_log_in(user):
            if self.server.is_local_vm():
                logger.log_error("%s lost its key login; reverting to %s" % (user, SNAPSHOT_PRE_SSHD))
                virtualmachine.revert_vm(name, SNAPSHOT_PRE_SSHD, verbose = self.flags.verbose)
            else:
                logger.log_error("%s lost its key login; recover through the provider's console" % user)
            return False
        if self.can_log_in("root"):
            logger.log_error("root can still log in after the sshd hardening")
            return False
        return True

    # The hardening checks, as the account, the way verify_server runs them
    def run_verify(self):
        with self.session(self.server.get_user()) as connection:
            if not connection:
                logger.log_error("%s cannot log in to verify" % self.server.get_user())
                return False
            results = hardening.verify_hardening(
                connection = connection,
                domain = self.server.get_domain_name(),
                public_ports = runner.get_public_ports(self.server.get_index()))
        terminal.write(hardening.format_results(results) + "\n")
        self.verify_failures = hardening.count_failures(results)
        if self.verify_failures:
            logger.log_error("%d check(s) failed" % self.verify_failures)
            return False
        logger.log_info("All checks passed")
        return True

    ###########################################################
    # Running
    ###########################################################

    # Describe environment
    def describe(self):
        lines = ["Provisioning server %s (%s@%s)" % (
            self.server.get_index(), self.server.get_user(), self.server.get_host())]
        if self.server.is_local_vm():
            lines.append("  test guest: %s" % self.server.get_vm_name())
        lines.append("  stages: %s" % ", ".join(self.stages))
        lines.append("  components: %s" % (", ".join(self.components) if self.components else "all"))
        lines.append("  storage: %s" % (
            "Storage Box %s" % self.server.get_storage_host() if self.server.has_storage_box() else "local"))
        return lines

    # Run each stage in turn, stopping at the first that fails
    def run(self):
        for stage in self.stages:
            logger.log_info("== %s ==" % stage)
            if not getattr(self, "run_%s" % stage)():
                logger.log_error("Stage '%s' failed; fix it and run again to resume" % stage)
                return False
        return True

###########################################################
# Provisioning and verifying a server entry
###########################################################

# The server entry and stages a provisioning run uses, every stage when none are given,
# after checking its inputs before anything is touched: no unexpected arguments, a server
# given and configured, known stages, the settings they need and paramiko; quits on the first failure
def check_provision_inputs(server_index, stages = None, unknown = None):
    if unknown:
        logger.log_error("Unexpected arguments: %s" % " ".join(unknown), quit_program = True)
    if server_index is None:
        logger.log_error("--server is required", quit_program = True)
    stages = stages or STAGES
    unknown_stages = [stage for stage in stages if stage not in STAGES]
    if unknown_stages:
        logger.log_error("Unknown stage(s): %s" % ", ".join(unknown_stages), quit_program = True)
    server = serverinfo.ServerInfo(server_index)
    if not server.is_configured():
        logger.log_error("No host configured for server %s" % server_index, quit_program = True)
    missing = get_missing_settings(server, stages)
    if missing:
        logger.log_error("Set these in ~/JoyBox.ini first: %s" % ", ".join(missing), quit_program = True)
    if importlib.util.find_spec("paramiko") is None:
        logger.log_error(
            "paramiko is not installed; run: python3 bootstrap.py -a setup "
            "-t local_ubuntu --components python", quit_program = True)
    return server, stages

# Log the plan for provisioning a server entry, then, unless a pretend run, select the
# server and run the stages; on failure quits with the failed check count when the last
# stage is a failing verify, else with 1
def provision_server(
    server_index,
    server,
    stages,
    components = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    provisioner = Provisioner(
        server = server,
        components = components,
        stages = stages,
        flags = runoptions.RunFlags(
            verbose = verbose,
            pretend_run = False,
            exit_on_failure = exit_on_failure))
    for line in provisioner.describe():
        logger.log_info(line)
    if pretend_run:
        return

    # Run
    serverinfo.select_server(server_index)
    if provisioner.run():
        logger.log_info("Server %s is provisioned" % server_index)
        return
    if provisioner.verify_failures and provisioner.stages[-1] == "verify":
        runtime.quit_program(provisioner.verify_failures)
    runtime.quit_program(1)

# Connect to a server entry, run the hardening checks against it and disconnect, returning
# the results; quits when no host is configured for it
def verify_server(server_index, domain = None, verbose = False, pretend_run = False, exit_on_failure = False):
    connection = serverinfo.get_connection(
        server_index = server_index,
        flags = runoptions.RunFlags(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure))
    if not connection:
        logger.log_error(
            "No host configured for server %s" % server_index, quit_program = True)
    connection.setup()
    try:
        return hardening.verify_hardening(
            connection = connection,
            domain = domain,
            public_ports = runner.get_public_ports(server_index),
            verbose = False)
    finally:
        connection.teardown()
