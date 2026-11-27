# Imports
import importlib
import os
import shlex
import threading
import time
import uuid
import concurrent.futures
from io import StringIO

# Local imports
from joybox import runtime, cmdline
from joybox import logger, runoptions
from joybox import paths
from joybox import fileops
from joybox import knownhosts
from . import connection

# Get paramiko, imported on first use since only SSH connections need it
def _get_paramiko():
    return importlib.import_module("paramiko")

# The errors an SSH session or SFTP transfer fails with
def _get_ssh_errors():
    return (_get_paramiko().SSHException, OSError, EOFError)

# Load a private key without assuming its type. RSAKey.from_private_key* accepts
# only RSA, so an ed25519 key - what ssh-keygen produces by default - is rejected
# outright. Newer paramiko exposes PKey.from_path, which sniffs the type; fall back
# to trying each class in turn when it is unavailable.
def _load_private_key(filepath = None, key_str = None):
    paramiko = _get_paramiko()
    if filepath and hasattr(paramiko.PKey, "from_path"):
        return paramiko.PKey.from_path(filepath)
    attempts = []
    for key_class in [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]:
        try:
            if filepath:
                return key_class.from_private_key_file(filepath)
            return key_class.from_private_key(StringIO(key_str))
        except _get_ssh_errors() + (ValueError,) as e:
            attempts.append("%s: %s" % (key_class.__name__, e))
    raise ValueError("Could not load SSH private key (%s)" % "; ".join(attempts))

# Trust and remember a server's key the first time, as StrictHostKeyChecking=
# accept-new does; paramiko refuses a later different key, since the known
# keys are loaded before connecting
class RememberNewHostKeyPolicy:
    def __init__(self, known_hosts_path):
        self.known_hosts_path = known_hosts_path

    # Append the unseen key to known_hosts, creating its directory mode 700, and accept it for this session
    def missing_host_key(self, client, hostname, key):
        known_hosts_dir = os.path.dirname(self.known_hosts_path)
        if not paths.does_path_exist(known_hosts_dir):
            fileops.make_directory(known_hosts_dir)
            fileops.chmod_file_or_directory(known_hosts_dir, "700")
        line = "%s %s %s\n" % (hostname, key.get_name(), key.get_base64())
        if not fileops.touch_file(self.known_hosts_path, contents = line, contents_mode = "a"):
            raise OSError("Unable to remember the host key of %s in %s" % (hostname, self.known_hosts_path))
        client.get_host_keys().add(hostname, key.get_name(), key)
        logger.log_info("Trusting the %s host key of %s, seen for the first time" % (key.get_name(), hostname))

# Connection to a remote host over paramiko: commands via exec_command, file contents and uploads via SFTP
class ConnectionSSH(connection.Connection):
    ssh_client = None

    def __init__(
        self,
        ssh_host,
        ssh_port = 22,
        ssh_user = None,
        ssh_key_filepath = None,
        ssh_key_str = None,
        ssh_password = None,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(flags, options)
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_key_filepath = ssh_key_filepath
        self.ssh_key_str = ssh_key_str
        self.ssh_password = ssh_password
        self.remote_home_directory = None

    # Log in with the key (string preferred over file) or else the password; no-op when a session is already live
    def connect(self, timeout = None):
        paramiko = _get_paramiko()
        if not ConnectionSSH.ssh_client:
            ConnectionSSH.ssh_client = paramiko.SSHClient()
            known_hosts_path = knownhosts.get_known_hosts_path()
            if paths.does_path_exist(known_hosts_path):
                ConnectionSSH.ssh_client.load_host_keys(known_hosts_path)
            ConnectionSSH.ssh_client.set_missing_host_key_policy(RememberNewHostKeyPolicy(known_hosts_path))
        if self.is_connected():
            return
        if self.ssh_key_str or self.ssh_key_filepath:
            private_key = _load_private_key(
                filepath = self.ssh_key_filepath if not self.ssh_key_str else None,
                key_str = self.ssh_key_str)
            ConnectionSSH.ssh_client.connect(
                self.ssh_host,
                port = self.ssh_port,
                username = self.ssh_user,
                pkey = private_key,
                timeout = timeout,
                allow_agent = False,
                look_for_keys = False
            )
        elif self.ssh_password:
            ConnectionSSH.ssh_client.connect(
                self.ssh_host,
                port = self.ssh_port,
                username = self.ssh_user,
                password = self.ssh_password,
                timeout = timeout
            )
        else:
            raise ValueError("Either ssh_key_str, ssh_key_filepath, or ssh_password must be provided.")

    # Connect, logging and re-raising any failure
    def setup(self):
        try:
            self.connect()
        except Exception as e:
            logger.log_error("SSH connection failed")
            logger.log_error(e)
            raise

    # Try to log in, for when a refusal is an answer rather than an error
    def try_setup(self, timeout = 15):
        try:
            self.connect(timeout = timeout)
            return True
        except _get_ssh_errors() + (ValueError,):
            self.teardown()
            return False

    # Whether the shared SSH client has an active transport
    def is_connected(self):
        if not ConnectionSSH.ssh_client:
            return False
        transport = ConnectionSSH.ssh_client.get_transport()
        return bool(transport and transport.is_active())

    # Open an SFTP session on the live connection
    def _open_sftp(self):
        if not ConnectionSSH.ssh_client:
            raise ConnectionError("SSH client not initialized")
        return ConnectionSSH.ssh_client.open_sftp()

    # Close the shared SSH client and forget it, logging a close failure rather than raising
    def teardown(self):
        try:
            if ConnectionSSH.ssh_client:
                ConnectionSSH.ssh_client.close()
        except _get_ssh_errors() as e:
            logger.log_error("Failed to close SSH connection")
            logger.log_error(e)
        ConnectionSSH.ssh_client = None

    # Remote home, as SFTP resolves the login directory; cached after the first lookup, None when not connected
    def get_home_directory(self):
        if self.remote_home_directory:
            return self.remote_home_directory
        try:
            if not ConnectionSSH.ssh_client:
                return None
            sftp = self._open_sftp()
            try:
                self.remote_home_directory = sftp.normalize(".")
            finally:
                sftp.close()
        except _get_ssh_errors() as e:
            return self.handle_error("Unable to resolve remote home directory", e, return_value = None)
        return self.remote_home_directory

    # Prefix sudo -n, so a password prompt fails instead of hanging the remote command
    def mark_command_as_sudo(self, cmd):
        if isinstance(cmd, str):
            return f"sudo -n {cmd}"
        if isinstance(cmd, list):
            return ["sudo", "-n"] + cmd
        return cmd

    # Wrap a command string with exports for the option env and a cd to the option cwd, ~ mapped to $HOME
    def process_command(self, cmd):
        parts = []
        if self.options.env:
            env_vars = " ".join([f"export {key}={shlex.quote(value)}" for key, value in self.options.env.items()])
            parts.append(env_vars)
        if self.options.cwd:
            cwd = self.options.cwd
            if cwd == "~":
                cwd = "\"$HOME\""
            elif cwd.startswith("~/"):
                cwd = "\"$HOME\"/" + shlex.quote(cwd[2:])
            else:
                cwd = shlex.quote(cwd)
            parts.append(f"cd {cwd}")
        parts.append(cmd)
        return " && ".join(parts)

    # Run over exec_command and return stripped stdout, plus stderr when the options ask; empty on error
    def run_output(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise ConnectionError("SSH client not initialized")
            cmd = cmdline.create_command_string(cmd, style = "posix")
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.process_command(cmd)
                _, stdout, stderr = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                output = stdout.read()
                error = stderr.read()
                output = cmdline.clean_command_output(output.strip())
                error = cmdline.clean_command_output(error.strip())
                if self.options.include_stderr and error:
                    return output + "\n" + error
                return output
            return ""
        except _get_ssh_errors() as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return ""

    # Run over exec_command and return the remote exit status; 1 on error
    def run_return_code(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise ConnectionError("SSH client not initialized")
            cmd = cmdline.create_command_string(cmd, style = "posix")
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.process_command(cmd)
                _, stdout, _ = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                exit_code = stdout.channel.recv_exit_status()
                return exit_code
            return 0
        except _get_ssh_errors() as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return 1

    # Run over exec_command, streaming the channel output to the log; returns the exit status, 1 on error
    def run_blocking(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise ConnectionError("SSH client not initialized")
            cmd = cmdline.create_command_string(cmd, style = "posix")
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.process_command(cmd)
                _, stdout, _ = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                channel = stdout.channel
                self.stream_command_output(iter(lambda: channel.recv(4096), b""))
                exit_code = channel.recv_exit_status()
                return exit_code
            return 0
        except _get_ssh_errors() as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return 1

    # Run inside a remote login shell, logging its output when verbose; returns the exit status, 1 on error
    def run_interactive(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise ConnectionError("SSH client not initialized")
            cmd = cmdline.create_command_string(cmd, style = "posix")
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.process_command(cmd)
                channel = ConnectionSSH.ssh_client.invoke_shell()
                try:
                    channel.settimeout(5.0)
                    channel.send(cmd + "\nexit $?\n")
                    while True:
                        if channel.recv_ready():
                            data = channel.recv(1024).decode("utf-8", errors="ignore")
                            if self.flags.verbose:
                                logger.log_info(data.strip())
                        elif channel.exit_status_ready():
                            break
                        else:
                            time.sleep(0.1)
                    return channel.recv_exit_status()
                finally:
                    channel.close()
            return 0
        except _get_ssh_errors() as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return 1

    # Run blocking; on a nonzero exit raise ValueError when asked, otherwise quit with that code
    def run_checked(self, cmd, sudo = False, throw_exception = False):
        code = self.run_blocking(cmd = cmd, sudo = sudo)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            runtime.quit_program(code)

    # Create a remote temp directory by mktemp -d; None in a pretend run or on failure
    def make_temporary_directory(self):
        if self.flags.pretend_run:
            return None
        temp_dir = self.run_output("mktemp -d").strip()
        if not temp_dir:
            return self.handle_error("Failed to create temporary directory", "mktemp failed", return_value = None)
        if self.flags.verbose:
            logger.log_info(f"Created temporary directory: {temp_dir}")
        return temp_dir

    # Whether the remote path exists, by an SFTP stat
    def does_file_or_directory_exist(self, src):
        try:
            if self.flags.verbose:
                logger.log_info(f"Checking existence of {src}")
            if not self.flags.pretend_run:
                sftp = self._open_sftp()
                try:
                    sftp.stat(src)
                finally:
                    sftp.close()
            return True
        except FileNotFoundError:
            return False
        except _get_ssh_errors() as e:
            return self.handle_error(f"Error checking existence of {src}", e)

    # Upload a local file or tree over SFTP, eight files at a time; under sudo, upload to /tmp then cp into place as root
    def transfer_files(self, src, dest, excludes = None, sudo = False):
        excludes = [] if excludes is None else excludes
        try:
            if self.flags.verbose:
                logger.log_info(f"Transferring {src} to {dest}")
            if self.flags.pretend_run:
                return True
            upload_dest = "/tmp/transfer_" + uuid.uuid4().hex if sudo else dest
            try:
                sftp = self._open_sftp()
                try:
                    uploaded = self._upload_files(sftp, self._plan_upload(sftp, src, upload_dest, excludes))
                finally:
                    sftp.close()
                if not all(uploaded):
                    return self.handle_error(f"Failed to transfer {src} to {dest}", "%d file(s) failed" % uploaded.count(False))
                if sudo:
                    if os.path.isdir(src):
                        cmds = [["mkdir", "-p", dest], ["cp", "-r", upload_dest + "/.", dest]]
                    else:
                        cmds = [["cp", upload_dest, dest]]
                    for cmd in cmds:
                        if self.run_blocking(cmd, sudo = True) != 0:
                            return self.handle_error(f"Failed to transfer {src} to {dest}", "copy failed")
                return True
            finally:
                if sudo:
                    self.run_blocking(["rm", "-rf", "--", upload_dest])
        except _get_ssh_errors() + (ValueError,) as e:
            return self.handle_error(f"Failed to transfer {src} to {dest}", e)

    def _plan_upload(self, sftp, src, dest, excludes):
        if not os.path.isdir(src):
            return [(src, dest)]
        file_tasks = []
        for dirpath, dirnames, filenames in os.walk(src):
            relative = os.path.relpath(dirpath, src)
            dirnames[:] = [name for name in dirnames
                if not paths.is_exclude_path(os.path.join(relative, name), excludes = excludes)]
            remote_dir = dest if dirpath == src else os.path.join(dest, relative)
            if self.flags.verbose:
                logger.log_info(f"Making remote directory: {remote_dir}")
            try:
                sftp.stat(remote_dir)
            except FileNotFoundError:
                sftp.mkdir(remote_dir)
            for filename in filenames:
                if not paths.is_exclude_path(filename, excludes = excludes):
                    file_tasks.append((os.path.join(dirpath, filename), os.path.join(remote_dir, filename)))
        return file_tasks

    def _upload_files(self, sftp, file_tasks):
        sftp_lock = threading.Lock()

        def upload_file(task):
            local_file, remote_file = task
            try:
                with sftp_lock:
                    if self.flags.verbose:
                        logger.log_info(f"Transferring file: {local_file} to {remote_file}")
                    sftp.put(local_file, remote_file)
                return True
            except _get_ssh_errors() as e:
                logger.log_error(f"Failed to transfer file {local_file} to {remote_file}: {e}")
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers = 8) as executor:
            return list(executor.map(upload_file, file_tasks))

    # Read a remote file over SFTP, or by sudo cat when sudo is set
    def read_file(self, src, sudo = False):
        try:
            if self.flags.verbose:
                logger.log_info(f"Reading remote file {src}")
            if not self.flags.pretend_run:
                if sudo:
                    return self.run_output(["cat", src], sudo = True)
                sftp = self._open_sftp()
                try:
                    with sftp.file(src, "r") as f:
                        return f.read().decode()
                finally:
                    sftp.close()
            return None
        except _get_ssh_errors() + (ValueError,) as e:
            return self.handle_error(f"Unable to read file from {src}", e, return_value = None)

    # Write a remote file over SFTP; under sudo, write to /tmp then cp into place as root
    def write_file(self, src, contents, sudo = False):
        try:
            if self.flags.verbose:
                logger.log_info(f"Writing remote file {src}")
            if not self.flags.pretend_run:
                if sudo:
                    temp_path = "/tmp/tmp_write_file_" + uuid.uuid4().hex
                    sftp = self._open_sftp()
                    try:
                        with sftp.file(temp_path, "w") as remote_file:
                            remote_file.write(contents)
                            remote_file.flush()
                        code = self.run_blocking(["cp", temp_path, src], sudo = True)
                    finally:
                        sftp.remove(temp_path)
                        sftp.close()
                    if code != 0:
                        return self.handle_error(f"Failed to write file {src}", "copy failed")
                else:
                    sftp = self._open_sftp()
                    try:
                        with sftp.file(src, "w") as remote_file:
                            remote_file.write(contents)
                            remote_file.flush()
                    finally:
                        sftp.close()
            return True
        except _get_ssh_errors() + (ValueError,) as e:
            return self.handle_error(f"Failed to write file {src}", e)

    def _run_operation(self, cmd, sudo, message):
        try:
            self.run_checked(cmd, sudo = sudo, throw_exception = True)
            return True
        except _get_ssh_errors() + (ValueError,) as e:
            return self.handle_error(message, e)

    # Create the remote directory and parents by mkdir -p
    def make_directory(self, src, sudo = False):
        return self._run_operation(["mkdir", "-p", src], sudo, f"Unable to make directory {src}")

    # Delete the remote path by rm -rf
    def remove_file_or_directory(self, src, sudo = False):
        return self._run_operation(["rm", "-rf", "--", src], sudo, f"Unable to remove {src}")

    # Copy within the remote host by cp -r
    def copy_file_or_directory(self, src, dest, sudo = False):
        return self._run_operation(["cp", "-r", src, dest], sudo, f"Unable to copy {src} to {dest}")

    # Move within the remote host by mv
    def move_file_or_directory(self, src, dest, sudo = False):
        return self._run_operation(["mv", src, dest], sudo, f"Unable to move {src} to {dest}")

    # Symlink on the remote host by ln -sf
    def link_file_or_directory(self, src, dest, sudo = False):
        return self._run_operation(["ln", "-sf", src, dest], sudo, f"Unable to link {src} to {dest}")

    # Fetch the URL on the remote host by curl -fL, failing on HTTP errors
    def download_file(self, url, dest, sudo = False):
        return self._run_operation(["curl", "-fL", "-o", dest, url], sudo, f"Unable to download {url} to {dest}")

    # Unpack a tar archive already on the remote host by tar -xf
    def extract_tar_archive(self, src, dest, sudo = False):
        return self._run_operation(["tar", "-xf", src, "-C", dest], sudo, f"Unable to extract {src} to {dest}")

    # Recursive chown on the remote host
    def change_owner(self, src, owner, sudo = False):
        return self._run_operation(["chown", "-R", owner, src], sudo, f"Unable to change owner of {src}")

    # Recursive chmod on the remote host
    def change_permission(self, src, permission, sudo = False):
        return self._run_operation(["chmod", "-R", permission, src], sudo, f"Unable to change permissions of {src}")
