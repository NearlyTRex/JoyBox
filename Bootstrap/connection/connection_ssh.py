# Imports
import os
import sys
import shlex
import stat
import traceback
import threading
import select
import time
import concurrent.futures
from io import StringIO

# Local imports
import util
from . import connection

# Lazy import for paramiko (only needed for SSH connections)
paramiko = None

def _ensure_paramiko():
    global paramiko
    if paramiko is None:
        import paramiko as _paramiko
        paramiko = _paramiko

class ConnectionSSH(connection.Connection):
    ssh_client = None

    def __init__(
        self,
        config,
        ssh_host,
        ssh_port = 22,
        ssh_user = None,
        ssh_key_filepath = None,
        ssh_key_str = None,
        ssh_password = None,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, flags, options)
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_key_filepath = ssh_key_filepath
        self.ssh_key_str = ssh_key_str
        self.ssh_password = ssh_password

    def setup(self):
        _ensure_paramiko()
        try:
            if not ConnectionSSH.ssh_client:
                ConnectionSSH.ssh_client = paramiko.SSHClient()
                ConnectionSSH.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if not ConnectionSSH.ssh_client.get_transport() or not ConnectionSSH.ssh_client.get_transport().is_active():
                if self.ssh_key_str:
                    private_key = paramiko.RSAKey.from_private_key(StringIO(self.ssh_key_str))
                    ConnectionSSH.ssh_client.connect(
                        self.ssh_host,
                        port = self.ssh_port,
                        username = self.ssh_user,
                        pkey = private_key
                    )
                elif self.ssh_key_filepath:
                    private_key = paramiko.RSAKey.from_private_key_file(self.ssh_key_filepath)
                    ConnectionSSH.ssh_client.connect(
                        self.ssh_host,
                        port = self.ssh_port,
                        username = self.ssh_user,
                        pkey = private_key
                    )
                elif self.ssh_password:
                    ConnectionSSH.ssh_client.connect(
                        self.ssh_host,
                        port = self.ssh_port,
                        username = self.ssh_user,
                        password = self.ssh_password
                    )
                else:
                    raise ValueError("Either ssh_key_str, ssh_key_filepath, or ssh_password must be provided.")
        except Exception as e:
            util.log_error("SSH connection failed")
            util.log_error(e)
            raise

    def teardown(self):
        try:
            if ConnectionSSH.ssh_client and ConnectionSSH.ssh_client.get_transport().is_active():
                ConnectionSSH.ssh_client.close()
                ConnectionSSH.ssh_client = None
        except Exception as e:
            util.log_error("Failed to close SSH connection")
            util.log_error(e)

    def ProcessCommand(self, cmd):
        parts = []
        if self.options.env:
            env_vars = " ".join([f"export {key}={shlex.quote(value)}" for key, value in self.options.env.items()])
            parts.append(env_vars)
        if self.options.cwd:
            cwd = shlex.quote(self.options.cwd)
            cwd = cwd.replace("~", f"/home/{self.ssh_user}")
            cwd = cwd.replace("$HOME", f"/home/{self.ssh_user}")
            parts.append(f"cd {cwd}")
        parts.append(cmd)
        return " && ".join(parts)

    def run_output(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.create_command_string(cmd)
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                stdin, stdout, stderr = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                output = stdout.read()
                error = stderr.read()
                output = self.clean_command_output(output.strip())
                error = self.clean_command_output(error.strip())
                if self.options.include_stderr and error:
                    return output + "\n" + error
                return output
            return ""
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return ""

    def run_return_code(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.create_command_string(cmd)
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                stdin, stdout, stderr = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                exit_code = stdout.channel.recv_exit_status()
                return exit_code
            return 0
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return 1

    def run_blocking(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.create_command_string(cmd)
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                stdin, stdout, stderr = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                channel = stdout.channel
                self.stream_command_output(iter(lambda: channel.recv(4096), b""))
                exit_code = channel.recv_exit_status()
                return exit_code
            return 0
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return 1

    def run_interactive(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.create_command_string(cmd)
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                channel = ConnectionSSH.ssh_client.invoke_shell()
                channel.settimeout(5.0)
                channel.send(cmd + "\n")
                while True:
                    if channel.recv_ready():
                        data = channel.recv(1024).decode("utf-8", errors="ignore")
                        if self.flags.verbose:
                            util.log_info(data.strip())
                    elif channel.exit_status_ready():
                        break
                    else:
                        time.sleep(0.1)
                exit_code = channel.recv_exit_status()
                return exit_code
            return 0
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return 1

    def run_checked(self, cmd, sudo = False, throw_exception = False):
        code = self.run_blocking(cmd = cmd, sudo = sudo)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            else:
                util.quit_program(code)

    def make_temporary_directory(self):
        try:
            temp_dir = self.run_output("mktemp -d").strip()
            if self.flags.verbose:
                util.log_info(f"Created temporary directory: {temp_dir}")
            return temp_dir
        except Exception as e:
            util.log_error("Failed to create temporary directory")
            util.log_error(e)
            return None

    def does_file_or_directory_exist(self, src):
        try:
            if self.flags.verbose:
                util.log_info(f"Checking existence of {src}")
            if not self.flags.pretend_run:
                sftp = ConnectionSSH.ssh_client.open_sftp()
                sftp.stat(src)
                sftp.close()
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Error checking existence of {src}")
                util.log_error(e)
                util.quit_program()
            return False

    def transfer_files(self, src, dest, excludes = [], sudo = False):
        try:
            sftp = ConnectionSSH.ssh_client.open_sftp()
            sftp_lock = threading.Lock()

            # For sudo transfers, upload to temp dir first then move
            if sudo:
                temp_dest = f"/tmp/transfer_{int(time.time())}"
                actual_dest = dest
                dest = temp_dest

            # Gather all files and ensure remote dirs
            file_tasks = []
            for dirpath, dirnames, filenames in os.walk(src):
                if util.is_exclude_path(os.path.relpath(dirpath, src), excludes = excludes):
                    continue

                # Get remote directory
                if dirpath == src:
                    remote_dir = dest
                else:
                    remote_dir = os.path.join(dest, os.path.relpath(dirpath, src))

                # Ensure the remote directory exists
                util.log_info(f"Making remote directory: {remote_dir}")
                try:
                    sftp.stat(remote_dir)
                except FileNotFoundError:
                    sftp.mkdir(remote_dir)

                # Collect files to copy
                for filename in filenames:
                    local_file_path = os.path.join(dirpath, filename)
                    remote_file_path = os.path.join(remote_dir, filename)
                    file_tasks.append((local_file_path, remote_file_path))

            # Upload files in parallel
            def upload_file(task):
                local_file, remote_file = task
                try:
                    with sftp_lock:
                        util.log_info(f"Transferring file: {local_file} to {remote_file}")
                        sftp.put(local_file, remote_file)
                except Exception as e:
                    util.log_error(f"Failed to transfer file {local_file} to {remote_file}: {e}")

            # Start uploads
            with concurrent.futures.ThreadPoolExecutor(max_workers = 8) as executor:
                executor.map(upload_file, file_tasks)
            sftp.close()

            # For sudo transfers, move from temp to actual destination
            if sudo:
                self.run_blocking(["mv", temp_dest, actual_dest], sudo = True)
            return True
        except Exception as e:
            util.log_error(f"Failed to transfer {src} to {dest}")
            util.log_error(e)
            util.log_error(traceback.format_exc())
            return False

    def read_file(self, src, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Reading remote file {src}")
            if not self.flags.pretend_run:
                if sudo:
                    return self.run_output(["cat", src], sudo = True)
                else:
                    sftp = ConnectionSSH.ssh_client.open_sftp()
                    with sftp.file(src, "r") as f:
                        contents = f.read().decode()
                    sftp.close()
                    return contents
            return None
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to read file from {src}")
                util.log_error(e)
                util.quit_program()
            return None

    def write_file(self, src, contents, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Writing remote file {src}")
            if not self.flags.pretend_run:
                if sudo:
                    temp_path = "/tmp/tmp_write_file_" + str(int(time.time()))
                    sftp = ConnectionSSH.ssh_client.open_sftp()
                    with sftp.file(temp_path, "w") as remote_file:
                        remote_file.write(contents)
                        remote_file.flush()
                    sftp.close()
                    self.run_blocking(["mv", temp_path, src], sudo = True)
                else:
                    sftp = ConnectionSSH.ssh_client.open_sftp()
                    with sftp.file(src, "w") as remote_file:
                        remote_file.write(contents)
                        remote_file.flush()
                    sftp.close()
                return True
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Failed to write file {src}")
                util.log_error(e)
                util.quit_program()
            return False
