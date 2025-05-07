# Imports
import os
import sys
import shlex
import paramiko
import stat
import traceback
import threading
import select
import termios
import tty
import time
import concurrent.futures
from io import StringIO

# Local imports
import util
from . import connection

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

    def Setup(self):
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
            util.LogError("SSH connection failed")
            util.LogError(e)
            raise

    def TearDown(self):
        try:
            if ConnectionSSH.ssh_client and ConnectionSSH.ssh_client.get_transport().is_active():
                ConnectionSSH.ssh_client.close()
                ConnectionSSH.ssh_client = None
        except Exception as e:
            util.LogError("Failed to close SSH connection")
            util.LogError(e)

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

    def RunOutput(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.CreateCommandString(cmd)
            if sudo:
                cmd = self.MarkCommandAsSudo(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                stdin, stdout, stderr = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                output = stdout.read()
                error = stderr.read()
                output = self.CleanCommandOutput(output.strip())
                error = self.CleanCommandOutput(error.strip())
                if self.options.include_stderr and error:
                    return output + "\n" + error
                return output
            return ""
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return ""

    def RunReturncode(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.CreateCommandString(cmd)
            if sudo:
                cmd = self.MarkCommandAsSudo(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
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
                util.LogError(e)
                util.QuitProgram()
            return 1

    def RunBlocking(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.CreateCommandString(cmd)
            if sudo:
                cmd = self.MarkCommandAsSudo(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                stdin, stdout, stderr = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                while True:
                    output = stdout.readline()
                    if not output:
                        break
                    util.LogInfo(self.CleanCommandOutput(output.strip()))
                exit_code = stdout.channel.recv_exit_status()
                return exit_code
            return 0
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return 1

    def RunInteractive(self, cmd, sudo = False):
        try:
            if not ConnectionSSH.ssh_client:
                raise RuntimeError("SSH client not initialized")
            cmd = self.CreateCommandString(cmd)
            if sudo:
                cmd = self.MarkCommandAsSudo(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                channel = ConnectionSSH.ssh_client.invoke_shell()
                channel.settimeout(5.0)
                channel.send(cmd + "\n")
                while True:
                    if channel.recv_ready():
                        data = channel.recv(1024).decode("utf-8", errors="ignore")
                        if self.flags.verbose:
                            util.LogInfo(data.strip())
                    elif channel.exit_status_ready():
                        break
                    else:
                        time.sleep(0.1)
                exit_code = channel.recv_exit_status()
                return exit_code
            return 0
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return 1

    def RunChecked(self, cmd, sudo = False, throw_exception = False):
        code = self.RunBlocking(cmd = cmd, sudo = sudo)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            else:
                util.QuitProgram(code)

    def MakeTemporaryDirectory(self):
        try:
            temp_dir = self.RunOutput("mktemp -d").strip()
            if self.flags.verbose:
                util.LogInfo(f"Created temporary directory: {temp_dir}")
            return temp_dir
        except Exception as e:
            util.LogError("Failed to create temporary directory")
            util.LogError(e)
            return None

    def DoesFileOrDirectoryExist(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Checking existence of {src}")
            if not self.flags.pretend_run:
                sftp = ConnectionSSH.ssh_client.open_sftp()
                sftp.stat(src)
                sftp.close()
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Error checking existence of {src}")
                util.LogError(e)
                util.QuitProgram()
            return False

    def TransferFiles(self, src, dest, excludes = []):
        try:
            sftp = ConnectionSSH.ssh_client.open_sftp()
            sftp_lock = threading.Lock()

            # Gather all files and ensure remote dirs
            file_tasks = []
            for dirpath, dirnames, filenames in os.walk(src):
                if IsExcludedPath(os.path.relpath(dirpath, src), excludes = excludes):
                    continue

                # Get remote directory
                if dirpath == src:
                    remote_dir = dest
                else:
                    remote_dir = os.path.join(dest, os.path.relpath(dirpath, src))

                # Ensure the remote directory exists
                util.LogInfo(f"Making remote directory: {remote_dir}")
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
                        util.LogInfo(f"Transferring file: {local_file} to {remote_file}")
                        sftp.put(local_file, remote_file)
                except Exception as e:
                    util.LogError(f"Failed to transer file {local_file} to {remote_file}: {e}")

            # Start uploads
            with concurrent.futures.ThreadPoolExecutor(max_workers = 8) as executor:
                executor.map(upload_file, file_tasks)
            sftp.close()
            return True
        except Exception as e:
            util.LogError(f"Failed to transfer {src} to {dest}")
            util.LogError(e)
            util.LogError(traceback.format_exc())
            return False

    def ReadFile(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Reading remote file {src}")
            if not self.flags.pretend_run:
                sftp = ConnectionSSH.ssh_client.open_sftp()
                with sftp.file(src, "r") as f:
                    contents = f.read().decode()
                sftp.close()
                return contents
            return None
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to read file from {src}")
                util.LogError(e)
                util.QuitProgram()
            return None

    def WriteFile(self, src, contents):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Writing remote file {src}")
            if not self.flags.pretend_run:
                sftp = ConnectionSSH.ssh_client.open_sftp()
                with sftp.file(src, "w") as remote_file:
                    remote_file.write(contents)
                    remote_file.flush()
                sftp.close()
                return True
            return False
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Failed to write file {src}")
                util.LogError(e)
                util.QuitProgram()
            return False
