# Imports
import os
import sys
import shlex
import paramiko
from io import StringIO

# Local imports
import util
from . import connection

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
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(flags, options)
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
        if self.options.env:
            env_vars = " ".join([f"export {key}={shlex.quote(value)}" for key, value in self.options.env.items()])
            cmd = f"{env_vars} && {cmd}"
        return cmd

    def RunOutput(self, cmd):
        try:
            cmd = self.CreateCommandString(cmd)
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
        except Exception as e:
            if self.flags.verbose:
                util.LogError(e)
            elif self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return ""

    def RunReturncode(self, cmd):
        try:
            cmd = self.CreateCommandString(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
            if not self.flags.pretend_run:
                cmd = self.ProcessCommand(cmd)
                stdin, stdout, stderr = ConnectionSSH.ssh_client.exec_command(
                    command = cmd,
                    get_pty = self.options.shell)
                exit_code = stdout.channel.recv_exit_status()
                return exit_code
        except Exception as e:
            if self.flags.verbose:
                util.LogError(e)
            elif self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return 1

    def RunBlocking(self, cmd):
        try:
            cmd = self.CreateCommandString(cmd)
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
        except Exception as e:
            if self.flags.verbose:
                util.LogError(e)
            elif self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return 1

    def RunChecked(self, cmd, throw_exception = False):
        code = self.RunBlocking(cmd = cmd)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            else:
                util.QuitProgram(code)

    def MakeTemporaryDirectory(self):
        return None

    def MakeDirectory(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Making remote directory {src}")
            sftp = ConnectionSSH.ssh_client.open_sftp()
            try:
                sftp.stat(src)
            except FileNotFoundError:
                sftp.mkdir(src)
            sftp.close()
            return True
        except Exception as e:
            if self.flags.verbose:
                util.LogError(f"Failed to make directory {src}")
                util.LogError(e)
            elif self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return False

    def RemoveDirectory(self, src):
        return False

    def CopyFileOrDirectory(self, src, dest):
        return False

    def MoveFileOrDirectory(self, src, dest):
        return False

    def DoesFileOrDirectoryExist(self, src):
        return False

    def WriteFile(self, src, contents):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Writing remote file {src}")
            sftp = ConnectionSSH.ssh_client.open_sftp()
            remote_dir = os.path.dirname(src)
            if self.MakeDirectory(remote_dir):
                with sftp.file(src, "w") as remote_file:
                    remote_file.write(contents)
                    remote_file.flush()
                sftp.close()
                return True
            return False
        except Exception as e:
            if self.flags.verbose:
                util.LogError(f"Failed to write file {src}")
                util.LogError(e)
            elif self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return False

    def DownloadFile(self, url, dest):
        return False

    def ExtractTarArchive(self, src, dest):
        return False

    def ExtractZipArchive(self, src, dest):
        return False

    def ChangeOwner(self, src, owner):
        return False

    def ChangePermission(self, src, permission):
        return False

    def AddToPath(self, src):
        return False
