# Imports
import os
import sys
import copy

# Local imports
import util

class Connection:
    def __init__(
        self,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        self.flags = flags
        self.options = options

    def Copy(self):
        return copy.deepcopy(self)

    def Setup(self):
        pass

    def TearDown(self):
        pass

    def SetCurrentWorkingDirectory(self, cwd):
        self.options.cwd = cwd

    def SetEnvironment(self, env):
        self.options.env = env

    def SetEnvironmentVar(self, var, value):
        self.options.env[var] = value

    def UnsetEnvironmentVar(self, var):
        del self.options.env[var]

    def SetFlags(self, flags):
        self.flags = flags

    def GetFlags(self):
        return self.flags

    def SetOptions(self, options):
        self.options = options

    def GetOptions(self):
        return self.options

    def CreateCommandString(self, cmd):
        if not cmd:
            return ""
        if len(cmd) == 0:
            return ""
        if isinstance(cmd, str):
            return copy.deepcopy(cmd)
        if isinstance(cmd, list):
            cmd_str = ""
            for cmd_segment in cmd:
                if " " in cmd_segment:
                    cmd_str += " " + "\"" + cmd_segment + "\""
                else:
                    cmd_str += " " + cmd_segment
            cmd_str = cmd_str.strip()
            return cmd_str
        return ""

    def CreateCommandList(self, cmd):
        if not cmd:
            return []
        if len(cmd) == 0:
            return []
        if isinstance(cmd, list):
            return copy.deepcopy(cmd)
        if isinstance(cmd, str):
            return cmd.split(" ")
        return []

    def CleanCommandOutput(self, output):
        try:
            return output.decode("utf-8", "ignore")
        except:
            return output

    def PrintCommand(self, cmd):
        if isinstance(cmd, str):
            util.LogInfo("Running \"%s\"" % cmd)
        if isinstance(cmd, list):
            util.LogInfo("Running \"%s\"" % " ".join(cmd))

    def ProcessCommand(self, cmd):
        return cmd

    def RunOutput(self, cmd):
        return ""

    def RunReturncode(self, cmd):
        return 0

    def RunBlocking(self, cmd):
        return 0

    def RunInteractive(self, cmd):
        return 0

    def RunChecked(self, cmd, throw_exception = False):
        return None

    def MakeTemporaryDirectory(self):
        return None

    def MakeDirectory(self, src):
        return False

    def RemoveDirectory(self, src):
        return False

    def RemoveFile(self, src):
        return False

    def CopyFileOrDirectory(self, src, dest):
        return False

    def MoveFileOrDirectory(self, src, dest):
        return False

    def DoesFileOrDirectoryExist(self, src):
        return False

    def TransferFiles(self, src, dest, excludes = []):
        return False

    def ReadFile(self, src):
        return None

    def WriteFile(self, src, contents):
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
        if util.IsWindowsPlatform():
            return self.AddToWindowsPath(src)
        else:
            return self.AddToUnixPath(src)

    def AddToWindowsPath(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Adding {src} to path")
            if not self.flags.pretend_run:

                # Get current path
                current_path = self.RunOutput([
                    "powershell",
                    "-Command",
                    '[Environment]::GetEnvironmentVariable("PATH", "User")'
                ])
                current_paths = current_path.split(";") if current_path else []
                current_paths = [p.strip() for p in current_path.split(";") if p.strip()]
                if src.strip() in current_paths:
                    return True

                # Append path
                new_paths = ";".join(current_paths + [src])
                new_paths_escaped = new_paths.replace('"', '`"')
                code = self.RunReturncode([
                    "powershell",
                    "-Command",
                    f'[Environment]::SetEnvironmentVariable("PATH", "{new_paths_escaped}", "User")'
                ])
                return code == 0
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to add {src} to path")
                util.LogError(e)
                util.QuitProgram()
            return False

    def AddToUnixPath(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Adding {src} to path")
            if not self.flags.pretend_run:

                # Get possible profiles
                profile_candidates = [
                    "~/.bash_profile",
                    "~/.bashrc",
                    "~/.zshrc",
                    "~/.profile"
                ]

                # Get profile
                profile_file = profile_candidates[0]
                for candidate in profile_candidates:
                    if self.DoesFileOrDirectoryExist(candidate):
                        profile_file = candidate
                        break

                # Read current profile
                existing_content = self.ReadFile(profile_file)
                if not existing_content:
                    existing_content = ""

                # Add to profile
                export_line = f'export PATH="{src}:$PATH"\n'
                if export_line not in existing_content:
                    new_content = existing_content + "\n" + export_line + "\n"
                    return self.WriteFile(profile_file, new_content)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to add {src} to path")
                util.LogError(e)
                util.QuitProgram()
            return False
