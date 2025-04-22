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

    def RunChecked(self, cmd, throw_exception = False):
        return None

    def MakeTemporaryDirectory(self):
        return None

    def MakeDirectory(self, src):
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
