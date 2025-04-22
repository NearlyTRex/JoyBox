# Imports
import os
import sys

# Local imports
import util
from . import connection_local

class ConnectionLocalAdministrator(connection_local.ConnectionLocal):
    def __init__(
        self,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(flags, options)

    def MakeTemporaryDirectory(self):
        return False

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
