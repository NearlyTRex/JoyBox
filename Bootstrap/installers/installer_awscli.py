# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# AWS CLI
class AwsCli(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.aws_binary_path = "/usr/local/bin/aws"
        self.install_dir = "/usr/local/aws-cli"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.aws_binary_path)

    def get_package_status(self):
        installed = []
        missing = []
        if self.connection.does_file_or_directory_exist(self.aws_binary_path):
            installed.append("aws-cli")
        else:
            missing.append("aws-cli")
        return {"installed": installed, "missing": missing}

    def install(self):

        # Start install
        util.log_info("Installing AWS CLI v2")

        # Ensure required tools are installed
        util.log_info("Installing required dependencies")
        code = self.connection.run_blocking(
            [self.aptget_tool, "install", "-y", "unzip", "curl"],
            sudo=True
        )
        if code != 0:
            util.log_error("Failed to install dependencies")
            return False

        # Create temp directory for download
        temp_dir = "/tmp/awscli-install"
        self.connection.remove_file_or_directory(temp_dir)
        self.connection.make_directory(temp_dir)

        # Download AWS CLI installer
        util.log_info("Downloading AWS CLI installer")
        download_url = "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
        zip_path = os.path.join(temp_dir, "awscliv2.zip")
        self.connection.download_file(download_url, zip_path)
        if not self.connection.does_file_or_directory_exist(zip_path):
            util.log_error("Failed to download AWS CLI installer")
            self.connection.remove_file_or_directory(temp_dir)
            return False

        # Unzip the installer
        util.log_info("Extracting AWS CLI installer")
        code = self.connection.run_blocking(
            ["unzip", "-q", zip_path, "-d", temp_dir]
        )
        if code != 0:
            util.log_error("Failed to extract AWS CLI installer")
            self.connection.remove_file_or_directory(temp_dir)
            return False

        # Run the installer
        util.log_info("Running AWS CLI installer")
        installer_path = os.path.join(temp_dir, "aws", "install")
        if self.connection.does_file_or_directory_exist(self.aws_binary_path):
            code = self.connection.run_blocking(
                [installer_path, "--update"],
                sudo=True
            )
        else:
            code = self.connection.run_blocking(
                [installer_path],
                sudo=True
            )
        if code != 0:
            util.log_error("Failed to run AWS CLI installer")
            self.connection.remove_file_or_directory(temp_dir)
            return False

        # Cleanup
        util.log_info("Cleaning up")
        self.connection.remove_file_or_directory(temp_dir)

        # Verify installation
        util.log_info("Verifying installation")
        code = self.connection.run_blocking([self.aws_binary_path, "--version"])
        if code != 0:
            util.log_error("AWS CLI installation verification failed")
            return False

        # All done
        util.log_info("AWS CLI installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling AWS CLI")

        # Remove the installation directory
        if self.connection.does_file_or_directory_exist(self.install_dir):
            util.log_info("Removing AWS CLI installation directory")
            self.connection.remove_file_or_directory(self.install_dir, sudo=True)

        # Remove symlinks
        util.log_info("Removing AWS CLI symlinks")
        self.connection.remove_file_or_directory("/usr/local/bin/aws", sudo=True)
        self.connection.remove_file_or_directory("/usr/local/bin/aws_completer", sudo=True)

        # All done
        util.log_info("AWS CLI uninstalled")
        return True
