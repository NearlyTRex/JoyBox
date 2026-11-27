# Imports
import os

# Local imports
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from . import installer

# AWS CLI
class AwsCli(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.aws_binary_path = "/usr/local/bin/aws"
        self.install_dir = "/usr/local/aws-cli"

    # Local Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Whether /usr/local/bin/aws exists
    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.aws_binary_path)

    # aws-cli as installed or missing, by /usr/local/bin/aws
    def get_package_status(self):
        installed = []
        missing = []
        if self.connection.does_file_or_directory_exist(self.aws_binary_path):
            installed.append("aws-cli")
        else:
            missing.append("aws-cli")
        return {"installed": installed, "missing": missing}

    # Install or update AWS CLI v2 from Amazon's x86_64 zip with its bundled
    # installer, then check aws --version; False when a step fails
    def install(self):

        # Start install
        logger.log_info("Installing AWS CLI v2")

        # Ensure required tools are installed
        logger.log_info("Installing required dependencies")
        code = self.connection.run_blocking(
            [self.aptget_tool, "install", "-y", "unzip", "curl"],
            sudo=True
        )
        if code != 0:
            logger.log_error("Failed to install dependencies")
            return False

        # Create temp directory for download
        temp_dir = "/tmp/awscli-install"
        self.connection.remove_file_or_directory(temp_dir)
        self.connection.make_directory(temp_dir)

        # Download, extract and run the installer
        if not self._run_bundled_installer(temp_dir):
            self.connection.remove_file_or_directory(temp_dir)
            return False

        # Cleanup
        logger.log_info("Cleaning up")
        self.connection.remove_file_or_directory(temp_dir)

        # Verify installation
        logger.log_info("Verifying installation")
        code = self.connection.run_blocking([self.aws_binary_path, "--version"])
        if code != 0:
            logger.log_error("AWS CLI installation verification failed")
            return False

        # All done
        logger.log_info("AWS CLI installed successfully")
        return True

    # Download Amazon's zip into temp_dir, unpack it and run its installer, updating
    # an existing install; False after logging the step that failed
    def _run_bundled_installer(self, temp_dir):

        # Download AWS CLI installer
        logger.log_info("Downloading AWS CLI installer")
        download_url = "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
        zip_path = os.path.join(temp_dir, "awscliv2.zip")
        self.connection.download_file(download_url, zip_path)
        if not self.connection.does_file_or_directory_exist(zip_path):
            logger.log_error("Failed to download AWS CLI installer")
            return False

        # Unzip the installer
        logger.log_info("Extracting AWS CLI installer")
        code = self.connection.run_blocking(
            [self.unzip_tool, "-q", zip_path, "-d", temp_dir]
        )
        if code != 0:
            logger.log_error("Failed to extract AWS CLI installer")
            return False

        # Run the installer
        logger.log_info("Running AWS CLI installer")
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
            logger.log_error("Failed to run AWS CLI installer")
            return False
        return True

    # Remove /usr/local/aws-cli and the aws and aws_completer links in /usr/local/bin
    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling AWS CLI")

        # Remove the installation directory
        if self.connection.does_file_or_directory_exist(self.install_dir):
            logger.log_info("Removing AWS CLI installation directory")
            self.connection.remove_file_or_directory(self.install_dir, sudo=True)

        # Remove symlinks
        logger.log_info("Removing AWS CLI symlinks")
        self.connection.remove_file_or_directory("/usr/local/bin/aws", sudo=True)
        self.connection.remove_file_or_directory("/usr/local/bin/aws_completer", sudo=True)

        # All done
        logger.log_info("AWS CLI uninstalled")
        return True
