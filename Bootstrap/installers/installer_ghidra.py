# Imports
import os
import sys

# Local imports
import util
from . import installer

# Nginx stream config template
nginx_stream_config_template = """
upstream ghidra_rmi_registry {{
    server 127.0.0.1:{port_rmi};
}}

server {{
    listen 13100;
    proxy_pass ghidra_rmi_registry;
    proxy_timeout 10s;
    proxy_responses 1;
    proxy_connect_timeout 5s;
    error_log /var/log/nginx/ghidra_rmi_registry.log;
}}

upstream ghidra_rmi_ssl {{
    server 127.0.0.1:{port_ssl};
}}

server {{
    listen 13101;
    proxy_pass ghidra_rmi_ssl;
    proxy_timeout 10s;
    proxy_responses 1;
    proxy_connect_timeout 5s;
    error_log /var/log/nginx/ghidra_rmi_ssl.log;
}}

upstream ghidra_block_stream {{
    server 127.0.0.1:{port_stream};
}}

server {{
    listen 13102;
    proxy_pass ghidra_block_stream;
    proxy_timeout 10s;
    proxy_responses 1;
    proxy_connect_timeout 5s;
    error_log /var/log/nginx/ghidra_block_stream.log;
}}
"""

# Docker compose template
docker_compose_template = """
version: '3.8'
services:
  ghidra_server:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: ghidra_server
    restart: always
    ports:
      - "127.0.0.1:${GHIDRA_PORT_RMI}:13100"
      - "127.0.0.1:${GHIDRA_PORT_SSL}:13101"
      - "127.0.0.1:${GHIDRA_PORT_STREAM}:13102"
    volumes:
      - ghidra_repos:/repos
    environment:
      - GHIDRA_INSTALL_DIR=/ghidra
    healthcheck:
      test: ["CMD", "pgrep", "-f", "ghidraSvr"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    networks:
      - ghidra_network

networks:
  ghidra_network:
    driver: bridge

volumes:
  ghidra_repos: {}
"""

# Dockerfile template
dockerfile_template = """
FROM openjdk:21-jdk-slim

# Install required packages
RUN apt-get update && apt-get install -y \\
    wget \\
    unzip \\
    curl \\
    jq \\
    procps \\
    net-tools \\
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra
WORKDIR /tmp
RUN echo "Fetching latest Ghidra release..." \\
    && GHIDRA_URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | \\
       jq -r '.assets[] | select(.name | test("ghidra_.*_PUBLIC_.*\\\\.zip$")) | .browser_download_url') \\
    && echo "Downloading Ghidra from: $GHIDRA_URL" \\
    && wget -q "$GHIDRA_URL" -O ghidra.zip \\
    && unzip ghidra.zip \\
    && mv ghidra_*_PUBLIC /ghidra \\
    && rm -rf /tmp/*

# Set up Ghidra server
WORKDIR /ghidra/server
RUN mkdir -p /repos

# Copy Ghidra scripts
COPY ExportToGzf.java /ghidra/Ghidra/Features/Base/ghidra_scripts/ExportToGzf.java
COPY ListAndExportRepository.java /ghidra/Ghidra/Features/Base/ghidra_scripts/ListAndExportRepository.java

# Initialize the repository and install the server service
RUN ./svrInstall /repos

# Set Java to headless mode
ENV JAVA_OPTS="-Djava.awt.headless=true"

EXPOSE 13100 13101 13102
WORKDIR /ghidra/server
CMD ["./ghidraSvr", "console"]
"""

# .env template
env_template = """
GHIDRA_PORT_RMI={port_rmi}
GHIDRA_PORT_SSL={port_ssl}
GHIDRA_PORT_STREAM={port_stream}
GHIDRA_ADMIN_USER={admin_user}
GHIDRA_ADMIN_PASS={admin_pass}
"""

# Ghidra scripts
export_to_gzf_script = """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.app.util.exporter.GzfExporter;
import java.io.File;
public class ExportToGzf extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        // Get output path
        String outputPath;
        if (args.length > 0) {
            outputPath = args[0];
        } else {
            outputPath = "/tmp/ghidraProject.gzf";
        }

        // Get current program
        Program program = getCurrentProgram();
        if (program == null) {
            println("No program is currently open");
            return;
        }

        // Ensure parent directory exists
        File outputFile = new File(outputPath);
        File parentDir = outputFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        // Export program
        println("Exporting program: " + program.getName() + " to: " + outputPath);
        GzfExporter exporter = new GzfExporter();
        if (exporter.export(outputFile, program, null, monitor)) {
            println("Export completed successfully");
        } else {
            println("Export failed");
        }
    }
}
"""
list_and_export_script = """
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.app.util.exporter.GzfExporter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;
import java.util.ArrayList;
public class ListAndExportRepository extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        // Check args
        if (args.length < 1) {
            println("Usage: ListAndExportRepository <output_directory>");
            return;
        }

        // Get output directory
        String outputDir = args[0];
        File outputDirectory = new File(outputDir);
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        // Get project
        Project project = state.getProject();
        if (project == null) {
            println("No project available");
            return;
        }

        // Scan repository for programs
        println("Scanning repository for programs...");
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
        List<String> exportedPrograms = new ArrayList<>();
        exportFolder(rootFolder, outputDirectory, exportedPrograms, "");

        // Create manifest file
        File manifestFile = new File(outputDirectory, "backup_manifest.txt");
        try (PrintWriter writer = new PrintWriter(new FileWriter(manifestFile))) {
            writer.println("# Ghidra GZF Backup Manifest");
            writer.println("# Created: " + new java.util.Date());
            writer.println("# Repository: " + project.getName());
            writer.println();
            for (String program : exportedPrograms) {
                writer.println(program);
            }
        }
        println("Backup completed. Exported " + exportedPrograms.size() + " programs.");
        println("Manifest written to: " + manifestFile.getAbsolutePath());
    }

    private void exportFolder(DomainFolder folder, File outputDir, List<String> exportedPrograms, String path) throws Exception {
        DomainFile[] files = folder.getFiles();
        for (DomainFile file : files) {
            if (file.getContentType().equals("Program")) {

                // Process program folder
                String relativePath = path.isEmpty() ? file.getName() : path + "/" + file.getName();
                String safeName = relativePath.replace("/", "_").replace(" ", "_");
                println("Processing: " + relativePath);
                try {
                    Program program = (Program) file.getDomainObject(this, false, false, monitor);
                    if (program != null) {
                        File gzfFile = new File(outputDir, safeName + ".gzf");
                        GzfExporter exporter = new GzfExporter();
                        if (exporter.export(gzfFile, program, null, monitor)) {
                            exportedPrograms.add(relativePath + "|" + safeName + ".gzf");
                            println("  Exported: " + gzfFile.getName());
                        } else {
                            println("  FAILED to export: " + file.getName());
                        }
                        program.release(this);
                    }
                } catch (Exception e) {
                    println("  ERROR exporting " + file.getName() + ": " + e.getMessage());
                }
            }
        }

        // Process subfolders
        DomainFolder[] subfolders = folder.getSubfolders();
        for (DomainFolder subfolder : subfolders) {
            String subPath = path.isEmpty() ? subfolder.getName() : path + "/" + subfolder.getName();
            exportFolder(subfolder, outputDir, exportedPrograms, subPath);
        }
    }
}
"""

# Ghidra Installer
class Ghidra(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "ghidra_server"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.nginx_stream_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Ghidra", "ghidra_subdomain"),
            "port_rmi": self.config.GetValue("UserData.Ghidra", "ghidra_port_rmi"),
            "port_ssl": self.config.GetValue("UserData.Ghidra", "ghidra_port_ssl"),
            "port_stream": self.config.GetValue("UserData.Ghidra", "ghidra_port_stream")
        }
        self.env_values = {
            "port_rmi": self.config.GetValue("UserData.Ghidra", "ghidra_port_rmi"),
            "port_ssl": self.config.GetValue("UserData.Ghidra", "ghidra_port_ssl"),
            "port_stream": self.config.GetValue("UserData.Ghidra", "ghidra_port_stream"),
            "admin_user": self.config.GetValue("UserData.Ghidra", "ghidra_admin_user"),
            "admin_pass": self.config.GetValue("UserData.Ghidra", "ghidra_admin_pass")
        }

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def Install(self):

        # Create directories
        util.LogInfo("Creating directories")
        self.connection.MakeDirectory(self.app_dir)

        # Write Ghidra scripts
        util.LogInfo("Writing Ghidra scripts")
        if self.connection.WriteFile("/tmp/ExportToGzf.java", export_to_gzf_script):
            self.connection.MoveFileOrDirectory("/tmp/ExportToGzf.java", f"{self.app_dir}/ExportToGzf.java")
        if self.connection.WriteFile("/tmp/ListAndExportRepository.java", list_and_export_script):
            self.connection.MoveFileOrDirectory("/tmp/ListAndExportRepository.java", f"{self.app_dir}/ListAndExportRepository.java")

        # Write Dockerfile
        util.LogInfo("Writing Dockerfile")
        if self.connection.WriteFile("/tmp/Dockerfile", dockerfile_template):
            self.connection.MoveFileOrDirectory("/tmp/Dockerfile", f"{self.app_dir}/Dockerfile")

        # Write docker compose
        util.LogInfo("Writing docker compose")
        if self.connection.WriteFile("/tmp/docker-compose.yml", docker_compose_template):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.LogInfo("Writing docker env")
        if self.connection.WriteFile("/tmp/.env", env_template.format(**self.env_values)):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Create nginx stream entry
        util.LogInfo("Creating nginx stream entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_stream_config_template.format(**self.nginx_stream_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_stream_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_stream_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Open all three firewall ports
        util.LogInfo("Opening firewall ports for Ghidra")
        for port in ["13100", "13101", "13102"]:
            self.connection.RunChecked([self.nginx_manager_tool, "open_port", port], sudo = True)

        # Start docker
        util.LogInfo("Starting docker")
        self.connection.SetCurrentWorkingDirectory(self.app_dir)
        self.connection.SetEnvironmentVar("DOCKER_BUILDKIT", "1")
        self.connection.SetEnvironmentVar("COMPOSE_DOCKER_CLI_BUILD", "1")
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d", "--build"])
        return True

    def Uninstall(self):

        # Stop docker
        util.LogInfo("Stopping docker")
        self.connection.SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "down", "-v"])
        self.connection.SetCurrentWorkingDirectory(None)

        # Remove directory
        util.LogInfo("Removing directory")
        self.connection.RemoveFileOrDirectory(self.app_dir)

        # Remove nginx stream entry
        util.LogInfo("Removing nginx stream entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_stream_conf", f"{self.app_name}.conf"], sudo = True)

        # Close all firewall ports
        util.LogInfo("Closing firewall ports")
        for port in ["13100", "13101", "13102"]:
            self.connection.RunChecked([self.nginx_manager_tool, "close_port", port], sudo = True)
        return True
