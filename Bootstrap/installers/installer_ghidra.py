# Imports
import os
import sys
import secrets
import string

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
      - ./certs:/certs:ro
    environment:
      - GHIDRA_INSTALL_DIR=/ghidra
      - GHIDRA_DOMAIN=${GHIDRA_DOMAIN}
      - GHIDRA_KEYSTORE_PATH=/repos/ghidra.keystore
      - GHIDRA_KEYSTORE_PASSWORD_FILE=/certs/keystore_password.txt
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
    openssl \\
    ca-certificates \\
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

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Initialize the repository and install the server service
RUN ./svrInstall /repos

# Set Java to headless mode
ENV JAVA_OPTS="-Djava.awt.headless=true"

EXPOSE 13100 13101 13102
WORKDIR /ghidra/server
ENTRYPOINT ["/entrypoint.sh"]
CMD ["./ghidraSvr", "console"]
"""

# .env template
env_template = """
GHIDRA_PORT_RMI={port_rmi}
GHIDRA_PORT_SSL={port_ssl}
GHIDRA_PORT_STREAM={port_stream}
GHIDRA_ADMIN_USER={admin_user}
GHIDRA_ADMIN_PASS={admin_pass}
GHIDRA_DOMAIN={domain}
"""

# Entrypoint script
entrypoint_script = """#!/bin/bash
set -euo pipefail

configure_ssl_keystore() {
    local domain="$1"
    echo "Configuring SSL keystore for domain: $domain"
    local source_keystore="/certs/ghidra-keystore.p12"
    local target_keystore="/repos/ghidra.keystore"
    local keystore_pass_file="/certs/keystore_password.txt"
    if [ -f "$source_keystore" ] && [ -f "$keystore_pass_file" ]; then
        echo "Found pre-exported keystore at $source_keystore"
        local keystore_pass=$(cat "$keystore_pass_file")

        echo "Copying keystore to repository directory..."
        cp "$source_keystore" "$target_keystore"
        chmod 600 "$target_keystore"

        echo "Keystore verification:"
        keytool -list -keystore "$target_keystore" -storetype PKCS12 -storepass "$keystore_pass" | grep "Alias name" || echo "Keystore verified"

        echo "Configuring SSL in Ghidra server.conf..."
        local server_conf="/ghidra/server/server.conf"
        sed -i "s|^ghidra.repositories.dir=.*|ghidra.repositories.dir=/repos|" "$server_conf"
        sed -i "s|^#wrapper.java.additional.9=-Dghidra.keystore=.*|wrapper.java.additional.9=-Dghidra.keystore=$target_keystore|" "$server_conf"
        sed -i "s|^#wrapper.java.additional.10=-Dghidra.password=.*|wrapper.java.additional.10=-Dghidra.password=$keystore_pass|" "$server_conf"
        if ! grep -q "wrapper.java.additional.9=" "$server_conf"; then
            # Find line with wrapper.java.additional.8 and add our properties after it
            sed -i '/wrapper\.java\.additional\.8=/a\\nwrapper.java.additional.9=-Dghidra.keystore='$target_keystore'' "$server_conf"
            sed -i '/wrapper\.java\.additional\.9=/a\wrapper.java.additional.10=-Dghidra.password='$keystore_pass'' "$server_conf"
        fi
        sed -i 's/^#wrapper\.java\.additional\.9=/wrapper.java.additional.9=/' "$server_conf"
        sed -i 's/^#wrapper\.java\.additional\.10=/wrapper.java.additional.10=/' "$server_conf"

        echo "Setting RMI server hostname to: ghidra.$domain"
        local highest_additional=$(grep -o "wrapper\.java\.additional\.[0-9]\+" "$server_conf" | sed 's/wrapper\.java\.additional\.//' | sort -n | tail -1)
        local next_num=$((highest_additional + 1))
        echo "wrapper.java.additional.$next_num=-Djava.rmi.server.hostname=ghidra.$domain" >> "$server_conf"

        echo "Enabling user ID prompting..."
        sed -i '/wrapper\.app\.parameter\.2=/i\wrapper.app.parameter.2=-u' "$server_conf"
        sed -i 's/wrapper\.app\.parameter\.2=${ghidra\.repositories\.dir}/wrapper.app.parameter.3=${ghidra.repositories.dir}/' "$server_conf"

        echo "Verifying keystore accessibility..."
        if keytool -list -keystore "$target_keystore" -storetype PKCS12 -storepass "$keystore_pass" > /dev/null 2>&1; then
            echo "Keystore verification successful"
        else
            echo "WARNING: Keystore verification failed"
        fi

        echo "SSL keystore configuration completed successfully"
        echo "Keystore location: $target_keystore"
        echo "RMI hostname set to: ghidra.$domain"
        echo "User prompting enabled: -u flag added"
        echo "Configuration file: $server_conf"
        return 0
    else
        echo "Pre-exported keystore not found. SSL will use Ghidra's default configuration."
        echo "Expected keystore: $source_keystore"
        echo "Expected password file: $keystore_pass_file"

        local server_conf="/ghidra/server/server.conf"
        sed -i "s|^ghidra.repositories.dir=.*|ghidra.repositories.dir=/repos|" "$server_conf"

        local highest_additional=$(grep -o "wrapper\.java\.additional\.[0-9]\+" "$server_conf" | sed 's/wrapper\.java\.additional\.//' | sort -n | tail -1)
        local next_num=$((highest_additional + 1))
        echo "wrapper.java.additional.$next_num=-Djava.rmi.server.hostname=ghidra.$domain" >> "$server_conf"
        sed -i '/wrapper\.app\.parameter\.2=/i\wrapper.app.parameter.2=-u' "$server_conf"
        sed -i 's/wrapper\.app\.parameter\.2=${ghidra\.repositories\.dir}/wrapper.app.parameter.3=${ghidra.repositories.dir}/' "$server_conf"

        echo "RMI hostname set to: ghidra.$domain (no SSL)"
        return 1
    fi
}

sleep 2
chmod 755 /repos
chown -R root:root /repos

echo "Starting Ghidra Server initialization..."
if [ -n "${GHIDRA_DOMAIN:-}" ]; then
    echo "Configuring for domain: $GHIDRA_DOMAIN"
    if configure_ssl_keystore "$GHIDRA_DOMAIN"; then
        echo "SSL configuration completed successfully"
    else
        echo "SSL configuration failed, using default Ghidra SSL settings"
    fi
else
    echo "No GHIDRA_DOMAIN set, using default Ghidra configuration"
    local server_conf="/ghidra/server/server.conf"
    sed -i "s|^ghidra.repositories.dir=.*|ghidra.repositories.dir=/repos|" "$server_conf"
    sed -i '/wrapper\.app\.parameter\.2=/i\wrapper.app.parameter.2=-u' "$server_conf"
    sed -i 's/wrapper\.app\.parameter\.2=${ghidra\.repositories\.dir}/wrapper.app.parameter.3=${ghidra.repositories.dir}/' "$server_conf"
    echo "User prompting enabled: -u flag added"
fi

echo "Starting Ghidra Server..."
exec "$@"
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
        self.app_domain = self.config.get_value("UserData.Servers", "domain_name")
        self.nginx_stream_config_values = {
            "domain": self.config.get_value("UserData.Servers", "domain_name"),
            "subdomain": self.config.get_value("UserData.Ghidra", "ghidra_subdomain"),
            "port_rmi": self.config.get_value("UserData.Ghidra", "ghidra_port_rmi"),
            "port_ssl": self.config.get_value("UserData.Ghidra", "ghidra_port_ssl"),
            "port_stream": self.config.get_value("UserData.Ghidra", "ghidra_port_stream")
        }
        self.env_values = {
            "domain": self.config.get_value("UserData.Servers", "domain_name"),
            "port_rmi": self.config.get_value("UserData.Ghidra", "ghidra_port_rmi"),
            "port_ssl": self.config.get_value("UserData.Ghidra", "ghidra_port_ssl"),
            "port_stream": self.config.get_value("UserData.Ghidra", "ghidra_port_stream"),
            "admin_user": self.config.get_value("UserData.Ghidra", "ghidra_admin_user"),
            "admin_pass": self.config.get_value("UserData.Ghidra", "ghidra_admin_pass")
        }

    def is_installed(self):
        containers = self.connection.run_output("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def install(self):

        # Create directories
        util.log_info("Creating directories")
        self.connection.make_directory(self.app_dir)
        self.connection.make_directory(f"{self.app_dir}/certs")

        # Generate keystore password
        util.log_info("Generate keystore password")
        keystore_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        keystore_password_file = f"{self.app_dir}/certs/keystore_password.txt"
        if self.connection.write_file("/tmp/keystore_password.txt", keystore_password):
            self.connection.move_file_or_directory("/tmp/keystore_password.txt", keystore_password_file)
            self.connection.change_permission(keystore_password_file, "644")

        # Export SSL keystore from certbot
        util.log_info("Exporting SSL keystore from certbot")
        self.connection.run_checked([
            self.cert_manager_tool,
            "export_keystore",
            self.app_domain,
            f"{self.app_dir}/certs/ghidra-keystore.p12",
            keystore_password,
            "ghidra",
            "p12",
            "644"
        ], sudo = True)

        # Write entrypoint script
        util.log_info("Writing entrypoint script")
        if self.connection.write_file("/tmp/entrypoint.sh", entrypoint_script):
            self.connection.move_file_or_directory("/tmp/entrypoint.sh", f"{self.app_dir}/entrypoint.sh")

        # Write Ghidra scripts
        util.log_info("Writing Ghidra scripts")
        if self.connection.write_file("/tmp/ExportToGzf.java", export_to_gzf_script):
            self.connection.move_file_or_directory("/tmp/ExportToGzf.java", f"{self.app_dir}/ExportToGzf.java")
        if self.connection.write_file("/tmp/ListAndExportRepository.java", list_and_export_script):
            self.connection.move_file_or_directory("/tmp/ListAndExportRepository.java", f"{self.app_dir}/ListAndExportRepository.java")

        # Write Dockerfile
        util.log_info("Writing Dockerfile")
        if self.connection.write_file("/tmp/Dockerfile", dockerfile_template):
            self.connection.move_file_or_directory("/tmp/Dockerfile", f"{self.app_dir}/Dockerfile")

        # Write docker compose
        util.log_info("Writing docker compose")
        if self.connection.write_file("/tmp/docker-compose.yml", docker_compose_template):
            self.connection.move_file_or_directory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.log_info("Writing docker env")
        if self.connection.write_file("/tmp/.env", env_template.format(**self.env_values)):
            self.connection.move_file_or_directory("/tmp/.env", f"{self.app_dir}/.env")

        # Create nginx stream entry
        util.log_info("Creating nginx stream entry")
        if self.connection.write_file(f"/tmp/{self.app_name}.conf", nginx_stream_config_template.format(**self.nginx_stream_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_stream_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_stream_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.remove_file_or_directory(f"/tmp/{self.app_name}.conf")

        # Open all three firewall ports
        util.log_info("Opening firewall ports for Ghidra")
        for port in ["13100", "13101", "13102"]:
            self.connection.run_checked([self.nginx_manager_tool, "open_port", port], sudo = True)

        # Start docker
        util.log_info("Starting docker")
        self.connection.set_current_working_directory(self.app_dir)
        self.connection.set_environmentVar("DOCKER_BUILDKIT", "1")
        self.connection.set_environmentVar("COMPOSE_DOCKER_CLI_BUILD", "1")
        self.connection.run_checked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d", "--build"])
        return True

    def uninstall(self):

        # Stop docker
        util.log_info("Stopping docker")
        self.connection.set_current_working_directory(self.app_dir)
        self.connection.run_checked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "down", "-v"])
        self.connection.set_current_working_directory(None)

        # Remove directory
        util.log_info("Removing directory")
        self.connection.remove_file_or_directory(self.app_dir)

        # Remove nginx stream entry
        util.log_info("Removing nginx stream entry")
        self.connection.run_checked([self.nginx_manager_tool, "remove_stream_conf", f"{self.app_name}.conf"], sudo = True)

        # Close all firewall ports
        util.log_info("Closing firewall ports")
        for port in ["13100", "13101", "13102"]:
            self.connection.run_checked([self.nginx_manager_tool, "close_port", port], sudo = True)
        return True
