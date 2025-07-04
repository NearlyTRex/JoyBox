#!/bin/bash

set -euo pipefail

DEFAULT_BACKUP_DIR="/mnt/storage/Backups/Ghidra"
BACKUP_DIR="$DEFAULT_BACKUP_DIR"

print_usage() {
    echo "Usage:"
    echo "  $0 [--backup-dir <path>] add_user <container_name> <username> [password]"
    echo "  $0 [--backup-dir <path>] remove_user <container_name> <username>"
    echo "  $0 [--backup-dir <path>] list_users <container_name>"
    echo "  $0 [--backup-dir <path>] reset_password <container_name> <username>"
    echo "  $0 [--backup-dir <path>] grant_repository_access <container_name> <username> <repository_name> [+r|+w|+a]"
    echo "  $0 [--backup-dir <path>] revoke_repository_access <container_name> <username> <repository_name>"
    echo "  $0 [--backup-dir <path>] list_repositories <container_name>"
    echo "  $0 [--backup-dir <path>] check_server_status <container_name>"
    echo "  $0 [--backup-dir <path>] backup_repositories <container_name>"
    echo "  $0 [--backup-dir <path>] restore_repositories <container_name> <repo_name> <backup_name>"
    echo "  $0 [--backup-dir <path>] export_program_gzf <container_name> <project_name> <program_name> [output_path]"
    echo ""
    echo "Options:"
    echo "  --backup-dir <path>    Specify backup directory (default: $DEFAULT_BACKUP_DIR)"
    echo ""
    echo "Notes:"
    echo "  - Repositories are created by connecting with Ghidra GUI client, not via command line"
    echo "  - Repository access permissions: +r (read), +w (write), +a (admin)"
    exit 1
}

check_directory_traversal() {
    local filename="$1"
    if [[ "$filename" == *".."* || "$filename" == */* ]]; then
        echo "Error: Directory traversal or path separators are not allowed in filename."
        exit 1
    fi
}

check_container_exists() {
    local container_name="$1"
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
        echo "Error: Container '$container_name' does not exist."
        exit 1
    fi
}

check_container_running() {
    local container_name="$1"
    if ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        echo "Error: Container '$container_name' is not running."
        exit 1
    fi
}

check_storage_mount() {
    local storage_path="$(dirname "$BACKUP_DIR")"
    if ! mountpoint -q "$storage_path" 2>/dev/null; then
        echo "Warning: Storage path '$storage_path' may not be mounted."
    fi

    if [ ! -w "$(dirname "$BACKUP_DIR")" ]; then
        echo "Error: Parent directory of backup path '$BACKUP_DIR' is not writable."
        exit 1
    fi
}

create_backup_directory() {
    if [ ! -d "$BACKUP_DIR" ]; then
        echo "Creating backup directory at $BACKUP_DIR..."
        mkdir -p "$BACKUP_DIR"
    fi
    echo "$BACKUP_DIR"
}

check_server_status() {
    local container_name="$1"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Checking Ghidra server status in container '$container_name'..."

    if docker exec "$container_name" pgrep -f "ghidraSvr" > /dev/null 2>&1; then
        echo "Ghidra server process is running"
    else
        echo "Ghidra server process is not running"
        return 1
    fi

    if docker exec "$container_name" netstat -tlnp 2>/dev/null | grep -q ":13100"; then
        echo "Server is listening on port 13100 (RMI Registry)"
    else
        echo "Server is not listening on port 13100"
        return 1
    fi

    if docker exec "$container_name" netstat -tlnp 2>/dev/null | grep -q ":13101"; then
        echo "Server is listening on port 13101 (RMI SSL)"
    else
        echo "Server is not listening on port 13101"
        return 1
    fi

    if docker exec "$container_name" netstat -tlnp 2>/dev/null | grep -q ":13102"; then
        echo "Server is listening on port 13102 (Block Stream)"
    else
        echo "Server is not listening on port 13102"
        return 1
    fi

    echo "Ghidra server appears to be running correctly"
    return 0
}

add_user() {
    local container_name="$1"
    local username="$2"
    local password="${3:-}"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Adding Ghidra user '$username' to container '$container_name'..."

    if [ -n "$password" ]; then
        if docker exec "$container_name" /bin/bash -c "cd /ghidra/server && echo '$password' | ./svrAdmin -add '$username'"; then
            echo "User '$username' added successfully."
        else
            echo "Error: Failed to add user '$username'. User may already exist or password was rejected."
            exit 1
        fi
    else
        if docker exec -it "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -add '$username' --p"; then
            echo "User '$username' added successfully."
        else
            echo "Error: Failed to add user '$username'. User may already exist."
            exit 1
        fi
    fi
}

remove_user() {
    local container_name="$1"
    local username="$2"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Removing Ghidra user '$username' from container '$container_name'..."
    if docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -remove '$username'"; then
        echo "User '$username' removed successfully."
    else
        echo "Error: Failed to remove user '$username'. User may not exist."
        exit 1
    fi
}

list_users() {
    local container_name="$1"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Ghidra users in container '$container_name':"
    docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -users" || echo "Error: Failed to list users."
}

reset_password() {
    local container_name="$1"
    local username="$2"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Resetting password for Ghidra user '$username' in container '$container_name'..."
    if docker exec -it "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -reset '$username' --p"; then
        echo "Password reset for user '$username' completed successfully."
    else
        echo "Error: Failed to reset password for user '$username'."
        exit 1
    fi
}

grant_repository_access() {
    local container_name="$1"
    local username="$2"
    local repository_name="$3"
    local permission="${4:-+w}"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Granting '$permission' access to repository '$repository_name' for user '$username'..."
    if docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -grant '$username' '$permission' '$repository_name'"; then
        echo "Access granted successfully."
    else
        echo "Error: Failed to grant access. User or repository may not exist."
        exit 1
    fi
}

revoke_repository_access() {
    local container_name="$1"
    local username="$2"
    local repository_name="$3"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Revoking access to repository '$repository_name' for user '$username'..."
    if docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -revoke '$username' '$repository_name'"; then
        echo "Access revoked successfully."
    else
        echo "Error: Failed to revoke access. User or repository may not exist."
        exit 1
    fi
}

list_repositories() {
    local container_name="$1"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    echo "Ghidra repositories in container '$container_name':"
    docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -list" || echo "Error: Failed to list repositories."
}

backup_repositories() {
    local container_name="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local total_exported=0
    local repo_count=0

    check_container_exists "$container_name"
    check_container_running "$container_name"
    check_storage_mount

    echo "Creating GZF backup for container '$container_name'..."
    local backup_base_dir
    backup_base_dir=$(create_backup_directory)

    echo "Getting list of repositories..."
    local repositories
    repositories=$(docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -list" 2>/dev/null | grep -v "^$" | grep -v "Repositories:" | grep -v "<No repositories" || true)
    if [ -z "$repositories" ]; then
        echo "No repositories found to backup."
        return 0
    fi

    echo "Found repositories: $repositories"
    echo "Backup timestamp: $timestamp"
    while IFS= read -r repo; do
        if [ -n "$repo" ] && [ "$repo" != "Repositories:" ]; then
            echo "Processing repository: $repo"
            ((repo_count++))

            local repo_backup_dir="$backup_base_dir/$repo/$timestamp"
            mkdir -p "$repo_backup_dir"

            local backup_manifest="$repo_backup_dir/backup_manifest.txt"
            echo "# Ghidra GZF Backup Manifest" > "$backup_manifest"
            echo "# Created: $(date)" >> "$backup_manifest"
            echo "# Container: $container_name" >> "$backup_manifest"
            echo "# Repository: $repo" >> "$backup_manifest"
            echo "# Timestamp: $timestamp" >> "$backup_manifest"
            echo "" >> "$backup_manifest"

            echo "Exporting programs from repository '$repo'..."
            local temp_project_dir="/tmp/ghidra_backup_$$"
            if docker exec "$container_name" /ghidra/support/analyzeHeadless \
                "$temp_project_dir" "TempBackup_$repo" \
                -connect "localhost:13100" \
                -repository "$repo" \
                -scriptPath /ghidra/Ghidra/Features/Base/ghidra_scripts \
                -postScript ListAndExportRepository.java "/tmp/repo_$repo" \
                -deleteProject 2>/dev/null; then

                local container_export_dir="/tmp/repo_$repo"
                docker exec "$container_name" test -d "$container_export_dir" || continue
                if docker exec "$container_name" find "$container_export_dir" -name "*.gzf" -type f | grep -q .; then
                    docker exec "$container_name" find "$container_export_dir" -name "*.gzf" -exec basename {} \; | while read -r gzf_file; do
                        docker cp "$container_name:$container_export_dir/$gzf_file" "$repo_backup_dir/$gzf_file"
                        echo "$gzf_file" >> "$backup_manifest"
                    done

                    local repo_exported
                    repo_exported=$(docker exec "$container_name" find "$container_export_dir" -name "*.gzf" | wc -l)
                    total_exported=$((total_exported + repo_exported))
                    echo "Exported $repo_exported programs"
                    echo "$repo_backup_dir"
                else
                    echo "No programs found in repository '$repo'"
                    rmdir "$repo_backup_dir" 2>/dev/null || true
                    rmdir "$backup_base_dir/$repo" 2>/dev/null || true
                fi
                docker exec "$container_name" rm -rf "$container_export_dir" 2>/dev/null || true
            else
                echo "Warning: Failed to process repository '$repo'"
                rmdir "$repo_backup_dir" 2>/dev/null || true
                rmdir "$backup_base_dir/$repo" 2>/dev/null || true
            fi
            docker exec "$container_name" rm -rf "$temp_project_dir" 2>/dev/null || true
        fi
    done <<< "$repositories"

    echo "Backup completed successfully!"
    echo "Programs exported: $total_exported"
    echo "Repositories: $repo_count"
    echo "Backup timestamp: $timestamp"
    echo "Base location: $backup_base_dir"
    if [ $total_exported -eq 0 ]; then
        echo "Warning: No programs were exported. Check if repositories contain any programs."
    fi
}

restore_repositories() {
    local container_name="$1"
    local repo_name="$2"
    local backup_name="$3"
    local backup_path="$BACKUP_DIR/$repo_name/$backup_name"

    check_container_exists "$container_name"
    check_container_running "$container_name"

    if [ ! -d "$backup_path" ]; then
        echo "Error: Backup '$backup_name' for repository '$repo_name' does not exist at $backup_path"
        echo "Available backups for repository '$repo_name':"
        local repo_backup_dir="$BACKUP_DIR/$repo_name"
        if [ -d "$repo_backup_dir" ]; then
            ls -la "$repo_backup_dir/" | grep "^d" | awk '{print $9}' | grep -v "^\.$" | grep -v "^\.\.$" || echo "  No backups found"
        else
            echo "Repository backup directory does not exist"
            echo "Available repositories:"
            if [ -d "$BACKUP_DIR" ]; then
                ls -la "$BACKUP_DIR/" | grep "^d" | awk '{print $9}' | grep -v "^\.$" | grep -v "^\.\.$" || echo "  No repositories found"
            fi
        fi
        exit 1
    fi

    echo "Restoring backup from: $backup_path"
    echo "Target repository: $repo_name"
    local backup_manifest="$backup_path/backup_manifest.txt"
    if [ -f "$backup_manifest" ]; then
        echo "Backup manifest found:"
        head -10 "$backup_manifest"
    fi

    echo "WARNING: This will import programs into repository '$repo_name'."
    echo "The repository must already exist and you must have access to it."
    echo "Existing programs with the same name may be overwritten."
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Restore cancelled."
        exit 0
    fi

    echo "Restoring backup..."
    if ! ls "$backup_path"/*.gzf 1> /dev/null 2>&1; then
        echo "No .gzf files found in backup directory."
        exit 1
    fi

    local total_imported=0
    local failed_imports=0
    for gzf_file in "$backup_path"/*.gzf; do
        if [ -f "$gzf_file" ]; then
            local program_name
            program_name=$(basename "$gzf_file" .gzf)

            echo "Importing: $program_name into repository $repo_name"
            local container_gzf="/tmp/restore_$(basename "$gzf_file")"
            if docker cp "$gzf_file" "$container_name:$container_gzf"; then

                local temp_project_dir="/tmp/ghidra_restore_$$"
                if docker exec "$container_name" /ghidra/support/analyzeHeadless \
                    "$temp_project_dir" "TempRestore" \
                    -connect "localhost:13100" \
                    -repository "$repo_name" \
                    -import "$container_gzf" \
                    -deleteProject >/dev/null 2>&1; then
                    echo "Successfully imported $program_name"
                    ((total_imported++))
                else
                    echo "Failed to import $program_name"
                    ((failed_imports++))
                fi
                docker exec "$container_name" rm -f "$container_gzf" 2>/dev/null || true
                docker exec "$container_name" rm -rf "$temp_project_dir" 2>/dev/null || true
            else
                echo "Failed to copy $program_name to container"
                ((failed_imports++))
            fi
        fi
    done

    echo "Restore completed!"
    echo "Programs imported: $total_imported"
    if [ $failed_imports -gt 0 ]; then
        echo "Failed imports: $failed_imports"
    fi
    echo "Repository: $repo_name"
    echo "Backup restored: $backup_name"
    echo "Note: Users may need to reconnect to see newly imported programs."
}

export_program_gzf() {
    local container_name="$1"
    local project_name="$2"
    local program_name="$3"
    local output_path="${4:-/tmp/${program_name}.gzf}"

    check_container_exists "$container_name"

    echo "Running headless export..."
    temp_project_dir="/tmp/ghidra_projects"
    temp_output="/tmp/export_${program_name}_$(date +%s).gzf"
    if docker exec "$container_name" /ghidra/support/analyzeHeadless \
        "$temp_project_dir" "TempExport" \
        -import "/repos/$project_name/$program_name" \
        -scriptPath /ghidra/Ghidra/Features/Base/ghidra_scripts \
        -postScript ExportToGzf.java "$temp_output" \
        -deleteProject; then
        if docker cp "$container_name:$temp_output" "$output_path"; then
            echo "Program exported successfully to: $output_path"
            docker exec "$container_name" rm -f "$temp_output" 2>/dev/null || true
        else
            echo "Error: Failed to copy exported file from container"
            exit 1
        fi
    else
        echo "Error: Headless export failed"
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --backup-dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --help)
            print_usage
            ;;
        *)
            break
            ;;
    esac
done

if [ $# -lt 1 ]; then
    print_usage
fi

case "$1" in
    add_user)
        if [ $# -lt 3 ] || [ $# -gt 4 ]; then
            echo "Usage: $0 add_user <container_name> <username> [password]"
            exit 1
        fi
        add_user "${@:2}"
        ;;

    remove_user)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 remove_user <container_name> <username>"
            exit 1
        fi
        remove_user "${@:2}"
        ;;

    list_users)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 list_users <container_name>"
            exit 1
        fi
        list_users "${@:2}"
        ;;

    reset_password)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 reset_password <container_name> <username>"
            exit 1
        fi
        reset_password "${@:2}"
        ;;

    grant_repository_access)
        if [ $# -lt 4 ] || [ $# -gt 5 ]; then
            echo "Usage: $0 grant_repository_access <container_name> <username> <repository_name> [+r|+w|+a]"
            exit 1
        fi
        grant_repository_access "${@:2}"
        ;;

    revoke_repository_access)
        if [ $# -ne 4 ]; then
            echo "Usage: $0 revoke_repository_access <container_name> <username> <repository_name>"
            exit 1
        fi
        revoke_repository_access "${@:2}"
        ;;

    list_repositories)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 list_repositories <container_name>"
            exit 1
        fi
        list_repositories "${@:2}"
        ;;

    check_server_status)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 check_server_status <container_name>"
            exit 1
        fi
        check_server_status "${@:2}"
        ;;

    backup_repositories)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 backup_repositories <container_name>"
            exit 1
        fi
        backup_repositories "${@:2}"
        ;;

    restore_repositories)
        if [ $# -ne 4 ]; then
            echo "Usage: $0 restore_repositories <container_name> <repo_name> <backup_name>"
            exit 1
        fi
        restore_repositories "${@:2}"
        ;;

    export_program_gzf)
        if [ $# -lt 4 ] || [ $# -gt 5 ]; then
            echo "Usage: $0 export_program_gzf <container_name> <project_name> <program_name> [output_path]"
            exit 1
        fi
        export_program_gzf "${@:2}"
        ;;

    *)
        echo "Error: Invalid operation '$1'."
        print_usage
        ;;
esac
