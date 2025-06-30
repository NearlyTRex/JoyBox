#!/bin/bash

set -euo pipefail

print_usage() {
    echo "Usage:"
    echo "  $0 add_user <container_name> <username> [password]"
    echo "  $0 remove_user <container_name> <username>"
    echo "  $0 list_users <container_name>"
    echo "  $0 reset_password <container_name> <username>"
    echo "  $0 create_repository <container_name> <repo_name>"
    echo "  $0 delete_repository <container_name> <repo_name>"
    echo "  $0 list_repositories <container_name>"
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

if [ $# -lt 2 ]; then
    print_usage
fi

case "$1" in
    add_user)
        if [ $# -lt 3 ] || [ $# -gt 4 ]; then
            echo "Usage: $0 add_user <container_name> <username> [password]"
            exit 1
        fi

        local container_name="$2"
        local username="$3"
        local password="${4:-}"

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
            if docker exec -it "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -add '$username'"; then
                echo "User '$username' added successfully."
            else
                echo "Error: Failed to add user '$username'. User may already exist."
                exit 1
            fi
        fi
        ;;

    remove_user)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 remove_user <container_name> <username>"
            exit 1
        fi

        local container_name="$2"
        local username="$3"

        check_container_exists "$container_name"
        check_container_running "$container_name"

        echo "Removing Ghidra user '$username' from container '$container_name'..."
        if docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -remove '$username'"; then
            echo "User '$username' removed successfully."
        else
            echo "Error: Failed to remove user '$username'. User may not exist."
            exit 1
        fi
        ;;

    list_users)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 list_users <container_name>"
            exit 1
        fi

        local container_name="$2"

        check_container_exists "$container_name"
        check_container_running "$container_name"

        echo "Ghidra users in container '$container_name':"
        docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -list" || echo "Error: Failed to list users."
        ;;

    reset_password)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 reset_password <container_name> <username>"
            exit 1
        fi

        local container_name="$2"
        local username="$3"

        check_container_exists "$container_name"
        check_container_running "$container_name"

        echo "Resetting password for Ghidra user '$username' in container '$container_name'..."
        if docker exec -it "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -reset '$username'"; then
            echo "Password reset for user '$username' completed successfully."
        else
            echo "Error: Failed to reset password for user '$username'."
            exit 1
        fi
        ;;

    create_repository)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 create_repository <container_name> <repo_name>"
            exit 1
        fi

        local container_name="$2"
        local repo_name="$3"

        check_container_exists "$container_name"
        check_container_running "$container_name"

        echo "Creating Ghidra repository '$repo_name' in container '$container_name'..."
        if docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -create '$repo_name'"; then
            echo "Repository '$repo_name' created successfully."
        else
            echo "Error: Failed to create repository '$repo_name'. Repository may already exist."
            exit 1
        fi
        ;;

    delete_repository)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 delete_repository <container_name> <repo_name>"
            exit 1
        fi

        local container_name="$2"
        local repo_name="$3"

        check_container_exists "$container_name"
        check_container_running "$container_name"

        echo "Deleting Ghidra repository '$repo_name' from container '$container_name'..."
        echo "WARNING: This will permanently delete all data in the repository!"
        if docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -delete '$repo_name'"; then
            echo "Repository '$repo_name' deleted successfully."
        else
            echo "Error: Failed to delete repository '$repo_name'. Repository may not exist."
            exit 1
        fi
        ;;

    list_repositories)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 list_repositories <container_name>"
            exit 1
        fi

        local container_name="$2"

        check_container_exists "$container_name"
        check_container_running "$container_name"

        echo "Ghidra repositories in container '$container_name':"
        docker exec "$container_name" /bin/bash -c "cd /ghidra/server && ./svrAdmin -list-repos" || echo "Error: Failed to list repositories."
        ;;

    *)
        echo "Error: Invalid operation '$1'."
        print_usage
        ;;
esac
