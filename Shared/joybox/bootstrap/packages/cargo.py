# Local imports
import joybox.bootstrap.constants as constants
###########################################################
# Cargo (crates installed with cargo install)
###########################################################
cargo = {}
cargo[constants.EnvironmentType.LOCAL_UBUNTU] = []
cargo[constants.EnvironmentType.LOCAL_WINDOWS] = []
cargo[constants.EnvironmentType.REMOTE_UBUNTU] = []
cargo[constants.EnvironmentType.REMOTE_WINDOWS] = []

###########################################################
# Cargo - Local Ubuntu
###########################################################
cargo[constants.EnvironmentType.LOCAL_UBUNTU] += [

    # Devel
    {"id": "cargo-xwin", "name": "cargo-xwin", "description": "Cross-compiles to the MSVC target with clang and lld", "category": "Devel"},
    {"id": "xwin", "name": "xwin", "description": "Downloads the MSVC CRT and Windows SDK for cross-compiling", "category": "Devel"},
]

###########################################################
# Rust targets (added with rustup target add)
###########################################################
rust_targets = {}
rust_targets[constants.EnvironmentType.LOCAL_UBUNTU] = []
rust_targets[constants.EnvironmentType.LOCAL_WINDOWS] = []
rust_targets[constants.EnvironmentType.REMOTE_UBUNTU] = []
rust_targets[constants.EnvironmentType.REMOTE_WINDOWS] = []

###########################################################
# Rust targets - Local Ubuntu
###########################################################
rust_targets[constants.EnvironmentType.LOCAL_UBUNTU] += [
    {"id": "x86_64-pc-windows-msvc", "name": "Windows MSVC (x86_64)", "description": "Windows target built with cargo xwin", "category": "Devel"},
]
