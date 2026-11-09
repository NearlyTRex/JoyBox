# NocturneDecomp: only nocedit.exe's pseudocode is built, so the other programs'
# exports skip the header, function and static-analysis passes over it
no_pseudocode_checks = ["--no-header-compile", "--no-function-compile", "--no-static-analysis"]

# Decompiler presets
decompiler_presets = {
    "NocturneDecomp": {
        "description": "Nocturne game decompilation project",
        "repository": "NocturneDecomp",
        "project_dir": "projects",
        "project_name": "NocturneEdit",
        "program_name": "nocedit.exe",
        "project_language": "x86:LE:32:watcom",
        "project_cspec": "watcomcpp",
        "scripts": {
            "export_all": {
                "description": "Export all annotations for every program in the project to annotations/<program_name>, compiling only nocedit.exe's pseudocode",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "default_args": ["annotations/", "--all-programs", "--checks-only-for", "nocedit.exe"]
            },
            "export_nocedit": {
                "description": "Export all annotations for nocedit.exe only",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "nocedit.exe",
                "default_args": ["annotations/nocedit.exe"]
            },
            "export_nocturne": {
                "description": "Export all annotations for nocturne.exe only, without compiling the pseudocode",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "nocturne.exe",
                "default_args": ["annotations/nocturne.exe", *no_pseudocode_checks]
            },
            "export_tridx7": {
                "description": "Export all annotations for tridx7.dll only, without compiling the pseudocode",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "tridx7.dll",
                "default_args": ["annotations/tridx7.dll", *no_pseudocode_checks]
            },
            "export_bw1": {
                "description": "Export all annotations for bw1.exe only, without compiling the pseudocode",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "bw1.exe",
                "default_args": ["annotations/bw1.exe", *no_pseudocode_checks]
            },
            "export_blairwitch2": {
                "description": "Export all annotations for blairwitch2.exe only, without compiling the pseudocode",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "blairwitch2.exe",
                "default_args": ["annotations/blairwitch2.exe", *no_pseudocode_checks]
            },
            "export_bw3": {
                "description": "Export all annotations for bw3.exe only, without compiling the pseudocode",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "bw3.exe",
                "default_args": ["annotations/bw3.exe", *no_pseudocode_checks]
            },
            "import_annotations": {
                "description": "Import annotations from JSON files",
                "script_path": "scripts/Python",
                "script_name": "import_annotations.py",
                "default_args": ["annotations/nocedit.exe"]
            },
            "sync_annotations": {
                "description": "Sync annotations (import then export)",
                "script_path": "scripts/Python",
                "script_name": "sync_annotations.py",
                "default_args": ["annotations/nocedit.exe"]
            },
            "analyze_crt": {
                "description": "Analyze CRT functions for calling convention and signature issues",
                "script_path": "scripts/Python",
                "script_name": "analyze_crt_functions.py",
                "default_args": []
            }
        }
    }
}
