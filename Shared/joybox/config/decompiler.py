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
                "description": "Export all annotations for every program in the project to annotations/<program_name>",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "default_args": ["annotations/", "--all-programs"]
            },
            "export_nocedit": {
                "description": "Export all annotations for nocedit.exe only",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "nocedit.exe",
                "default_args": ["annotations/nocedit.exe"]
            },
            "export_nocturne": {
                "description": "Export all annotations for nocturne.exe only",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "nocturne.exe",
                "default_args": ["annotations/nocturne.exe"]
            },
            "export_tridx7": {
                "description": "Export all annotations for tridx7.dll only",
                "script_path": "scripts/Python",
                "script_name": "export_annotations.py",
                "program_name": "tridx7.dll",
                "default_args": ["annotations/tridx7.dll"]
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
