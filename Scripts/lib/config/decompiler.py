# Imports
import os
import sys

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
            "export_annotations": {
                "description": "Export all annotations to JSON files",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe"]
            },
            "import_annotations": {
                "description": "Import annotations from JSON files",
                "script_path": "scripts/Jython",
                "script_name": "import_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe"]
            }
        }
    }
}
