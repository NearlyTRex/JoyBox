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
            "export_all": {
                "description": "Export all annotations to JSON files",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe"]
            },
            "export_pseudocode": {
                "description": "Export decompiled pseudocode only",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe", "pseudocode"]
            },
            "export_data_types": {
                "description": "Export data type definitions only",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe", "data_types"]
            },
            "export_functions": {
                "description": "Export function signatures only",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe", "functions"]
            },
            "export_symbols": {
                "description": "Export all symbol types",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe", "symbols_class,symbols_label,symbols_namespace"]
            },
            "export_applied": {
                "description": "Export all applied type annotations",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe", "applied_arrays,applied_basic_types,applied_enums,applied_pointers,applied_strings,applied_structs,applied_unions"]
            },
            "export_metadata": {
                "description": "Export metadata, memory layout, and entry points",
                "script_path": "scripts/Jython",
                "script_name": "export_annotations_headless.py",
                "default_args": ["annotations/nocedit.exe", "metadata,memory_layout,entry_points"]
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
