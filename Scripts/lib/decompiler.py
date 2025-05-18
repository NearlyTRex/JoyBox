# Imports
import os
import sys
import json
import time

# Local imports
import config
import system
import environment
import programs

# Function code template
function_code_template = """
// Name: {func_name}
// Address: {func_addr}
// Address Range: {func_addr_range}
// Convention: {func_convention}
// Signature: {func_signature}

{func_decomp_code}

// Assembly code:
{func_asm_code}
"""

class ProjectOptions:
    def __init__(
        self,
        project_name,
        project_dir,
        project_language,
        project_cspec,
        program_name,
        program_binary_file):
        self.project_name = project_name
        self.project_dir = project_dir
        self.project_language = project_language
        self.project_cspec = project_cspec
        self.program_name = program_name
        self.program_binary_file = program_binary_file

    def GetProjectName(self):
        return self.project_name

    def GetProjectLanguage(self):
        return self.project_language

    def GetProjectCompilerSpec(self):
        return self.project_cspec

    def GetProjectDir(self):
        return os.path.abspath(self.project_dir)

    def GetProgramName(self):
        return self.program_name

    def GetProgramBinaryFile(self):
        return os.path.abspath(self.program_binary_file)

class DecompilerProject:
    def __init__(self, options):
        self.options = options
        self.api = None
        self._ctx = None

        # Import pyghidra
        self.pyghidra = environment.ImportPythonModulePackage(
            module_path = programs.GetToolPathConfigValue("Ghidra", "package_dir"),
            module_name = programs.GetToolConfigValue("Ghidra", "package_name"))
        self.pyghidra.start(install_dir = programs.GetLibraryInstallDir("Ghidra", "lib"))

    def __enter__(self):
        self._ctx = self.pyghidra.open_program(
            binary_path = self.options.GetProgramBinaryFile(),
            project_location = self.options.GetProjectDir(),
            project_name = self.options.GetProjectName(),
            analyze = True,
            language = self.options.GetProjectLanguage(),
            compiler = self.options.GetProjectCompilerSpec(),
            program_name = self.options.GetProgramName())
        self.api = self._ctx.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._ctx.__exit__(exc_type, exc_value, traceback)

    def ExportFunctions(
        self,
        export_dir,
        timeout = 60,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Imports
        from ghidra.app.decompiler import DecompInterface
        from ghidra.app.decompiler import DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor

        # Initialize decompiler
        interface = DecompInterface()
        interface.setOptions(DecompileOptions())
        interface.openProgram(self.api.currentProgram)

        # Read functions
        function_manager = self.api.currentProgram.getFunctionManager()
        program_listing = self.api.currentProgram.getListing()
        for func in function_manager.getFunctions(True):

            # Get basic info
            func_name = func.getName()
            func_addr = str(func.getEntryPoint())
            func_addr_range = func.getBody()
            func_convention = func.getCallingConventionName()
            func_signature = func.getPrototypeString(True, False)
            if func_convention and func_convention not in func_signature:
                func_signature = func_signature.replace(func_name, f"{func_convention} {func_name}")

            # Get assembly code
            func_asm_code = ""
            for instr in program_listing.getInstructions(func_addr_range, True):
                func_asm_code += f"// {instr.getAddress()}: {instr}\n"
            func_asm_code += "\n"

            # Get decompiled code
            func_decomp_code = ""
            res = interface.decompileFunction(func, timeout, ConsoleTaskMonitor())
            if res.decompileCompleted():
                func_decomp_code = res.getDecompiledFunction().getC()
            else:
                func_decomp_code = "// Decompilation failed\n"

            # Get function code values
            function_code_values = {
                "func_name": func_name,
                "func_addr": func_addr,
                "func_addr_range": func_addr_range,
                "func_convention": func_convention,
                "func_signature": func_signature,
                "func_asm_code": func_asm_code,
                "func_decomp_code": func_decomp_code
            }

            system.TouchFile(
                src = os.path.join(export_dir, f"{func_name}.cpp"),
                contents = function_code_template.format(**function_code_values),
                contents_mode = "w",
                encoding = None,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            break
