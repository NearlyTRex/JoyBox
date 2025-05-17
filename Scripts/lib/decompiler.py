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

class ProgramDecompiler:
    def __init__(self, program_exe):
        self.program_exe = program_exe
        self.pyghidra = None
        self.flat_api = None
        self.current_program = None
        self._ctx = None

    def __enter__(self):

        # Import pyghidra
        self.pyghidra = environment.ImportPythonModulePackage(
            module_path = programs.GetToolPathConfigValue("Ghidra", "package_dir"),
            module_name = programs.GetToolConfigValue("Ghidra", "package_name"))
        self.pyghidra.start(install_dir = programs.GetLibraryInstallDir("Ghidra", "lib"))

        # Load program context
        self._ctx = self.pyghidra.open_program(self.program_exe)
        self.flat_api = self._ctx.__enter__()
        self.current_program = self.flat_api.currentProgram
        return self

    def __exit__(self, exc_type, exc_value, traceback):

        # Close program context
        if self._ctx:
            self._ctx.__exit__(exc_type, exc_value, traceback)
            self._ctx = None

    def get_name(self):
        return self.current_program.getName()

    def get_language(self):
        return str(self.current_program.getLanguage().getLanguageID())

    def get_file_format(self):
        return str(self.current_program.getExecutableFormat())

    def export_functions(
        self,
        export_dir,
        timeout = 60,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Imports
        from ghidra.app.decompiler import DecompileOptions
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        # Initialize and open decompiler
        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)
        ifc.openProgram(self.current_program)

        # Read functions
        func_manager = self.current_program.getFunctionManager()
        listing = self.current_program.getListing()
        for func in func_manager.getFunctions(True):

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
            for instr in listing.getInstructions(func_addr_range, True):
                func_asm_code += f"// {instr.getAddress()}: {instr}\n"
            func_asm_code += "\n"

            # Get decompiled code
            func_decomp_code = ""
            res = ifc.decompileFunction(func, timeout, monitor)
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
