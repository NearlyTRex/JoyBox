# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import environment
import programs

# Function c template
function_c_template = """
// Name: {name}
// Address: {addr}
// Address Range: {addr_range}
// Convention: {convention}
// Signature: {signature}
//
// Assembly code:
// {assembly_code}

{signature} {
    {c_code}
}
"""

class GhidraProgram:
    def __init__(self, program_exe):

        # Import pyghidra
        self.pyghidra = environment.ImportPythonModulePackage(
            module_path = programs.GetToolPathConfigValue("Ghidra", "package_dir"),
            module_name = programs.GetToolConfigValue("Ghidra", "package_name"))
        self.pyghidra.start(install_dir = programs.GetLibraryInstallDir("Ghidra", "lib"))

        # Load program
        self.program_exe = program_exe
        self.flat_api = self.pyghidra.open_program(self.program_exe)
        self.current_program = self.flat_api.currentProgram

    def get_name(self):
        return self.current_program.getName()

    def get_language(self):
        return str(self.current_program.getLanguage().getLanguageID())

    def get_file_format(self):
        return str(self.current_program.getExecutableFormat())

    def export_functions(self, export_dir):

        # Imports
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        # Open decompiler interface
        decomp = DecompInterface()
        decomp.openProgram(self.current_program)

        # Read functions
        func_manager = self.current_program.getFunctionManager()
        for func in func_manager.getFunctions(True):

            # Get basic info
            name = func.getName()
            addr = str(func.getEntryPoint())
            addr_range = func.getBody()
            convention = func.getCallingConventionName()
            signature = func.getPrototypeString(True, False)
            if convention and convention not in signature:
                signature = signature.replace(name, f"{convention} {name}")

            # Get decompiled C
            c_code = []
            try:
                result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
                c_code = result.getDecompiledFunction().getC()
            except:
                c_code = ["// Decompilation failed\n"]

            # Get assembly code
            asm_lines = []
            for instr in listing.getInstructions(addr_range, True):
                asm_lines.append(f"// {instr.getAddress()}: {instr}")

    def export_strings(self, export_dir):
        pass
