# Imports
import os
import sys
import re
import json
import time

# Local imports
import config
import system
import environment
import programs
import command

# Function code template
function_code_template = """
// Name: {func_name}
// Address: {func_addr}
// Address Range: {func_addr_range}
// Convention: {func_convention}
// Signature: {func_signature}

#include "functions.h"
{func_decomp_code}
// Assembly code:
{func_asm_code}
"""

# Function header template
function_header_template = """
#ifndef FUNCTIONS_H
#define FUNCTIONS_H

// Auto-generated function prototypes
{prototypes}

#endif // FUNCTIONS_H
"""

class ProjectOptions:
    def __init__(
        self,
        project_name,
        project_dir,
        project_language,
        project_cspec,
        program_name,
        program_binary_file,
        export_dir):
        self.project_name = project_name
        self.project_dir = project_dir
        self.project_language = project_language
        self.project_cspec = project_cspec
        self.program_name = program_name
        self.program_binary_file = program_binary_file
        self.export_dir = export_dir
        if not self.program_name and self.program_binary_file:
            self.program_name = os.path.basename(self.program_binary_file)

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

    def GetExportDir(self):
        return os.path.abspath(self.export_dir)

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

    def BuildStringMap(self, defined_data):

        # Imports
        from ghidra.program.model.data import StringDataType

        # Build string map
        string_map = {}
        while defined_data.hasNext():
            data = defined_data.next()
            if isinstance(data.getDataType(), StringDataType):
                string_addr = data.getAddress()
                string_val = data.getValue()
                string_map[string_addr.toString()] = string_val
        return string_map

    def GenerateAssemblyCode(self, func, symbol_table, reference_manager, program_listing):

        # Imports
        from ghidra.program.model.lang import OperandType

        # Parse instructions
        asm_lines = []
        for instr in program_listing.getInstructions(func.getBody(), True):
            addr = instr.getAddress()
            instr_str = str(instr)

            # Default line
            line = f"// {addr}: {instr_str}"

            # Adjust call target name
            if instr.getMnemonicString() == "CALL":
                for i in range(instr.getNumOperands()):
                    operand_type = instr.getOperandType(i)
                    if operand_type & OperandType.ADDRESS:
                        target_addr = instr.getAddress(i)
                        if target_addr:
                            target_sym = symbol_table.getPrimarySymbol(target_addr)
                            if target_sym:
                                symbol_name = target_sym.getName()
                                addr_str = f"0x{target_addr}"
                                if addr_str in line:
                                    line = line.replace(addr_str, symbol_name)

            # Add symbol label for instruction if it has one
            symbol = symbol_table.getPrimarySymbol(addr)
            if symbol and symbol.getName() != instr.toString():
                line += f"\n//   Label: {symbol.getName()}"

            # Add cross references for this instruction
            refs_from = reference_manager.getReferencesFrom(addr)
            for ref in refs_from:
                line += f"\n//   XREF to: {ref.getToAddress()} ({ref.getReferenceType()})"
            asm_lines.append(line + "\n")
        return "".join(asm_lines)

    def GenerateDecompilationCode(self, func, interface, symbol_table, string_map, timeout):

        # Imports
        from ghidra.util.task import ConsoleTaskMonitor

        # Start decompilation
        res = interface.decompileFunction(func, timeout, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            return "// Decompilation failed\n"

        # Get initial decompiled code
        decompiled_code = res.getDecompiledFunction().getC()

        # Replace string symbols with inline C-style strings
        def replace_symbol(match):
            hex_addr = match.group(1).lower()
            if hex_addr in string_map:
                string_literal = string_map[hex_addr].replace("\\", "\\\\").replace('"', '\\"')
                return f'"{string_literal}"'
            return match.group(0)
        pattern = re.compile(r'\bs_[^\s]*?_([0-9A-Fa-f]{8,})\b')
        decompiled_code = pattern.sub(replace_symbol, decompiled_code)
        return decompiled_code

    def GenerateSourceFileName(self, func_name, func_decomp):

        # Initial guess for extension
        file_extension = ".c"
        if ".cpp" in func_name:
            file_extension = ".cpp"

        # Completely custom path
        if "FUN_" not in func_name:
            for potential_type in [".c", ".cpp"]:
                if potential_type in func_name:
                    return func_name.replace("_", "/")

        # Thunk hybrid path
        if "_thunk_FUN_" in func_name:
            func_parts = func_name.split("_thunk_FUN_")
            path_dir = func_parts[0].replace("_", "/")
            path_base = "_thunk_FUN_" + func_parts[1]
            return os.path.join(path_dir, f"{path_base}{file_extension}")

        # Regular hybrid path
        if "_FUN_" in func_name and "thunk_" not in func_name:
            func_parts = func_name.split("_FUN_")
            path_dir = func_parts[0].replace("_", "/")
            path_base = "_FUN_" + func_parts[1]
            return os.path.join(path_dir, f"{path_base}{file_extension}")

        # Decompilation guessed path
        if "..\\" in func_decomp:
            matches = re.finditer(r'"[^"]*(\.\.[\\/][^"]*)"', func_decomp)
            for match in matches:
                guessed_path = match.group(1)
                if guessed_path.endswith(".txt"):
                    continue
                guessed_path = guessed_path.replace("..\\\\", "")
                guessed_path = guessed_path.replace("\\", "/")
                guessed_path = os.path.normpath(guessed_path)
                if ".cpp" in guessed_path:
                    file_extension = ".cpp"
                return os.path.join(guessed_path, f"{func_name}{file_extension}")

        # Fallback
        return f"{func_name}{file_extension}"

    def ExportFunctions(
        self,
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

        # Keep track of function prototypes
        function_prototypes = set()

        # Read program data
        function_manager = self.api.currentProgram.getFunctionManager()
        program_listing = self.api.currentProgram.getListing()
        defined_data = program_listing.getDefinedData(True)
        string_map = self.BuildStringMap(defined_data)
        reference_manager = self.api.currentProgram.getReferenceManager()
        symbol_table = self.api.currentProgram.getSymbolTable()
        for func in function_manager.getFunctions(True):

            # Basic info
            func_name = func.getName()
            func_addr = str(func.getEntryPoint())
            func_addr_range = func.getBody()
            func_convention = func.getCallingConventionName()
            func_signature = func.getPrototypeString(True, False)
            if func_convention and func_convention not in func_signature:
                func_signature = func_signature.replace(func_name, f"{func_convention} {func_name}")

            # Clean and store prototype
            clean_signature = func_signature.strip()
            if clean_signature.endswith(";"):
                function_prototypes.add(clean_signature)
            else:
                function_prototypes.add(clean_signature + ";")

            # Generate assembly code
            func_asm_code = self.GenerateAssemblyCode(func, symbol_table, reference_manager, program_listing)

            # Generate decompilation code
            func_decomp_code = self.GenerateDecompilationCode(func, interface, symbol_table, string_map, timeout)

            # Prepare code output
            function_code_values = {
                "func_name": func_name,
                "func_addr": func_addr,
                "func_addr_range": func_addr_range,
                "func_convention": func_convention,
                "func_signature": func_signature,
                "func_asm_code": func_asm_code,
                "func_decomp_code": func_decomp_code
            }

            # Write output file
            if not system.TouchFile(
                src = os.path.join(self.options.GetExportDir(), self.GenerateSourceFileName(func_name, func_decomp_code)),
                contents = function_code_template.format(**function_code_values),
                contents_mode = "w",
                encoding = None,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False

        # Prepare header output
        function_header_values = {
            "prototypes": "\n".join(sorted(function_prototypes))
        }

        # Write the header file
        if not system.TouchFile(
            src = os.path.join(self.options.GetExportDir(), "functions.h"),
            contents = function_header_template.format(**function_header_values),
            contents_mode = "w",
            encoding = None,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            return False

    def ExportStrings(
        self,
        timeout = 60,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        pass

    def ExportStructs(
        self,
        timeout = 60,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        pass

    def ExportUnions(
        self,
        timeout = 60,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        pass

    def ExportTypedefs(
        self,
        timeout = 60,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        pass

    def ExportEnums(
        self,
        timeout = 60,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        pass

def LaunchProgram(verbose = False, pretend_run = False, exit_on_failure = False):

    # Get tool
    ghidra_tool = None
    if programs.IsToolInstalled("Ghidra"):
        ghidra_tool = programs.GetToolProgram("Ghidra")
    if not ghidra_tool:
        system.LogError("Ghidra was not found")
        return False

    # Get launch command
    launch_cmd = [
        ghidra_tool
    ]

    # Run launch command
    code = command.RunReturncodeCommand(
        cmd = launch_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)
