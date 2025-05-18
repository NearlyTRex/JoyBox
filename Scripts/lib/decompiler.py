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

    def FindMatchingStringLiteral(self, string_identifier, defined_data):

        # Imports
        from ghidra.program.model.data import StringDataType

        # Find matching string
        while defined_data.hasNext():
            data = defined_data.next()
            if isinstance(data.getDataType(), StringDataType):
                string_addr = data.getAddress()
                string_val = data.getValue()
                if string_identifier.endswith(string_addr.toString()):
                    return string_val

        # No match
        return None

    def GenerateAssemblyCode(self, func, symbol_table, reference_manager, program_listing):

        # Parse instructions
        asm_lines = []
        for instr in program_listing.getInstructions(func.getBody(), True):
            addr = instr.getAddress()

            # Basic instruction line
            line = f"// {addr}: {instr}"

            # Symbol label for this instruction address (if any and different than instr text)
            symbol = symbol_table.getPrimarySymbol(addr)
            if symbol and symbol.getName() != instr.toString():
                line += f"\n//   Label: {symbol.getName()}"

            # Add cross references for this instruction
            refs_from = reference_manager.getReferencesFrom(addr)
            for ref in refs_from:
                ref_type = ref.getReferenceType()
                if str(ref_type) in ("DATA", "READ", "WRITE", "CALL", "JUMP", "FALL_THROUGH"):
                    line += f"\n//   XREF to: {ref.getToAddress()} ({ref_type})"
            asm_lines.append(line + "\n")
        return "".join(asm_lines)

    def GenerateDecompilationCode(self, func, interface, symbol_table, defined_data, timeout):

        # Imports
        from ghidra.program.model.symbol import SymbolType
        from ghidra.util.task import ConsoleTaskMonitor

        # Start decompilation
        res = interface.decompileFunction(func, timeout, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            return "// Decompilation failed\n"

        # Get initial decompiled code
        decompiled_code = res.getDecompiledFunction().getC()

        # Replace raw addresses in decompiled C code with symbol names where possible
        # We only replace addresses that match function symbols to keep it safe
        for symbol in symbol_table.getAllSymbols(True):
            if symbol.getSymbolType() != SymbolType.FUNCTION:
                continue
            symbol_name = symbol.getName()
            symbol_addr_str = str(symbol.getAddress())
            if symbol_addr_str in decompiled_code:
                decompiled_code = decompiled_code.replace(symbol_addr_str, symbol_name)

        # Replace string symbols with inline C-style strings
        string_symbol_pattern = re.compile(r'\bs__\w+')
        matches = set(string_symbol_pattern.findall(decompiled_code))
        for string_symbol in matches:
            string_literal = self.FindMatchingStringLiteral(string_symbol, defined_data)
            if string_literal is not None:
                escaped_literal = json.dumps(string_literal)[1:-1]
                decompiled_code = decompiled_code.replace(string_symbol, f'"{escaped_literal}"')
        return decompiled_code

    def GenerateSourceFileName(self, func_name):
        return f"{func_name}.cpp"

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

        # Read program data
        function_manager = self.api.currentProgram.getFunctionManager()
        program_listing = self.api.currentProgram.getListing()
        defined_data = program_listing.getDefinedData(True)
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

            # Generate assembly code
            func_asm_code = self.GenerateAssemblyCode(func, symbol_table, reference_manager, program_listing)

            # Generate decompilation code
            func_decomp_code = self.GenerateDecompilationCode(func, interface, symbol_table, defined_data, timeout)

            # Prepare values for output
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
            system.TouchFile(
                src = os.path.join(export_dir, self.GenerateSourceFileName(func_name)),
                contents = function_code_template.format(**function_code_values),
                contents_mode = "w",
                encoding = None,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
