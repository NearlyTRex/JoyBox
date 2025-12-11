# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import release
import programs
import environment
import toolbase

# Config files
config_files = {}
config_files["Ghidra/lib/Ghidra/Processors/x86/data/languages/x86watcom.cspec"] = """
<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
    <data_organization>
        <absolute_max_alignment value="0" />
        <machine_alignment value="8" />
        <default_alignment value="1" />
        <default_pointer_alignment value="4" />
        <pointer_size value="4" />
        <wchar_size value="2" />
        <short_size value="2" />
        <integer_size value="4" />
        <long_size value="4" />
        <long_long_size value="8" />
        <float_size value="4" />
        <double_size value="8" />
        <long_double_size value="12" />
        <size_alignment_map>
            <entry size="1" alignment="1" />
            <entry size="2" alignment="2" />
            <entry size="4" alignment="4" />
            <entry size="8" alignment="4" />
        </size_alignment_map>
    </data_organization>
    <global>
        <range space="ram" />
    </global>
    <stackpointer register="ESP" space="ram" />
    <returnaddress>
        <varnode space="stack" offset="0" size="4" />
    </returnaddress>
    <default_proto>
        <prototype name="__watcallRegister" extrapop="unknown" stackshift="4">
            <input>
                <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
                <pentry minsize="1" maxsize="4"><register name="EDX" /></pentry>
                <pentry minsize="1" maxsize="4"><register name="EBX" /></pentry>
                <pentry minsize="1" maxsize="4"><register name="ECX" /></pentry>
                <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack" /></pentry>
            </input>
            <output killedbycall="true">
                <pentry minsize="4" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
                <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
                <pentry minsize="5" maxsize="8"><addr space="join" piece1="EDX" piece2="EAX" /></pentry>
            </output>
            <unaffected>
                <register name="EBX" />
                <register name="ESI" />
                <register name="EDI" />
                <register name="EBP" />
            </unaffected>
        </prototype>
    </default_proto>
    <prototype name="__watcallStack" extrapop="4" stackshift="4">
        <input>
            <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="4" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
            <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
            <pentry minsize="5" maxsize="8"><addr space="join" piece1="EDX" piece2="EAX" /></pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
    </prototype>
    <prototype name="__stdcall" extrapop="unknown" stackshift="4">
        <input>
            <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="4" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
            <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
        </killedbycall>
    </prototype>
    <prototype name="__cdecl" extrapop="unknown" stackshift="4">
        <input>
            <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
        </killedbycall>
    </prototype>
    <prototype name="__syscall" extrapop="4" stackshift="4">
        <input>
            <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="4" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
            <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="EBP" />
            <register name="EDI" />
            <register name="ESI" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
        </killedbycall>
    </prototype>
    <prototype name="__fpustack" extrapop="4" stackshift="0">
        <input>
            <pentry minsize="10" maxsize="10" metatype="float"><addr offset="4" space="stack" /></pentry>
            <pentry minsize="10" maxsize="10" metatype="float"><addr offset="14" space="stack" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="10" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
            <register name="ST0" />
            <register name="ST1" />
            <register name="ST2" />
            <register name="ST3" />
            <register name="ST4" />
            <register name="ST5" />
            <register name="ST6" />
            <register name="ST7" />
        </killedbycall>
    </prototype>
    <prototype name="__mathinternal" extrapop="0" stackshift="4">
        <input>
            <!-- No parameters -->
        </input>
        <output killedbycall="true">
            <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
            <pentry minsize="5" maxsize="8">
                <addr space="join" piece1="EDX" piece2="EAX" />
            </pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
        </killedbycall>
    </prototype>
    <prototype name="__crtmath" extrapop="unknown" stackshift="4">
        <!-- CRT math functions like floor/ceil: double on stack, returns EDX:EAX -->
        <input>
            <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack" /></pentry>
        </input>
        <output killedbycall="true">
            <!-- Force EDX:EAX return for doubles, NOT ST0 -->
            <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
            <pentry minsize="5" maxsize="8">
                <addr space="join" piece1="EDX" piece2="EAX" />
            </pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
        </killedbycall>
    </prototype>
    <prototype name="__fpureg" extrapop="0" stackshift="0">
        <!-- Pure FPU register convention: input ST0, output ST0 (for exp, internal math) -->
        <input>
            <pentry minsize="4" maxsize="10" metatype="float"><register name="ST0" /></pentry>
            <pentry minsize="4" maxsize="10" metatype="float"><register name="ST1" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="4" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
        </killedbycall>
    </prototype>
    <prototype name="__fpureg_safe" extrapop="0" stackshift="0">
        <!-- FPU register convention preserving EAX and ST1: for round/floor/ceil called in loops -->
        <!-- Input: ST0 (value to process), ST1 preserved across call -->
        <!-- Output: ST0 (result), EAX/ECX/EDX preserved -->
        <input>
            <pentry minsize="4" maxsize="10" metatype="float"><register name="ST0" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="4" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
        </output>
        <unaffected>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
            <register name="ST1" />
        </unaffected>
    </prototype>
    <prototype name="__softfp_double" extrapop="0" stackshift="0">
        <!-- Software FP: Two doubles as split uints in EAX:EDX and EBX:ECX, returns EDX:EAX -->
        <input>
            <pentry minsize="4" maxsize="4"><register name="EAX" /></pentry>
            <pentry minsize="4" maxsize="4"><register name="EDX" /></pentry>
            <pentry minsize="4" maxsize="4"><register name="EBX" /></pentry>
            <pentry minsize="4" maxsize="4"><register name="ECX" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="1" maxsize="4"><register name="EAX" /></pentry>
            <pentry minsize="5" maxsize="8">
                <addr space="join" piece1="EDX" piece2="EAX" />
            </pentry>
        </output>
        <unaffected>
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
            <register name="EBX" />
        </killedbycall>
    </prototype>
    <prototype name="__fpu_thunk" extrapop="0" stackshift="0">
        <!-- FPU register thunks: input from ST0-ST3, output ST0 -->
        <input>
            <pentry minsize="10" maxsize="10" metatype="float"><register name="ST0" /></pentry>
            <pentry minsize="10" maxsize="10" metatype="float"><register name="ST1" /></pentry>
            <pentry minsize="10" maxsize="10" metatype="float"><register name="ST2" /></pentry>
            <pentry minsize="10" maxsize="10" metatype="float"><register name="ST3" /></pentry>
        </input>
        <output killedbycall="true">
            <pentry minsize="10" maxsize="10" metatype="float" extension="float"><register name="ST0" /></pentry>
        </output>
        <unaffected>
            <register name="EBX" />
            <register name="ESI" />
            <register name="EDI" />
            <register name="EBP" />
        </unaffected>
        <killedbycall>
            <register name="EAX" />
            <register name="ECX" />
            <register name="EDX" />
        </killedbycall>
    </prototype>
</compiler_spec>
"""
config_files["Ghidra/lib/Ghidra/Processors/x86/data/languages/x86watcom.ldefs"] = """
<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
    <language processor="x86" endian="little" size="32" variant="default" version="1.0" slafile="x86.sla" processorspec="x86.pspec" manualindexfile="../manuals/x86.idx" id="x86:LE:32:watcom">
        <description>Intel/AMD 32-bit x86</description>
        <compiler name="Watcom C++" spec="x86watcom.cspec" id="watcomcpp" />
    </language>
</language_definitions>
"""
config_files["Ghidra/lib/Ghidra/Processors/x86/data/patterns/patternconstraints.xml"] = """
<patternconstraints>
    <language id="x86:LE:32:default">
        <compiler id="windows">
            <patternfile>x86win_patterns.xml</patternfile>
        </compiler>
        <compiler id="borlandcpp">
            <patternfile>x86win_patterns.xml</patternfile>
        </compiler>
        <compiler id="borlanddelphi">
            <patternfile>x86delphi_patterns.xml</patternfile>
        </compiler>
        <compiler id="gcc">
            <patternfile>x86gcc_patterns.xml</patternfile>
        </compiler>
        <compiler id="watcomcpp">
            <patternfile>x86watcomcpp_patterns.xml</patternfile>
        </compiler>
    </language>
    <language id="x86:LE:64:default">
        <compiler id="windows">
            <patternfile>x86-64win_patterns.xml</patternfile>
        </compiler>
        <compiler id="gcc">
            <patternfile>x86-64gcc_patterns.xml</patternfile>
        </compiler>
    </language>
    <language id="x86:LE:16:Real Mode">
        <compiler id="default">
            <patternfile>x86-16_default_patterns.xml</patternfile>
        </compiler>
    </language>
    <language id="x86:LE:16:Protected Mode">
        <compiler id="default">
            <patternfile>x86-16_default_patterns.xml</patternfile>
        </compiler>
    </language>
</patternconstraints>
"""
config_files["Ghidra/lib/Ghidra/Processors/x86/data/patterns/x86watcomcpp_patterns.xml"] = """
<patternlist>
</patternlist>
"""

# Patch files
patch_files = {}
patch_files["Ghidra/Processors/x86/data/languages/ia.sinc"] = """
--- a/Ghidra/Processors/x86/data/languages/ia.sinc
+++ b/Ghidra/Processors/x86/data/languages/ia.sinc
@@ -2604,6 +2604,17 @@
 :AND Rmr64,simm32    is $(LONGMODE_ON) & vexMode=0 & opsize=2 & byte=0x81; mod=3 & Rmr64 & reg_opcode=4; simm32  { logicalflags();  Rmr64 =  Rmr64 & simm32; resultflags( Rmr64); }
 @endif
 :AND Rmr16,usimm8_16		is vexMode=0 & opsize=0 & byte=0x83; mod=3 & Rmr16 & reg_opcode=4; usimm8_16	{ logicalflags();  Rmr16 =  Rmr16 & usimm8_16; resultflags( Rmr16); }
+
+# Watcom stack alignment fix: AND ESP, negative_mask (e.g., AND ESP, 0xFFFFFFF8)
+# Expresses AND as subtraction to preserve stack pointer tracking in decompiler.
+:AND Rmr32,usimm8_32		is vexMode=0 & opsize=1 & byte=0x83; mod=3 & Rmr32 & r32=4 & check_Rmr32_dest & reg_opcode=4; usimm8_32 & imm8_7=1	{
+	logicalflags();
+	local notMask:4 = ~usimm8_32;
+	local alignDelta:4 = Rmr32 & notMask;
+	Rmr32 = Rmr32 - alignDelta;
+	build check_Rmr32_dest;
+	resultflags(Rmr32);
+}
+
 :AND Rmr32,usimm8_32		is vexMode=0 & opsize=1 & byte=0x83; mod=3 & Rmr32 & check_Rmr32_dest & reg_opcode=4; usimm8_32	{ logicalflags();  Rmr32 =  Rmr32 & usimm8_32; build check_Rmr32_dest; resultflags( Rmr32); }
 @ifdef IA64
 :AND Rmr64,usimm8_64		is $(LONGMODE_ON) & vexMode=0 & opsize=2 & byte=0x83; mod=3 & Rmr64 & reg_opcode=4; usimm8_64	{ logicalflags();  Rmr64 =  Rmr64 & usimm8_64; resultflags( Rmr64); }
"""

# Ghidra tool
class Ghidra(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Ghidra"

    # Get config
    def GetConfig(self):
        return {
            "Ghidra": {
                "program": {
                    "windows": "Ghidra/lib/ghidraRun.bat",
                    "linux": "Ghidra/lib/ghidraRun"
                },
                "package_dir": "Ghidra/lib/Ghidra/Features/PyGhidra/pypkg/src",
                "package_name": "pyghidra"
            },
            "GhidraHeadless": {
                "program": {
                    "windows": "Ghidra/lib/support/analyzeHeadless.bat",
                    "linux": "Ghidra/lib/support/analyzeHeadless"
                }
            },
            "GhidraSleigh": {
                "program": {
                    "windows": "Ghidra/lib/support/sleigh.bat",
                    "linux": "Ghidra/lib/support/sleigh"
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("Ghidra"):
            success = release.DownloadGithubRelease(
                github_user = "NationalSecurityAgency",
                github_repo = "ghidra",
                starts_with = "ghidra_",
                ends_with = ".zip",
                search_file = "ghidraRun",
                install_name = "Ghidra",
                install_dir = programs.GetLibraryInstallDir("Ghidra", "lib"),
                backups_dir = programs.GetLibraryBackupDir("Ghidra", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Ghidra")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("Ghidra"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Ghidra", "lib"),
                install_name = "Ghidra",
                install_dir = programs.GetLibraryInstallDir("Ghidra", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Ghidra")
                return False
        return True

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            print(config_filename)

            success = system.TouchFile(
                src = system.JoinPaths(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not create Ghidra config files")
                return False
        return True
