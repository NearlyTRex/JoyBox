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
