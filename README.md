# PympMyBinary


Python tool to infect binaries with shellcode. The tool infects in one of three modes:
* **Injection at virtual section slack**: assuming a shellcode with size x, the last x bytes of the virtual space for the section containing the entrypoint are overwritten with the shellcode. This mode may overwrite legitimate assembly from the application so a warning is provided.
*  **Entrypoint section append**: shellcode is appended at the end of the entrypoint section. If the virtual size of the entrypoint section and the shellcode cross the RVA for the following section, the tampering fails. Messing with section RVAs is unwise since the code application relies on relative addresses.
* **New section**: a minimalistic section is created containing the shellcode. If the new section header together with the remaining header crosses the RVA for the first section, the tampering fails. Messing with section RVAs is unwise since the code application relies on relative addresses.

Regardless of the mode, the entrypoint RVA is overwritten so that the execution starts with the shellcode. The execution then passes to the original RVA. This requires the shellcode to be tuned with a negative jmp (details).

## What works?
So far, the infector is only able to infect Win32/64 binaries. 

## What does not?
* Integrity checks implemented by software installers like NSIS cause the execution to fail. Testing with those requires running the binaries with "/NCRC" flag. 
* Packed binaries (e.g. FireFox). Unpack the binary before using this. It is sill being tested.

I have tested a simple NOP sled using the three modes for some well-known binaries like Google Chrome, Skype, Wireshark, etc. Due to the RVA thing i have explained previously, some of them were not tamperable using certain modes, only others (e.g. Wireshark only worked when a new section was created). 

## Usage
```text
       ____                        __  ___      ____  _
      / __ \__  ______ ___  ____  /  |/  /_  __/ __ )(_)___  ____ ________  __
     / /_/ / / / / __ `__ \/ __ \/ /|_/ / / / / __  / / __ \/ __ `/ ___/ / / /
    / ____/ /_/ / / / / / / /_/ / /  / / /_/ / /_/ / / / / / /_/ / /  / /_/ /
   /_/    \__, /_/ /_/ /_/ .___/_/  /_/\__, /_____/_/_/ /_/\__,_/_/   \__, /
         /____/         /_/           /____/                         /____/
                   
Invalid number of arguments.
PympMyBinary -i input binary path -o output binary path -sm shellcode generator name -m modifier name

    -i: path for clean binary
    -o: path to infected binary
    -sm: shellcode module name. Check the ShellCodeGenerators package (e.g. -m NOPSled)
    -m: modifier. Check the BinaryModifiers package:
        - Win32SectionAppender: Inserts the shellcode at the end of entrypoint's virtual section. It will fail if the shellcode crosses the RVA
         for the next section.
        - Win32SectionCreator: creates a new section on the binary and puts the shellcode there. This modifier fails if the new section header crosses
        the RVA for the first section.
        - Win32SectionInjector: overwrites x bytes at the end of entrypoint's virtual section. x bytes is the size of the shellcode. This modifier may
        overwrite important assembly.

```

## Roadmap
* ELF infection modules
* .NET infection modules
* Infection using TLS 

Win32 binary modifier and supporting classes assume the following model:

![alt tag](https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg)




PEView has been my reference softwate to check for binary correctness.
