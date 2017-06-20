# PympMyBinary


Python tool to infect binaries with shellcode. The tool infects in one of three modes:
* **Injection at virtual section slack**: assuming a shellcode with size x, the last x bytes of the virtual space for the section containing the entrypoint are overwritten with the shellcode. This mode may overwrite legitimate assembly from the application so a warning is provided.
*  **Entrypoint section append**: shellcode is appended at the end of the entrypoint section. If the virtual size of the entrypoint section and the shellcode cross the RVA for the following section, the tampering fails. Messing with section RVAs is unwise since the code application relies on relative addresses.
* **New section**: a minimalistic section is created containing the shellcode. If the new section header together with the remaining header crosses the RVA for the first section, the tampering fails. Messing with section RVAs is unwise since the code application relies on relative addresses.


## What works?
So far, the infector is only able to infect Win32/64 binaries. 

## What does not?
* Integrity checks implemented by software installers like NSIS cause the execution to fail. Testing with those requires running the binaries with "/NCRC" flag. 
* Packed binaries (e.g. FireFox). Unpack the binary before using this. It is sill being tested.

I have tested a simple NOP sled using the three modes for some well-known binaries like Google Chrome, Skype, Wireshark, etc. Due to the RVA thing i have explained previously, some of them were not tamperable using certain modes, only others (e.g. Wireshark only worked when a new section was created). 

## Usage
```bash
PympMyBinary -i input binary path -o output binary path -sm shellcode generator name -m modifier
```
Where shellcode generator name is one of the filenames on ShellCodeGenerators package and modifier is one of the binary modifers on (surprise!) BinaryModifiers.

## Roadmap
* Elf infection modules
* .NET infection modules
* Infection using TLS 

Win32 binary modifier and supporting classes assume the following model:

![alt tag](https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg)




PEView has been my reference softwate to check for binary correctness.
