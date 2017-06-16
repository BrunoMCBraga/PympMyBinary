# PympMyBinary


Python tool to infect binaries with shellcode. The tool infects in one of three modes (by the following order):
* **Injection at Virtual Section slack**: assuming a shellcode with size x, the last x bytes of the virtual space for the section containing the entrypoint are overwritten with the shellcode. This mode is only employed if the x bytes are zero so that no legitimate instructions are overwritten.
*  **Entrypoint section append**: shell code is appended at the end of the entrypoint section. Headers and offsets are adjusted. This assumes a relocation table. If the relocation table is not detected, the third mode is employed.
* **New Section**: a minimalistic section is created containing the shellcode.



## What works?
So far, the infector is only able to infect Win32/64 binaries. Testing is ongoing since some sections (e.g. debug table, certificate table) are rare.

## What does not?
* Integrity checks implemented by software installers like NSIS cause the execution to fail. Testing with those requires running the binaries with "/NCRC" flag. 
* Packed binaries (e.g. FireFox). UPX the binary before using this. It is sill being tested.

## Usage
```bash
PympMyBinary -i input binary path -o output binary path -s shellcode generator name
```
Where shellcode generator name is one of the filenames on ShellCodeGenerators package.

## Roadmap
* Elf infection modules
* .NET infection modules


Win32 binary modifier and supporting classes assume the following model:

![alt tag](https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg)




PEView has been my reference softwate to check for binary correctness.
