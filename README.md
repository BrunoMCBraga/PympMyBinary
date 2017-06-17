# PympMyBinary


Python tool to infect binaries with shellcode. The tool infects in one of three modes (by the following order):
* **Injection at virtual section slack**: assuming a shellcode with size x, the last x bytes of the virtual space for the section containing the entrypoint are overwritten with the shellcode. This mode is only employed if the x bytes are zero so that no legitimate instructions are overwritten.
*  **Entrypoint section append**: shell code is appended at the end of the entrypoint section. Headers and offsets are adjusted. This assumes a relocation table. If the relocation table is not detected, the third mode is employed.
* **New section**: a minimalistic section is created containing the shellcode.



## What works?
So far, the infector is only able to infect Win32/64 binaries. Testing is ongoing since some sections (e.g. debug table, certificate table) are rare. The section injector is working but it is hard to test since binaries are compiled with low slack to minimize memory fingerprint. Section appender has worked in the past but i have been working on the section creator. See tested software.

## What does not?
* Integrity checks implemented by software installers like NSIS cause the execution to fail. Testing with those requires running the binaries with "/NCRC" flag. 
* Packed binaries (e.g. FireFox). UPX the binary before using this. It is sill being tested.

## Tested software and issues
* ImmunityDebugger_1_85_setup.exe (MD5: b94ff046f678a5e89d06007ea24c57ec): has to be ran with /NCRC flag to disable NSIS integrity check
* Wireshark-win32-2.2.7.exe (MD5: ab254d59f70aec9178aeb8a76a24de50): Currently creting a new section. This is causing NSIS to fail because i am inserting the shellcode after the last section. However, NSIS has Side-by-side configurations between the last section and the certificate table which is causing the installer to fail. Will test with section appender.


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
