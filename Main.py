import os

from ShellCodeGenerators.ZeroFiller import ZeroFiller
from BinaryModifiers.Win32BinaryModifier import Win32BinaryModifier



BINARIES_PATH='./Binaries/'
CLEAN_BINARY= 'TestBinary.exe'
INFECTED_BINARY = CLEAN_BINARY+'.inf'


if __name__=='__main__':

    binary = None

    with open(BINARIES_PATH+CLEAN_BINARY, "rb") as f:
        binary = bytearray(f.read())

    shellcode_generator = ZeroFiller()
    binary_modifier = Win32BinaryModifier()
    binary_modifier.set_binary(binary)
    binary_modifier.set_shell_code_generator(shellcode_generator)
    binary_modifier.modify_binary()

    infected_binary = binary_modifier.get_result()
    infected_binary_path = BINARIES_PATH+INFECTED_BINARY
    try:
        os.remove(infected_binary_path)
    except OSError:
        pass

    with open(infected_binary_path, "wb") as f:
        f.write(infected_binary)



