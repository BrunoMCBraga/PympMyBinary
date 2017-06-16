import os
import importlib
import sys
from BinaryModifiers.Win32BinaryModifier import Win32BinaryModifier


def _print_usage():
    print("PympMyBinary -i input binary path -o output binary path -s shellcode generator name")





if __name__=='__main__':


    clear_command = 'cls' if os.name == 'nt' else 'clear'
    os.system(clear_command)
    _print_usage()

    input_binary_path = None
    output_binary_path = None
    shellcode_generator_name = None


    if len(sys.argv) != 7:
        print("Invalid number of arguments.")
        sys.exit(1)
    else:
        input_binary_path = sys.argv[sys.argv.index('-i') + 1]
        output_binary_path = sys.argv[sys.argv.index('-o') + 1]
        shellcode_generator_name = sys.argv[sys.argv.index('-s') + 1]
        if None in [input_binary_path, output_binary_path, shellcode_generator_name]:
            print("One or more arguments are null.")
            sys.exit(1)

    binary_data = None
    shellcode_generator_instance = None

    if os.path.isfile(input_binary_path):

        with open(input_binary_path, "rb") as f:
            binary_data = bytearray(f.read())

        if binary_data == None:
            print("An error occurred while reading the original binary.")
            _print_usage()
            sys.exit(1)

        if os.path.isdir(os.path.dirname(output_binary_path)):
            module = None
            try:
                module = importlib.import_module("ShellCodeGenerators." + shellcode_generator_name, "ShellCodeGenerators")
            except Exception as e:
                print("Unable to find ShellCodeGenerator:" + str(e))
                _print_usage()
                sys.exit(1)

            shellcode_generator_class = getattr(module, shellcode_generator_name)
            if shellcode_generator_class == None:
                print("Error obtaining class for provided Shellcode generator name. Potential error with the provided name.")
                _print_usage()
                sys.exit(1)
            shellcode_generator_instance =  shellcode_generator_class()
        else:
            print("Invalid destination directory.")
            _print_usage()
            sys.exit(1)
    else:
        print("Invalid source path.")
        _print_usage()
        sys.exit(1)



    binary_data = Win32BinaryModifier(binary_data, shellcode_generator_instance).modify_binary()

    try:
        os.remove(output_binary_path)
    except OSError:
        pass

    with open(output_binary_path, "wb") as f:
        f.write(binary_data)



