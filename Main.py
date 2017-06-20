import importlib
import os
import sys

from BinaryModifierStubs.Win32BinaryModifierStub import  Win32BinaryModifierStub

def _print_title():
    title_string = """
       ____                        __  ___      ____  _
      / __ \__  ______ ___  ____  /  |/  /_  __/ __ )(_)___  ____ ________  __
     / /_/ / / / / __ `__ \/ __ \/ /|_/ / / / / __  / / __ \/ __ `/ ___/ / / /
    / ____/ /_/ / / / / / / /_/ / /  / / /_/ / /_/ / / / / / /_/ / /  / /_/ /
   /_/    \__, /_/ /_/ /_/ .___/_/  /_/\__, /_____/_/_/ /_/\__,_/_/   \__, /
         /____/         /_/           /____/                         /____/
                   """
    print("{0}".format(title_string))

def _print_usage():
    usage_string = "PympMyBinary -i input binary path -o output binary path -sm shellcode generator name -m modifier name\n"
    switch_explanation_string = """
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

    """
    print("{0}{1}".format(usage_string, switch_explanation_string))



if __name__=='__main__':


    clear_command = 'cls' if os.name == 'nt' else 'clear'
    os.system(clear_command)
    _print_title()


    input_binary_path = None
    output_binary_path = None
    shellcode_generator_name = None
    modifier_name = None


    if len(sys.argv) != 9:
        print("Invalid number of arguments.")
        _print_usage()
        sys.exit(1)
    else:
        input_binary_path = sys.argv[sys.argv.index('-i') + 1] if '-i' in sys.argv else None
        output_binary_path = sys.argv[sys.argv.index('-o') + 1] if '-o' in sys.argv else None
        shellcode_generator_name = sys.argv[sys.argv.index('-sm') + 1] if '-sm' in sys.argv else None
        modifier_name = sys.argv[sys.argv.index('-m') + 1] if '-m' in sys.argv else None


    if None in (input_binary_path, output_binary_path, shellcode_generator_name, modifier_name):
        print("Missing arguments.")
        _print_usage()
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

            shellcode_generator_module = None
            try:
                shellcode_generator_module = importlib.import_module("ShellCodeGenerators." + shellcode_generator_name, "ShellCodeGenerators")
            except Exception as e:
                print("Unable to find shellcode generator. Error:" + str(e))
                _print_usage()
                sys.exit(1)

            shellcode_generator_class = None
            try:
                shellcode_generator_class = getattr(shellcode_generator_module, shellcode_generator_name)
            except Exception as e:
                print("Error getting shellcode generator class. Error:" + str(e))
                _print_usage()
                sys.exit(1)

            modifier_module = None
            try:
                modifier_module = importlib.import_module("BinaryModifiers." + modifier_name, "BinaryModifiers")
            except Exception as e:
                print("Unable to find Binary Modifier. Error:" + str(e))
                _print_usage()
                sys.exit(1)

            modifier_class = None
            try:
                modifier_class = getattr(modifier_module, modifier_name)
            except Exception as e:
                print("Error getting modifier class. Error:" + str(e))
                _print_usage()
                sys.exit(1)

            if shellcode_generator_class == None:
                print("Error obtaining class for provided shellcode generator name. Potential error with the provided name.")
                _print_usage()
                sys.exit(1)

            if modifier_class == None:
                print("Error obtaining class for provided modifier. Potential error with the provided name.")
                _print_usage()
                sys.exit(1)
        else:
            print("Invalid destination directory.")
            _print_usage()
            sys.exit(1)
    else:
        print("Invalid source path.")
        _print_usage()
        sys.exit(1)



    binary_data = Win32BinaryModifierStub(binary_data, shellcode_generator_class, modifier_class).modify_binary()

    #This should be an exception..
    if binary_data == None:
        print("Unable to modify binary.")
        sys.exit(1)

    try:
        os.remove(output_binary_path)
    except OSError:
        pass

    with open(output_binary_path, "wb") as f:
        f.write(binary_data)



