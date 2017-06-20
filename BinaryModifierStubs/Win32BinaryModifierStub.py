from Utils.Win32BinaryUtils import Win32BinaryUtils
from Utils.MultiByteHandler import MultiByteHandler
from Utils.Win32BinaryOffsetsAndSizes import  Win32BinaryOffsetsAndSizes

class Win32BinaryModifierStub():
    """
    Proxy class used by Main.py to call the real modifiers.
    """

    def modify_binary(self):

        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)
        shell_code_generator_instance = self.shell_code_generator_class()

        #Temporary solution. Type returns classobject
        if str(self.binary_modifier_class).split('.')[-1] == "Win32SectionInjector":
            shell_code = shell_code_generator_instance.get_base_shell_code(0x0)
            print("Running Win32SectionInjector")
            (rva_for_region, raw_offset_for_region) = Win32BinaryUtils.get_executable_region_rva_and_raw_offset(self.binary_data, header_offset, len(shell_code))
            return self.binary_modifier_class(self.binary_data, shell_code_generator_instance, rva_for_region, raw_offset_for_region).modify_binary()
            if None in (rva_for_region, raw_offset_for_region):
                print("Memory search failed.")
                return None
        else:
           print("Running {0}".format(str(self.binary_modifier_class).split('.')[-1]))
           return self.binary_modifier_class(self.binary_data, shell_code_generator_instance).modify_binary()


    def __init__(self, binary_data, shell_code_generator_class, modifier_class):
       self.binary_data = binary_data
       self.shell_code_generator_class = shell_code_generator_class
       self.binary_modifier_class = modifier_class
