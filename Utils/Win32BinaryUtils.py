from Utils.MultiByteHandler import MultiByteHandler
from Utils.Win32BinaryOffsetsAndSizes import Win32BinaryOffsetsAndSizes
from Utils import GenericConstants

class Win32BinaryUtils:

    @staticmethod
    def get_raw_offset_for_header_of_section_containing_given_rva(binary, header_offset, rva):

        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(binary, number_of_sections_offset)
        current_header_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BEGINNING_OF_SECTION_HEADERS
        last_section_index = 0
        last_rva = 0
        for section_index in range(0, number_of_sections):

            virtual_section_size_offset = current_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
            virtual_section_size = MultiByteHandler.get_dword_given_offset(binary, virtual_section_size_offset)

            virtual_section_rva_offset = current_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
            virtual_section_rva = MultiByteHandler.get_dword_given_offset(binary, virtual_section_rva_offset)

            virtual_end_of_section_rva = virtual_section_rva + virtual_section_size - 1

            if (rva >= virtual_section_rva) and (rva < virtual_end_of_section_rva):
                return (section_index,current_header_offset)

            current_header_offset += Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER
            last_section_index = section_index
            last_rva = virtual_end_of_section_rva

        return (None, None)

    @staticmethod
    def convert_rva_to_raw(binary, header_offset, rva):
        section_header_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(binary, header_offset, rva)[1]

        virtual_section_rva_offset = section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
        virtual_section_rva = MultiByteHandler.get_dword_given_offset(binary, virtual_section_rva_offset)

        raw_section_offset_offset = section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER
        raw_section_offset = MultiByteHandler.get_dword_given_offset(binary, raw_section_offset_offset)

        return rva - virtual_section_rva + raw_section_offset

    @staticmethod
    def rva_requires_change(binary, header_offset, rva):

        #For entrypoint
        entrypoint_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(binary, entrypoint_rva_offset_within_header)
        entrypoint_section_header_index_and_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(binary, header_offset, entrypoint_rva)
        offset_of_header_of_section_containing_entrypoint = entrypoint_section_header_index_and_offset[1]

        entrypoint_virtual_section_rva_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
        entrypoint_virtual_section_rva = MultiByteHandler.get_dword_given_offset(binary, entrypoint_virtual_section_rva_offset)


        #For given RVA
        offset_of_header_of_section_containing_given_rva = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(binary, header_offset, rva)[1]

        #If it is None, it means the RVA is beyond the last section
        if offset_of_header_of_section_containing_given_rva == None:
            return True

        virtual_section_rva_offset_for_section_containing_given_rva = offset_of_header_of_section_containing_given_rva + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
        virtual_section_rva_for_section_containing_given_rva = MultiByteHandler.get_dword_given_offset(binary, virtual_section_rva_offset_for_section_containing_given_rva)

        if virtual_section_rva_for_section_containing_given_rva > entrypoint_virtual_section_rva:
            return True

    #Import address table ends five sequences of 0x0 dwords
    @staticmethod
    def is_end_of_import_directory_table(binary, offset):
        dword_sum = 0x0

        for dword_within_directory_table_entry in range(0, Win32BinaryOffsetsAndSizes.NUMBER_OF_DWORDS_WITHIN_EACH_DIRECTORY_TABLE_ENTRY):
            dword_sum += MultiByteHandler.get_dword_given_offset(binary, offset)
            offset += 0x4

        if dword_sum == 0x0:
            return True
        else:
            return False

    @staticmethod
    def get_rva_and_virtual_size_for_last_section(binary, header_offset):

        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(binary, number_of_sections_offset)

        #Jumping to last header
        beginning_of_section_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BEGINNING_OF_SECTION_HEADERS
        beginning_of_section_header += Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER * (number_of_sections-1)
        rva_for_last_section = MultiByteHandler.get_dword_given_offset(binary, beginning_of_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
        virtual_size_of_last_section = MultiByteHandler.get_dword_given_offset(binary, beginning_of_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)
        return (rva_for_last_section, virtual_size_of_last_section)

    #TODO: Consider searching across all executable sections if more than one (rare)
    @staticmethod
    def get_executable_region(binary_data, region_length):

        memory_region_reference = None
        header_offset = MultiByteHandler.get_dword_given_offset(binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        # We must get the offsets for the location where the shellcode will be inserted before inserting it and before changing the headers.
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA)
        raw_offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(binary_data, header_offset, entrypoint_rva)[1]

        entrypoint_raw_section_offset = MultiByteHandler.get_dword_given_offset(binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER)
        entrypoint_raw_section_size = MultiByteHandler.get_dword_given_offset(binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER)

        entrypoint_virtual_section_size = MultiByteHandler.get_dword_given_offset(binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)

        #Shellcode must be injected between the raw offset and raw offset + virtual size. The raw section will be cut.

        if entrypoint_virtual_section_size <= entrypoint_raw_section_size:
            memory_region_reference = entrypoint_raw_section_offset + entrypoint_virtual_section_size
            for index in range(0, region_length):
                region_byte = binary_data[memory_region_reference]
                if region_byte != 0x0:
                    return None
                memory_region_reference-=1


        # Shellcode must be injected between raw section offset and raw section offset + raw size
        else:
            memory_region_reference = entrypoint_raw_section_offset + entrypoint_raw_section_size
            for index in range(0, region_length):
                region_byte = binary_data[memory_region_reference]
                if region_byte != 0x0:
                    return None
                memory_region_reference -= 1


        return memory_region_reference


    @staticmethod
    def compute_checksum(binary_data, header_offset):
        # Clear checksum
        image_checksum_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CHECKSUM
        # checksum = MultiByteHandler.get_dword_given_offset(self.binary, image_checksum_offset)
        MultiByteHandler.set_dword_given_offset(binary_data, image_checksum_offset, 0x0)

        checksum = 0x0
        word_index = 0x0
        has_odd_byte = True if len(binary_data) % Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT == 1 else False

        while word_index < len(binary_data):
            if word_index == image_checksum_offset:
                word_index += Win32BinaryOffsetsAndSizes.CHECKSUM_SIZE
            else:
                checksum += MultiByteHandler.get_word_given_offset(binary_data, word_index)
                checksum & GenericConstants.DWORD_MASK
                # checksum += (checksum >> Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT)
                word_index += Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT

        if has_odd_byte:
            checksum += binary_data[-1]

        checksum = (
                   checksum >> Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT * GenericConstants.BITS_PER_BYTE) + (
                   checksum & 0xFFFF)
        checksum += (checksum >> Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT * GenericConstants.BITS_PER_BYTE)
        checksum = (checksum & 0xFFFF)
        checksum += len(binary_data)

    @staticmethod
    def has_relocation_table(binary_data):

        header_offset = MultiByteHandler.get_dword_given_offset(binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        offset_to_base_relocation_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_RVA
        base_relocation_table_rva = MultiByteHandler.get_dword_given_offset(binary_data, offset_to_base_relocation_table_rva_within_header)

        return True if base_relocation_table_rva != 0x0 else False


