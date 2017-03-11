from Utils.MultiByteHandler import MultiByteHandler
from Utils.Win32BinaryOffsetsAndSizes import Win32BinaryOffsetsAndSizes

class Win32BinaryUtils:

    @staticmethod
    def get_raw_offset_for_header_of_section_containing_given_rva(binary, header_offset, rva):

        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(binary, number_of_sections_offset)
        current_header_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BEGINNING_OF_SECTION_HEADERS
        for section_index in range(0, number_of_sections):

            virtual_section_size_offset = current_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
            virtual_section_size = MultiByteHandler.get_dword_given_offset(binary, virtual_section_size_offset)

            virtual_section_rva_offset = current_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
            virtual_section_rva = MultiByteHandler.get_dword_given_offset(binary, virtual_section_rva_offset)

            virtual_end_of_section_rva = virtual_section_rva + virtual_section_size - 1
            if (rva >= virtual_section_rva) and (rva < virtual_end_of_section_rva):
                return (section_index,current_header_offset)

            current_header_offset += Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER

    @staticmethod
    def convert_rva_to_raw(binary, header_offset, rva):
        section_header_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(binary, header_offset, rva)[1]

        virtual_section_rva_offset = section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
        virtual_section_rva = MultiByteHandler.get_dword_given_offset(binary, virtual_section_rva_offset)

        raw_section_offset_offset = section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER
        raw_section_offset = MultiByteHandler.get_dword_given_offset(binary, raw_section_offset_offset)

        return rva - virtual_section_rva + raw_section_offset

    @staticmethod
    def rva_requires_change(binary, header_offset,  rva):

        entrypoint_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(binary, entrypoint_rva_offset_within_header)
        entrypoint_section_header_index_and_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(binary, header_offset, entrypoint_rva)
        offset_of_header_of_section_containing_entrypoint = entrypoint_section_header_index_and_offset[1]

        entrypoint_virtual_section_rva_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
        entrypoint_virtual_section_rva = MultiByteHandler.get_dword_given_offset(binary, entrypoint_virtual_section_rva_offset)

        if rva > entrypoint_virtual_section_rva:
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
        vitual_size_of_last_section = MultiByteHandler.get_dword_given_offset(binary, beginning_of_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)

        return (rva_for_last_section, vitual_size_of_last_section)