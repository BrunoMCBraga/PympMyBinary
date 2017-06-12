from Utils.Win32BinaryUtils import Win32BinaryUtils
from Utils.Win32BinaryOffsetsAndSizes import Win32BinaryOffsetsAndSizes
from Utils.MultiByteHandler import  MultiByteHandler
from Utils.GenericConstants import GenericConstants

class Win32SectionCreator():

    '''
    TODO:
    1.Create new section header
        1.1. Split binary at the end of the last section header (need last section header end)
        1.2. Add array of bytes the size of the header (allocate array with a size that must be the shellcode + FileAlignment)
        1.3. Write the section headers as needed
    2.Create section:
        1.1. Split binary at the end of the last section
        1.2. Append shellcode (once it is adjusted)
    3.Adjust number of section
    4. Adjust size of image
    5. Adjust checksum


    .Align image and section


    '''

    def _inject_data_at_offset(self, data, offset):
        first_half = self.binary_data[0:offset]
        second_half = self.binary_data[offset:]
        first_half.extend(data)
        first_half.extend(second_half)
        self.binary_data = first_half


    def _get_new_header(self, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data):


        new_section_header = [None] * Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER
        new_section_header_index = 0

        section_name_bytes = '.scode\00\00'.encode('utf-8')
        first_half = section_name_bytes[3::-1]
        second_half = section_name_bytes[-1:-4:-1]
        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, int("".join("{:02x}".format(ord(c)) for c in first_half),16))
        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index + 4,  int("".join("{:02x}".format(ord(c)) for c in second_half),16))
        new_section_header_index += 8

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, virtual_size)
        new_section_header_index += 4

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, virtual_address)
        new_section_header_index += 4

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, size_of_raw_data)
        new_section_header_index += 4

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, pointer_to_raw_data)
        new_section_header_index += 4

        #TODO: Process properly
        pointer_to_relocations = 0
        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, pointer_to_relocations)
        new_section_header_index += 4
        pointer_to_line_numbers = 0
        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, pointer_to_line_numbers)
        new_section_header_index += 4
        number_of_relocations = 0
        MultiByteHandler.set_word_given_offset(new_section_header, new_section_header_index, number_of_relocations)
        new_section_header_index += 2
        number_of_line_numbers = 0
        MultiByteHandler.set_word_given_offset(new_section_header, new_section_header_index, number_of_line_numbers)
        new_section_header_index += 2
        characteristics = (0x00000020 | 0x20000000 | 0x40000000)
        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, characteristics)

        return new_section_header



    def _compute_section_aligned_rva_for_new_section(self, header_offset):
        raw_offset_for_last_section_header = Win32BinaryUtils.get_raw_offset_for_last_section_header(self.binary_data, header_offset)
        virtual_address_of_last_section = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_for_last_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
        virtual_size_of_last_section = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_for_last_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)
        new_section_minimum_rva = virtual_size_of_last_section + virtual_size_of_last_section
        return new_section_minimum_rva + Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, new_section_minimum_rva)



    def _adjust_export_table(self, header_offset):

        offset_to_export_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_EXPORT_TABLE_RVA
        export_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_export_table_rva_within_header)

        if export_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, export_table_rva):
            return

        export_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, export_table_rva)

        #Adjusting name RVA
        offset_to_name_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        name_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_name_rva_within_export_directory_table)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_name_rva_within_export_directory_table, name_rva + self.rva_delta)

        #Adjusting ordinal table rva
        offset_to_ordinal_table_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ORDINAL_TABLE_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        ordinal_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_ordinal_table_rva_within_export_directory_table)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_ordinal_table_rva_within_export_directory_table, ordinal_table_rva + self.rva_delta)

        #Adjusting function table RVAs
        offset_to_address_table_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_TABLE_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_address_table_rva_within_export_directory_table)

        offset_to_number_of_functions_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_FUNCTIONS_WITHIN_EXPORT_DIRECTORY_TABLE
        number_of_functions = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_number_of_functions_within_export_directory_table)

        function_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, address_table_rva)


        for functions_index in range(0, number_of_functions):
            function_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, function_table_raw)
            MultiByteHandler.set_dword_given_offset(self.binary_data, function_table_raw, function_rva + self.rva_delta)
            function_table_raw += 0x4

        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_address_table_rva_within_export_directory_table, address_table_rva + self.rva_delta)


        #Adjusting name table RVAs
        offset_to_name_pointer_table_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_POINTER_TABLE_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        name_pointer_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_name_pointer_table_rva_within_export_directory_table)

        offset_to_number_of_names_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_NAMES_WITHIN_EXPORT_DIRECTORY_TABLE
        number_of_names = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_number_of_names_within_export_directory_table)

        name_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, name_pointer_table_rva)

        for names_index in range(0, number_of_names):
            name_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, name_table_raw)
            MultiByteHandler.set_dword_given_offset(self.binary_data, name_table_raw, name_rva + self.rva_delta)
            name_table_raw += 0x4

        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_name_pointer_table_rva_within_export_directory_table, name_pointer_table_rva + self.rva_delta)


        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_export_table_rva_within_header, export_table_rva + self.rva_delta)
    def _adjust_import_table(self, header_offset):

        offset_to_import_table_rva = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_TABLE_RVA
        import_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_import_table_rva)

        if import_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, import_table_rva):
            return
        print("Requires change")
        import_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, import_table_rva)
        current_import_directory_table_entry = import_table_raw

        while(True):

            if Win32BinaryUtils.is_end_of_import_directory_table(self.binary_data, current_import_directory_table_entry):
                break
            offset_to_import_name_table_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_NAME_TABLE_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            import_name_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_import_name_table_rva)
            if import_name_table_rva != 0x0:
                raw_offset_for_import_name_table = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, import_name_table_rva)
                while True:
                    hint_name_rva_or_ordinal = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_for_import_name_table)
                    if hint_name_rva_or_ordinal == 0x0:
                        break
                    if (0x80000000 & hint_name_rva_or_ordinal) != 0x80000000:
                        MultiByteHandler.set_dword_given_offset(self.binary_data, raw_offset_for_import_name_table, hint_name_rva_or_ordinal + self.rva_delta)
                    raw_offset_for_import_name_table += 0x4  # Each hint/name/ordinal takes 4 bytes (dword)

                MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_import_name_table_rva, import_name_table_rva + self.rva_delta)

            offset_to_name_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            name_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_name_rva)
            if name_rva != 0x0:
                MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_name_rva, name_rva + self.rva_delta)

            offset_to_import_address_table_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_ADDRESS_TABLE_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            import_address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_import_address_table_rva)
            if import_address_table_rva != 0x0:
                raw_offset_for_import_address_table = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, import_address_table_rva)
                while True:
                    hint_name_rva_or_ordinal = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_for_import_address_table)
                    if hint_name_rva_or_ordinal == 0x0:
                        break
                    if (0x80000000 & hint_name_rva_or_ordinal) != 0x80000000:
                        MultiByteHandler.set_dword_given_offset(self.binary_data, raw_offset_for_import_address_table, hint_name_rva_or_ordinal + self.rva_delta)
                    raw_offset_for_import_address_table += 0x4 #Each hint/name/ordinal takes 4 bytes (dword)

                MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_import_address_table_rva, import_address_table_rva + self.rva_delta)

            current_import_directory_table_entry += Win32BinaryOffsetsAndSizes.NUMBER_OF_BYTES_PER_IMPORT_DIRECTORY_TABLE_ENTRY

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_import_table_rva, import_table_rva + self.rva_delta)
    def _adjust_resource_table(self, header_offset):

        offset_to_resource_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA
        resource_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_resource_table_rva_within_header)

        if resource_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, resource_table_rva):
            return

        resource_table_raw_offset = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, resource_table_rva)

        offset_to_number_of_id_entries_within_resource_directory_type = resource_table_raw_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_ID_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER
        number_of_id_entries_within_resource_directory_type = MultiByteHandler.get_word_given_offset(self.binary_data, offset_to_number_of_id_entries_within_resource_directory_type)
        pointer_to_offset_to_directory_for_id_entry_within_resource_directory_type = offset_to_number_of_id_entries_within_resource_directory_type + 0x2
        offset_to_offset_to_directory_of_a_type_within_nameid = pointer_to_offset_to_directory_for_id_entry_within_resource_directory_type + 0x4

        for id_entry_within_resource_directory_type in range(0, number_of_id_entries_within_resource_directory_type):

            offset_to_directory_of_a_type_within_nameid = 0x7FFFFFFF & MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_offset_to_directory_of_a_type_within_nameid)
            offset_to_number_of_id_entries_within_nameid = resource_table_raw_offset + offset_to_directory_of_a_type_within_nameid + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_ID_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER
            number_of_id_entries_within_nameid = MultiByteHandler.get_word_given_offset(self.binary_data, offset_to_number_of_id_entries_within_nameid)
            offset_to_offset_of_id_offset_to_directory_for_id_entry_within_nameid = offset_to_number_of_id_entries_within_nameid + 0x2
            offset_to_offset_to_directory_within_language = offset_to_offset_of_id_offset_to_directory_for_id_entry_within_nameid + 0x4

            for id_entry_within_nameid_language in range(0, number_of_id_entries_within_nameid):

                offset_to_directory_of_a_type_within_language = 0x7FFFFFFF & MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_offset_to_directory_within_language)
                offset_to_offset_to_data_entry_within_data_entry = resource_table_raw_offset + offset_to_directory_of_a_type_within_language + Win32BinaryOffsetsAndSizes.OFFSET_TO_OFFSET_TO_DATA_ENTRY_WITHIN_LANGUAGE
                offset_to_data_entry_within_data_entry = 0x7FFFFFFF & MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_offset_to_data_entry_within_data_entry)
                offset_to_rva_within_data_entry = resource_table_raw_offset + offset_to_data_entry_within_data_entry
                rva_of_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_rva_within_data_entry)
                MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_rva_within_data_entry, rva_of_data + self.rva_delta)
                offset_to_offset_to_directory_within_language += 0x8
            offset_to_offset_to_directory_of_a_type_within_nameid += 0x8

        #Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_resource_table_rva_within_header, resource_table_rva + self.rva_delta)
    def _adjust_exception_table(self, header_offset):
        offset_to_exception_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_EXCEPTION_TABLE_RVA
        exception_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_exception_table_rva_within_header)

        if exception_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, exception_table_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_exception_table_rva_within_header, exception_table_rva + self.rva_delta)
    def _adjust_certificate_table(self, header_offset):

        offset_to_certificate_table_rva = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CERTIFICATE_TABLE_RVA
        certificate_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                        offset_to_certificate_table_rva)

        if certificate_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset,
                                                                                    certificate_table_rva):
            return

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_certificate_table_rva,
                                                certificate_table_rva + len(self.shell_code))
    def _adjust_base_relocation_table(self, header_offset):

        offset_to_base_relocation_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_RVA
        base_relocation_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_base_relocation_table_rva_within_header)

        if base_relocation_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, base_relocation_table_rva):
            return

        offset_to_base_relocation_table_size = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_SIZE
        base_relocation_table_size = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_base_relocation_table_size)

        base_relocation_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, base_relocation_table_rva)
        current_base_relocation_table_raw = base_relocation_table_raw

        while current_base_relocation_table_raw < base_relocation_table_raw + base_relocation_table_size:
            rva_of_block = MultiByteHandler.get_dword_given_offset(self.binary_data, current_base_relocation_table_raw)
            size_of_block = MultiByteHandler.get_dword_given_offset(self.binary_data, current_base_relocation_table_raw + 0x4)
            if not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, rva_of_block):
                current_base_relocation_table_raw += size_of_block
                continue

            type_rva_offset = current_base_relocation_table_raw + 0x8 #Type RVA entries start two dwords after the beginning of the block
            number_of_type_rva_entries = (int)((size_of_block - 0x8)/0x2)

            for type_rva_index in range(0, number_of_type_rva_entries):
                type_rva = MultiByteHandler.get_word_given_offset(self.binary_data, type_rva_offset)
                if type_rva != 0x0:
                    MultiByteHandler.set_word_given_offset(self.binary_data, type_rva_offset, type_rva + self.rva_delta)
                type_rva_offset += 0x2

            MultiByteHandler.set_dword_given_offset(self.binary_data, current_base_relocation_table_raw, rva_of_block + self.rva_delta)
            current_base_relocation_table_raw += size_of_block
        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_base_relocation_table_rva_within_header, base_relocation_table_rva + self.rva_delta)
    def _adjust_debug(self, header_offset):
        offset_to_debug_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DEBUG_RVA
        debug_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_debug_rva_within_header)

        if debug_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, debug_rva):
            return


        debug_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, debug_rva)

        offset_to_address_of_raw_data_within_debug_directory = debug_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_RAW_DATA_WITHIN_DEBUG_DIRECTORY
        address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_address_of_raw_data_within_debug_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_address_of_raw_data_within_debug_directory, address_of_raw_data + self.rva_delta)

        offset_to_pointer_to_raw_data_within_debug_directory = debug_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_POINTER_TO_RAW_DATA_WITHIN_DEBUG_DIRECTORY
        pointer_to_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_pointer_to_raw_data_within_debug_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_pointer_to_raw_data_within_debug_directory, pointer_to_raw_data + len(self.shell_code))


        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_debug_rva_within_header, debug_rva + self.rva_delta)
    def _adjust_architecture_data(self, header_offset):
        offset_to_architecture_data_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ARCHITECTURE_DATA_RVA
        architecture_data_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_architecture_data_rva_within_header)

        if architecture_data_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, architecture_data_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_architecture_data_rva_within_header, architecture_data_rva + self.rva_delta)
    def _adjust_global_ptr(self, header_offset):
        offset_to_global_ptr_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_GLOBAL_PTR_RVA
        global_ptr_rva = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                 offset_to_global_ptr_rva_within_header)

        if global_ptr_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset,
                                                                             global_ptr_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_global_ptr_rva_within_header,
                                                global_ptr_rva + self.rva_delta)
    def _adjust_tls_table(self, header_offset):

        offset_to_tls_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_TLS_TABLE_RVA
        tls_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_tls_table_rva_within_header)

        if tls_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, tls_table_rva):
            return

        tls_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, tls_table_rva)

        offset_to_start_address_of_raw_data_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_START_ADDRESS_OF_RAW_DATA_WITHIN_TLS_DIRECTORY
        start_address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_start_address_of_raw_data_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_start_address_of_raw_data_within_tls_directory, start_address_of_raw_data + len(self.shell_code))

        offset_to_end_address_of_raw_data_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_END_OF_ADDRESS_OF_RAW_DATA_WITHIN_TLS_DIRECTORY
        end_address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_end_address_of_raw_data_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_end_address_of_raw_data_within_tls_directory, end_address_of_raw_data + len(self.shell_code))

        offset_to_address_of_index_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_INDEX_WITHIN_TLS_DIRECTORY
        address_of_index = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_address_of_index_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_address_of_index_within_tls_directory, address_of_index + len(self.shell_code))

        offset_to_address_of_callbacks_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_CALLBACKS_WITHIN_TLS_DIRECTORY
        address_of_callbacks = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_address_of_callbacks_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_address_of_callbacks_within_tls_directory, address_of_callbacks + len(self.shell_code))

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_tls_table_rva_within_header, tls_table_rva + self.rva_delta)
    def _adjust_load_config_table(self, header_offset):
        offset_to_load_config_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOAD_CONFIG_TABLE_RVA
        load_config_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                        offset_to_load_config_table_rva_within_header)

        if load_config_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset,
                                                                                    load_config_table_rva):
            return

        load_config_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset,
                                                                    load_config_table_rva)

        offset_to_lock_prefix_table_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOCK_PREFIX_TABLE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        lock_prefix_table_va = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                       offset_to_lock_prefix_table_va_within_load_config_directory)
        if lock_prefix_table_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary_data,
                                                    offset_to_lock_prefix_table_va_within_load_config_directory,
                                                    lock_prefix_table_va + self.rva_delta)

        offset_to_security_cookie_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECURITY_COOKIE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        security_cookie_va = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                     offset_to_security_cookie_va_within_load_config_directory)
        if security_cookie_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary_data,
                                                    offset_to_security_cookie_va_within_load_config_directory,
                                                    security_cookie_va + self.rva_delta)

        offset_to_se_handler_table_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_SE_HANDLER_TABLE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        se_handler_table_va = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                      offset_to_se_handler_table_va_within_load_config_directory)

        if se_handler_table_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary_data,
                                                    offset_to_se_handler_table_va_within_load_config_directory,
                                                    se_handler_table_va + self.rva_delta)

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_load_config_table_rva_within_header,
                                                load_config_table_rva + self.rva_delta)
    def _adjust_bound_import(self, header_offset):
        offset_to_bound_import_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BOUND_IMPORT_RVA
        bound_import_rva = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                   offset_to_bound_import_rva_within_header)

        if bound_import_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset,
                                                                               bound_import_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_bound_import_rva_within_header,
                                                bound_import_rva + self.rva_delta)
    def _adjust_import_address_table(self, header_offset):
        offset_to_import_address_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_ADDRESS_TABLE_RVA
        import_address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_import_address_table_rva_within_header)

        if import_address_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, import_address_table_rva):
            return

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_import_address_table_rva_within_header, import_address_table_rva + self.rva_delta)
    def _adjust_delay_import_descriptor(self, header_offset):
        offset_to_delay_import_descriptor_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DELAY_IMPORT_DESCRIPTOR_RVA
        delay_import_descriptor_rva = MultiByteHandler.get_dword_given_offset(self.binary_data,
                                                                              offset_to_delay_import_descriptor_rva_within_header)

        if delay_import_descriptor_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data,
                                                                                          header_offset,
                                                                                          delay_import_descriptor_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_delay_import_descriptor_rva_within_header,
                                                delay_import_descriptor_rva + self.rva_delta)
    def _adjust_clr_runtime_header(self, header_offset):
        offset_to_clr_runtime_header_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DELAY_IMPORT_DESCRIPTOR_RVA
        clr_runtime_header_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_clr_runtime_header_rva_within_header)

        if clr_runtime_header_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary_data, header_offset, clr_runtime_header_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_clr_runtime_header_rva_within_header, clr_runtime_header_rva + self.rva_delta)


    def _adjust_data_directories(self, header_offset):
        self._adjust_export_table(header_offset)
        self._adjust_import_table(header_offset)
        self._adjust_resource_table(header_offset)
        self._adjust_exception_table(header_offset)
        self._adjust_certificate_table(header_offset)
        self._adjust_base_relocation_table(header_offset)
        self._adjust_debug(header_offset)
        self._adjust_architecture_data(header_offset)
        self._adjust_global_ptr(header_offset)
        self._adjust_tls_table(header_offset)
        self._adjust_load_config_table(header_offset)
        self._adjust_bound_import(header_offset)
        self._adjust_import_address_table(header_offset)
        self._adjust_delay_import_descriptor(header_offset)
        self._adjust_clr_runtime_header(header_offset)

    def _adjust_section_headers(self, header_offset):


        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary_data, number_of_sections_offset)

        # Moving to the next section header
        current_section_header_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BEGINNING_OF_SECTION_HEADERS

        for section_index in range(0, number_of_sections):
            virtual_section_rva_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
            virtual_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
            virtual_section_rva = (virtual_section_rva + self.rva_delta) if virtual_section_rva != 0 else 0

            MultiByteHandler.set_dword_given_offset(self.binary_data, virtual_section_rva_offset, virtual_section_rva)

            raw_section_offset_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER
            raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_section_offset_offset)
            raw_section_offset = (raw_section_offset + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER) if raw_section_offset != 0 else 0
            MultiByteHandler.set_dword_given_offset(self.binary_data, raw_section_offset_offset, raw_section_offset)

            current_section_header_offset += Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER

    def _adjust_standard_coff_fields_and_coff_header(self, header_offset):
        #Adjust number of sections
        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary_data, number_of_sections_offset)
        number_of_sections += 1
        MultiByteHandler.set_word_given_offset(self.binary_data, number_of_sections_offset, number_of_sections)

        #Adjust address of entrypoint
        address_of_entrypoint = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA)
        address_of_entrypoint += self.rva_delta
        MultiByteHandler.set_dword_given_offset(self.binary_data,  header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA, address_of_entrypoint)

        #Adjust BaseOfCode
        base_of_code_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA)
        base_of_code_rva += self.rva_delta
        MultiByteHandler.set_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA, base_of_code_rva)

        #Adjust BaseOfData
        base_of_data_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_DATA_RVA)
        base_of_data_rva += self.rva_delta
        MultiByteHandler.set_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_DATA_RVA, base_of_data_rva)

    def _adjust_windows_specific_headers(self, header_offset):

        # SizeOfImage
        size_of_image_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_IMAGE
        size_of_image = MultiByteHandler.get_dword_given_offset(self.binary_data, size_of_image_offset)
        potentially_unaligned_size_of_image = size_of_image + self.rva_delta + len(self.shell_code)
        aligned_size_of_image = potentially_unaligned_size_of_image + Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, potentially_unaligned_size_of_image)
        MultiByteHandler.set_dword_given_offset(self.binary_data, size_of_image_offset, aligned_size_of_image)

        # SifeOfHeaders
        size_of_headers_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_HEADERS
        size_of_headers = MultiByteHandler.get_dword_given_offset(self.binary_data, size_of_headers_offset)
        potentially_unpadded_size_of_headers = size_of_headers + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER
        padding = Win32BinaryUtils.compute_padding_size_for_file_alignment(self.binary_data, header_offset, potentially_unpadded_size_of_headers)
        MultiByteHandler.set_dword_given_offset(self.binary_data, size_of_headers_offset, padding)


    def _set_rva_delta_for_section_alignment(self, header_offset, raw_offset_of_first_section_header):

        rva_for_entrypoint_section = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_first_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
        virtual_size_of_entrypoint_section = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_first_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)
        minimum_rva_for_next_section = (rva_for_entrypoint_section + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER)


        virtual_rva_delta = Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, minimum_rva_for_next_section)

        # Only the RVA for the shellcode section is affected.
        if virtual_rva_delta != 0x0:
            self.rva_delta = (Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER + virtual_rva_delta)

    def _file_align_shellcode(self, header_offset, shell_code_length):

        """
        :param raw_offset_of_header_of_section_containing_entrypoint:
        :param shell_code_length:
        :return: Updates public shellcode to take into account the FileAlignment specification, i.e., raw sections must have a size that is multiple of the FileAlignment
        """

        padding_size = Win32BinaryUtils.compute_padding_size_for_file_alignment(self.binary_data, header_offset, shell_code_length)
        padded_shell_code = self.shell_code_generator.get_padded_shell_code(padding_size)
        self.shell_code = padded_shell_code


    def modify_binary(self):

        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        # We must get the offsets for the location where the new section and headers will be inserted before inserting it and before changing the headers.
        beginning_of_new_section_header = Win32BinaryUtils.get_raw_offset_for_last_section_header(self.binary_data, header_offset) + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER
        (raw_offset_for_last_section, raw_size_for_last_section) = Win32BinaryUtils.get_raw_offset_and_size_for_last_section(self.binary_data, header_offset)
        beginning_of_new_section = raw_offset_for_last_section + raw_size_for_last_section
        rva_for_last_section = self._compute_section_aligned_rva_for_new_section(header_offset)
        default_shell_code = self.shell_code_generator.get_shell_code()

        self._file_align_shellcode(header_offset, len(default_shell_code))
        self._set_rva_delta_for_section_alignment(header_offset, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BEGINNING_OF_SECTION_HEADERS)
        self._adjust_data_directories(header_offset)
        self._adjust_section_headers(header_offset)
        self._adjust_standard_coff_fields_and_coff_header(header_offset)
        self._adjust_windows_specific_headers(header_offset)

        self._inject_data_at_offset(self.shell_code,beginning_of_new_section) #shellcode
        self._inject_data_at_offset(self._get_new_header(len(self.shell_code), 0x0 , len(self.shell_code), beginning_of_new_section), Win32BinaryUtils.get_raw_offset_for_last_section_header(self.binary_data, header_offset))  # since the number of sections is now six, this function will return the pointer to the 6th.
        # TODO: Enable Checksum
        Win32BinaryUtils.compute_checksum(self.binary_data, header_offset)
        return self.binary_data

        '''
        default_shell_code = self.shell_code_generator.get_shell_code()


        #(raw_offset_for_last_section, raw_size_for_last_section) = Win32BinaryUtils.get_raw_offset_for_last_section(self.binary_data, header_offset)
        padded_shell_code = self.shell_code_generator.get_padded_shell_code(Win32BinaryUtils.compute_padding_size_for_file_alignment(self.binary_data, header_offset, len(default_shell_code)))
        self._add_new_section_header(header_offset, len(default_shell_code), len(padded_shell_code))
        self._update_coff_header(header_offset)
        self._update_windows_specific_fields(header_offset)
        #self._inject_data_at_offset(padded_shell_code, raw_offset_for_last_section + raw_size_for_last_section)


        #Win32BinaryUtils.compute_checksum(self.binary_data, header_offset)
        return self.binary_data
        '''

        '''
        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        #We must get the offsets for the location where the shellcode will be inserted before inserting it and before changing the headers.
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA)
        raw_offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary_data, header_offset, entrypoint_rva)[1]

        entrypoint_raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER)
        entrypoint_raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER)

        self._file_align_shellcode(header_offset, raw_offset_of_header_of_section_containing_entrypoint, entrypoint_raw_section_size)
        self._set_rva_delta_for_section_alignment(header_offset, raw_offset_of_header_of_section_containing_entrypoint)

        self._adjust_data_directories(header_offset)
        self._adjust_section_headers(header_offset)
        self._adjust_standard_coff_fields_and_coff_header(header_offset)
        self._adjust_windows_specific_headers(header_offset)
        self._inject_shell_code_at_offset(entrypoint_raw_section_offset + entrypoint_raw_section_size)
        #TODO: Enable Checksum
        self._update_checksum(header_offset)
        return self.binary_data


        '''

    def __init__(self, binary_data, shell_code_generator):
        self.binary_data = binary_data
        self.shell_code_generator = shell_code_generator
        self.shell_code = shell_code_generator.get_shell_code()
        # extended section must have their RVAs adjusted. This variable contains the adjustment.
