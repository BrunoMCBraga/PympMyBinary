from Utils.Win32BinaryOffsetsAndSizes import Win32BinaryOffsetsAndSizes
from Utils.Win32BinaryUtils import Win32BinaryUtils
from Utils.MultiByteHandler import MultiByteHandler
from Utils.GenericConstants import GenericConstants

'''
1.Adjust size of code, Address of Entrypoint, Base of Code, Base of Data
2.Adjust size of image
3.Adjust RVAs:
    -Export Table
    -Import Table
    -Resource Table
    -Exception Table
    -CertificateTable
    -Base Relocation Table
    -Debug
    -Architecture Data
    -GlobalPtr
    -TLSTable
    -LoadConfigTable
    -BoundImport
    -ImportAddressTable
    -DelayImportDescriptor
    -CLRRuntimeHeader
Also, for each table, if it has RVAs, they must be adjusted.
4.Adjust section headers:
    1.For section containing shellcode:
        -Virtiual and Raw sizes must be adjusted
    2. For sections comming after the shellcode section:
        -Virtual RVA and Pointer to Raw Data must be adjusted



'''


class Win32BinaryModifier:

    def compute_padding_size_for_file_alignment(self, header_offset, size_or_offset):

        """
        :param header_offset:
        :param size_or_offset:
        :return: Used to compute the number of bytes that must be added to the shellcode to align the raw section size to filealignment.
        """

        file_alignment = MultiByteHandler.get_dword_given_offset(self.binary, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_FILE_ALIGNMENT)
        mod_result = size_or_offset % file_alignment

        return (file_alignment - mod_result) if mod_result != 0x0 else 0x0

    def compute_padding_size_for_section_alignment(self, header_offset, size_or_rva):
        section_alignment = MultiByteHandler.get_dword_given_offset(self.binary, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_ALIGNMENT)
        mod_result = size_or_rva % section_alignment
        return (section_alignment - mod_result) if mod_result != 0x0 else 0x0

    def inject_shell_code_at_offset(self, offset):
        first_half = self.binary[0:offset]
        second_half = self.binary[offset:]
        first_half.extend(self.shell_code)
        first_half.extend(second_half)
        self.binary = first_half

    def modify_entrypoint(self):
        '''
            1.Modify entrypoint
            2.Adjust shellcode to take into account the RVA (relative addresses)
            3.Insert jmp at the end of shellcode to pass execution to legitimate binary
        '''
        pass



    '''
        Adjust:
        -Size of code
        -Address of entrypoint (RVA)
        -Base of code (RVA)
     '''
    def adjust_standard_coff_fields(self, header_offset):

        # Set size of code
        size_of_code_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_CODE
        current_size_of_code = MultiByteHandler.get_dword_given_offset(self.binary, size_of_code_offset)
        MultiByteHandler.set_dword_given_offset(self.binary, size_of_code_offset, current_size_of_code + len(self.shell_code))


        ''' Set base of code RVA: since i am inserting the shell code on the section containing the entrypoint, i must verify
            whether the base of code is the section containing the entrypoint
        '''
        base_of_code_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA
        current_base_of_code_rva = MultiByteHandler.get_dword_given_offset(self.binary, base_of_code_rva_offset_within_header)

        offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, header_offset, MultiByteHandler.get_dword_given_offset(self.binary, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA))[1]
        entrypoint_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        if current_base_of_code_rva > entrypoint_section_rva:
            MultiByteHandler.set_dword_given_offset(self.binary, base_of_code_rva_offset_within_header, current_base_of_code_rva + self.rva_delta)

        #This is better not to be here. The entrypoint should be the last thing to be changed..
        self.modify_entrypoint()

    '''
        Adjust:
        -Base of data
        -Size of image

    '''
    def adjust_windows_specific_headers(self, header_offset):

        #Adjust base of data: must check whether this RVA is greater that the RVA of the section containing the shell code (section containing entrypoint).
        base_of_data_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_DATA_RVA
        current_base_of_data = MultiByteHandler.get_dword_given_offset(self.binary, base_of_data_rva_offset_within_header)

        entrypoint_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset_within_header)
        offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, header_offset, entrypoint_rva)[1]
        entrypoint_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        if current_base_of_data > entrypoint_section_rva:
            MultiByteHandler.set_dword_given_offset(self.binary, base_of_data_rva_offset_within_header, current_base_of_data + self.rva_delta)

        size_of_image_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_IMAGE
        rva_and_virtual_size_of_last_section = Win32BinaryUtils.get_rva_and_virtual_size_for_last_section(self.binary, header_offset)
        potentially_unaligned_size_of_image = rva_and_virtual_size_of_last_section[0] + rva_and_virtual_size_of_last_section[1]
        #Size of Image must be aligned using SectionAlignment.
        aligned_size_of_image = potentially_unaligned_size_of_image + self.compute_padding_size_for_section_alignment(header_offset, potentially_unaligned_size_of_image)

        MultiByteHandler.set_dword_given_offset(self.binary, size_of_image_offset, aligned_size_of_image)


    '''
        TODO: Consider the size for the resource table.
    '''
    def adjust_resource_table(self, header_offset):

        offset_to_resource_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA
        resource_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_resource_table_rva_within_header)

        if resource_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, resource_table_rva):
            return

        resource_table_raw_offset = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, resource_table_rva)

        offset_to_number_of_id_entries_within_resource_directory_type = resource_table_raw_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_ID_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER
        number_of_id_entries_within_resource_directory_type = MultiByteHandler.get_word_given_offset(self.binary, offset_to_number_of_id_entries_within_resource_directory_type)
        pointer_to_offset_to_directory_for_id_entry_within_resource_directory_type = offset_to_number_of_id_entries_within_resource_directory_type + 0x2
        offset_to_offset_to_directory_of_a_type_within_nameid = pointer_to_offset_to_directory_for_id_entry_within_resource_directory_type + 0x4

        for id_entry_within_resource_directory_type in range(0, number_of_id_entries_within_resource_directory_type):

            offset_to_directory_of_a_type_within_nameid = 0x7FFFFFFF & MultiByteHandler.get_dword_given_offset(self.binary, offset_to_offset_to_directory_of_a_type_within_nameid)
            offset_to_number_of_id_entries_within_nameid = resource_table_raw_offset + offset_to_directory_of_a_type_within_nameid + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_ID_ENTRIES_WITHIN_RESOURCE_DIRECTORY_HEADER
            number_of_id_entries_within_nameid = MultiByteHandler.get_word_given_offset(self.binary, offset_to_number_of_id_entries_within_nameid)
            offset_to_offset_of_id_offset_to_directory_for_id_entry_within_nameid = offset_to_number_of_id_entries_within_nameid + 0x2
            offset_to_offset_to_directory_within_language = offset_to_offset_of_id_offset_to_directory_for_id_entry_within_nameid + 0x4

            for id_entry_within_nameid_language in range(0, number_of_id_entries_within_nameid):

                offset_to_directory_of_a_type_within_language = 0x7FFFFFFF & MultiByteHandler.get_dword_given_offset(self.binary, offset_to_offset_to_directory_within_language)
                offset_to_offset_to_data_entry_within_data_entry = resource_table_raw_offset + offset_to_directory_of_a_type_within_language + Win32BinaryOffsetsAndSizes.OFFSET_TO_OFFSET_TO_DATA_ENTRY_WITHIN_LANGUAGE
                offset_to_data_entry_within_data_entry = 0x7FFFFFFF & MultiByteHandler.get_dword_given_offset(self.binary, offset_to_offset_to_data_entry_within_data_entry)
                offset_to_rva_within_data_entry = resource_table_raw_offset + offset_to_data_entry_within_data_entry
                rva_of_data = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_rva_within_data_entry)
                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_rva_within_data_entry, rva_of_data + self.rva_delta)
                offset_to_offset_to_directory_within_language += 0x8
            offset_to_offset_to_directory_of_a_type_within_nameid += 0x8

        #Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_resource_table_rva_within_header, resource_table_rva + self.rva_delta)

    '''
        1.Get size of import table. Compute number of entries.
        2.Adust RVAs within Import directory table:
            -Adjust import name table RVA
            -Adjust Name RVA
            -Adjust Import address table RVA

    '''
    def adjust_import_table(self, header_offset):

        offset_to_import_table_rva = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_TABLE_RVA
        import_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_table_rva)

        if import_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, import_table_rva):
            return

        import_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, import_table_rva)
        current_import_directory_table_entry = import_table_raw

        while(True):

            if Win32BinaryUtils.is_end_of_import_directory_table(self.binary, current_import_directory_table_entry):
                break
            offset_to_import_name_table_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_NAME_TABLE_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            import_name_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_name_table_rva)
            if import_name_table_rva != 0x0:
                raw_offset_for_import_name_table = Win32BinaryUtils.convert_rva_to_raw(self.binary,  header_offset, import_name_table_rva)
                while True:
                    hint_name_rva_or_ordinal = MultiByteHandler.get_dword_given_offset(self.binary, raw_offset_for_import_name_table)
                    if hint_name_rva_or_ordinal == 0x0:
                        break
                    if (0x80000000 & hint_name_rva_or_ordinal) != 0x80000000:
                        MultiByteHandler.set_dword_given_offset(self.binary, raw_offset_for_import_name_table, hint_name_rva_or_ordinal + self.rva_delta)
                    raw_offset_for_import_name_table += 0x4  # Each hint/name/ordinal takes 4 bytes (dword)

                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_import_name_table_rva, import_name_table_rva + self.rva_delta)

            offset_to_name_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            name_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_name_rva)
            if name_rva != 0x0:
                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_name_rva, name_rva + self.rva_delta)

            offset_to_import_address_table_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_ADDRESS_TABLE_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            import_address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_address_table_rva)
            if import_address_table_rva != 0x0:
                raw_offset_for_import_address_table = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, import_address_table_rva)
                while True:
                    hint_name_rva_or_ordinal = MultiByteHandler.get_dword_given_offset(self.binary,raw_offset_for_import_address_table)
                    if hint_name_rva_or_ordinal == 0x0:
                        break
                    if (0x80000000 & hint_name_rva_or_ordinal) != 0x80000000:
                        MultiByteHandler.set_dword_given_offset(self.binary, raw_offset_for_import_address_table, hint_name_rva_or_ordinal + self.rva_delta)
                    raw_offset_for_import_address_table += 0x4 #Each hint/name/ordinal takes 4 bytes (dword)

                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_import_address_table_rva, import_address_table_rva + self.rva_delta)

            current_import_directory_table_entry += Win32BinaryOffsetsAndSizes.NUMBER_OF_BYTES_PER_IMPORT_DIRECTORY_TABLE_ENTRY

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_import_table_rva, import_table_rva + self.rva_delta)

    def adjust_certificate_table(self, header_offset):

        offset_to_certificate_table_rva = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CERTIFICATE_TABLE_RVA
        certificate_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_certificate_table_rva)

        if certificate_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, certificate_table_rva):
            return

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_certificate_table_rva, certificate_table_rva + self.rva_delta)

    def adjust_export_table(self, header_offset):

        offset_to_export_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_EXPORT_TABLE_RVA
        export_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_export_table_rva_within_header)

        if export_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, export_table_rva):
            return

        export_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, export_table_rva)

        #Adjusting name RVA
        offset_to_name_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        name_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_name_rva_within_export_directory_table)
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_name_rva_within_export_directory_table, name_rva + self.rva_delta)

        #Adjusting ordinal table rva
        offset_to_ordinal_table_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ORDINAL_TABLE_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        ordinal_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_ordinal_table_rva_within_export_directory_table)
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_ordinal_table_rva_within_export_directory_table, ordinal_table_rva + self.rva_delta)

        #Adjusting function table RVAs
        offset_to_address_table_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_TABLE_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_address_table_rva_within_export_directory_table)

        offset_to_number_of_functions_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_FUNCTIONS_WITHIN_EXPORT_DIRECTORY_TABLE
        number_of_functions = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_number_of_functions_within_export_directory_table)

        function_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, address_table_rva)


        for functions_index in range(0, number_of_functions):
            function_rva = MultiByteHandler.get_dword_given_offset(self.binary, function_table_raw)
            MultiByteHandler.set_dword_given_offset(self.binary, function_table_raw, function_rva + self.rva_delta)
            function_table_raw += 0x4

        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_address_table_rva_within_export_directory_table, address_table_rva + self.rva_delta)


        #Adjusting name table RVAs
        offset_to_name_pointer_table_rva_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_POINTER_TABLE_RVA_WITHIN_EXPORT_DIRECTORY_TABLE
        name_pointer_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_name_pointer_table_rva_within_export_directory_table)

        offset_to_number_of_names_within_export_directory_table = export_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_NAMES_WITHIN_EXPORT_DIRECTORY_TABLE
        number_of_names = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_number_of_names_within_export_directory_table)

        name_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, name_pointer_table_rva)

        for names_index in range(0, number_of_names):
            name_rva = MultiByteHandler.get_dword_given_offset(self.binary, name_table_raw)
            MultiByteHandler.set_dword_given_offset(self.binary, name_table_raw, name_rva + self.rva_delta)
            name_table_raw += 0x4

        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_name_pointer_table_rva_within_export_directory_table, name_pointer_table_rva + self.rva_delta)


        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_export_table_rva_within_header, export_table_rva + self.rva_delta)

    def adjust_base_relocation_table(self, header_offset):

        offset_to_base_relocation_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_RVA
        base_relocation_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_base_relocation_table_rva_within_header)

        if base_relocation_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, base_relocation_table_rva):
            return

        offset_to_base_relocation_table_size = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_RELOCATION_TABLE_SIZE
        base_relocation_table_size = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_base_relocation_table_size)

        base_relocation_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, base_relocation_table_rva)
        current_base_relocation_table_raw = base_relocation_table_raw

        while current_base_relocation_table_raw < base_relocation_table_raw + base_relocation_table_size:
            rva_of_block = MultiByteHandler.get_dword_given_offset(self.binary, current_base_relocation_table_raw)
            size_of_block = MultiByteHandler.get_dword_given_offset(self.binary, current_base_relocation_table_raw + 0x4)
            if not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, rva_of_block):
                current_base_relocation_table_raw += size_of_block
                continue

            type_rva_offset = current_base_relocation_table_raw + 0x8 #Type RVA entries start two dwords after the beginning of the block
            number_of_type_rva_entries = (int)((size_of_block - 0x8)/0x2)

            for type_rva_index in range(0, number_of_type_rva_entries):
                type_rva = MultiByteHandler.get_word_given_offset(self.binary, type_rva_offset)
                if type_rva != 0x0:
                    MultiByteHandler.set_word_given_offset(self.binary, type_rva_offset, type_rva + self.rva_delta)
                type_rva_offset += 0x2

            MultiByteHandler.set_dword_given_offset(self.binary, current_base_relocation_table_raw, rva_of_block + self.rva_delta)
            current_base_relocation_table_raw += size_of_block
        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary,  offset_to_base_relocation_table_rva_within_header, base_relocation_table_rva + self.rva_delta)

    def adjust_tls_table(self, header_offset):

        offset_to_tls_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_TLS_TABLE_RVA
        tls_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_tls_table_rva_within_header)

        if tls_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, tls_table_rva):
            return

        tls_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, tls_table_rva)

        offset_to_start_address_of_raw_data_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_START_ADDRESS_OF_RAW_DATA_WITHIN_TLS_DIRECTORY
        start_address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_start_address_of_raw_data_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary,offset_to_start_address_of_raw_data_within_tls_directory , start_address_of_raw_data + len(self.shell_code))

        offset_to_end_address_of_raw_data_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_END_OF_ADDRESS_OF_RAW_DATA_WITHIN_TLS_DIRECTORY
        end_address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_end_address_of_raw_data_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_end_address_of_raw_data_within_tls_directory, end_address_of_raw_data + len(self.shell_code))

        offset_to_address_of_index_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_INDEX_WITHIN_TLS_DIRECTORY
        address_of_index = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_address_of_index_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_address_of_index_within_tls_directory, address_of_index + len(self.shell_code))

        offset_to_address_of_callbacks_within_tls_directory = tls_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_CALLBACKS_WITHIN_TLS_DIRECTORY
        address_of_callbacks = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_address_of_callbacks_within_tls_directory)
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_address_of_callbacks_within_tls_directory, address_of_callbacks + len(self.shell_code))

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_tls_table_rva_within_header, tls_table_rva + self.rva_delta)

    def adjust_exception_table(self, header_offset):
        offset_to_exception_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_EXCEPTION_TABLE_RVA
        exception_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_exception_table_rva_within_header)

        if exception_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, exception_table_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_exception_table_rva_within_header, exception_table_rva + self.rva_delta)

    def adjust_debug(self, header_offset):
        offset_to_debug_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DEBUG_RVA
        debug_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_debug_rva_within_header)

        if debug_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, debug_rva):
            return


        debug_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, debug_rva)

        offset_to_address_of_raw_data_within_debug_directory = debug_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_ADDRESS_OF_RAW_DATA_WITHIN_DEBUG_DIRECTORY
        address_of_raw_data = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_address_of_raw_data_within_debug_directory)
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_address_of_raw_data_within_debug_directory, address_of_raw_data + self.rva_delta)

        offset_to_pointer_to_raw_data_within_debug_directory = debug_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_POINTER_TO_RAW_DATA_WITHIN_DEBUG_DIRECTORY
        pointer_to_raw_data = MultiByteHandler.get_dword_given_offset(self.binary,  offset_to_pointer_to_raw_data_within_debug_directory)
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_pointer_to_raw_data_within_debug_directory, pointer_to_raw_data + len(self.shell_code))


        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_debug_rva_within_header, debug_rva + self.rva_delta)

    def adjust_architecture_data(self, header_offset):
        offset_to_architecture_data_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ARCHITECTURE_DATA_RVA
        architecture_data_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_architecture_data_rva_within_header)

        if architecture_data_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, architecture_data_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_architecture_data_rva_within_header, architecture_data_rva + self.rva_delta)


    def adjust_global_ptr(self, header_offset):
        offset_to_global_ptr_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_GLOBAL_PTR_RVA
        global_ptr_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_global_ptr_rva_within_header)

        if global_ptr_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, global_ptr_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_global_ptr_rva_within_header, global_ptr_rva + self.rva_delta)

    def adjust_load_config_table(self, header_offset):
        offset_to_load_config_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOAD_CONFIG_TABLE_RVA
        load_config_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_load_config_table_rva_within_header)

        if load_config_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, load_config_table_rva):
            return

        load_config_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, header_offset, load_config_table_rva)


        offset_to_lock_prefix_table_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_LOCK_PREFIX_TABLE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        lock_prefix_table_va = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_lock_prefix_table_va_within_load_config_directory)
        if lock_prefix_table_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary, offset_to_lock_prefix_table_va_within_load_config_directory,  lock_prefix_table_va + self.rva_delta)

        offset_to_security_cookie_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECURITY_COOKIE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        security_cookie_va = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_security_cookie_va_within_load_config_directory)
        if security_cookie_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary, offset_to_security_cookie_va_within_load_config_directory,  security_cookie_va + self.rva_delta)

        offset_to_se_handler_table_va_within_load_config_directory = load_config_table_raw + Win32BinaryOffsetsAndSizes.OFFSET_TO_SE_HANDLER_TABLE_VA_WITHIN_LOAD_CONFIG_DIRECTORY
        se_handler_table_va = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_se_handler_table_va_within_load_config_directory)

        if se_handler_table_va != 0x0:
            MultiByteHandler.set_dword_given_offset(self.binary, offset_to_se_handler_table_va_within_load_config_directory, se_handler_table_va + self.rva_delta)

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_load_config_table_rva_within_header, load_config_table_rva + self.rva_delta)

    def adjust_bound_import(self, header_offset):
        offset_to_bound_import_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BOUND_IMPORT_RVA
        bound_import_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_bound_import_rva_within_header)

        if bound_import_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, bound_import_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_bound_import_rva_within_header, bound_import_rva + self.rva_delta)

    '''
        All the Import fields are being adjusted on another function.

    '''
    def adjust_import_address_table(self, header_offset):
        offset_to_import_address_table_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_ADDRESS_TABLE_RVA
        import_address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_address_table_rva_within_header)

        if import_address_table_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, import_address_table_rva):
            return

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_import_address_table_rva_within_header, import_address_table_rva + self.rva_delta)

    def adjust_delay_import_descriptor(self, header_offset):
        offset_to_delay_import_descriptor_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DELAY_IMPORT_DESCRIPTOR_RVA
        delay_import_descriptor_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_delay_import_descriptor_rva_within_header)

        if delay_import_descriptor_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, delay_import_descriptor_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_delay_import_descriptor_rva_within_header, delay_import_descriptor_rva + self.rva_delta)

    def adjust_clr_runtime_header(self, header_offset):
        offset_to_clr_runtime_header_rva_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_DELAY_IMPORT_DESCRIPTOR_RVA
        clr_runtime_header_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_clr_runtime_header_rva_within_header)

        if clr_runtime_header_rva == 0x0 or not Win32BinaryUtils.rva_requires_change(self.binary, header_offset, clr_runtime_header_rva):
            return
        else:
            raise NotImplementedError

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_clr_runtime_header_rva_within_header, clr_runtime_header_rva + self.rva_delta)

    def adjust_data_directories(self, header_offset):

        self.adjust_export_table(header_offset)
        self.adjust_import_table(header_offset)
        self.adjust_resource_table(header_offset)
        self.adjust_exception_table(header_offset)
        self.adjust_certificate_table(header_offset)
        self.adjust_base_relocation_table(header_offset)
        self.adjust_debug(header_offset)
        self.adjust_architecture_data(header_offset)
        self.adjust_global_ptr(header_offset)
        self.adjust_tls_table(header_offset)
        self.adjust_load_config_table(header_offset)
        self.adjust_bound_import(header_offset)
        self.adjust_import_address_table(header_offset)
        self.adjust_delay_import_descriptor(header_offset)
        self.adjust_clr_runtime_header(header_offset)

    '''
        1.Modify Virtual and Raw sizes of section containing shellcode
        2.Modify Virtual and RAW RVAs for sections coming after the section containing the shell code

    '''
    def adjust_section_headers(self, header_offset):

        entrypoint_rva_offset_within_header = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset_within_header)
        section_header_index_and_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, header_offset, entrypoint_rva)
        offset_of_header_of_section_containing_entrypoint = section_header_index_and_offset [1]


        # Set raw section size for shellcoded section
        raw_section_size_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER
        raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary, raw_section_size_offset)
        raw_section_size += len(self.shell_code)
        MultiByteHandler.set_dword_given_offset(self.binary, raw_section_size_offset, raw_section_size)

        # Set virtual section size for shellcoded section
        virtual_section_size_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
        virtual_section_size = MultiByteHandler.get_dword_given_offset(self.binary, virtual_section_size_offset)
        virtual_section_size += len(self.shell_code)
        MultiByteHandler.set_dword_given_offset(self.binary, virtual_section_size_offset, virtual_section_size)

        number_of_sections_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary, number_of_sections_offset)
        remaining_sections_after_shell_code_section = number_of_sections - (section_header_index_and_offset[0] + 1)

        # Moving to the next section header
        current_section_header_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER

        for section_index in range(0, remaining_sections_after_shell_code_section):

            virtual_section_rva_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER
            virtual_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, virtual_section_rva_offset)
            virtual_section_rva += self.rva_delta

            MultiByteHandler.set_dword_given_offset(self.binary, virtual_section_rva_offset, virtual_section_rva)

            raw_section_offset_offset =  current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER
            raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary, raw_section_offset_offset)
            raw_section_offset += len(self.shell_code)
            MultiByteHandler.set_dword_given_offset(self.binary, raw_section_offset_offset, raw_section_offset)

            current_section_header_offset += Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER


    def update_checksum(self, header_offset):

        #Clear checksum
        image_checksum_offset = header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CHECKSUM
        #checksum = MultiByteHandler.get_dword_given_offset(self.binary, image_checksum_offset)
        MultiByteHandler.set_dword_given_offset(self.binary, image_checksum_offset, 0x0)

        checksum = 0x0
        word_index = 0x0
        has_odd_byte = True if len(self.binary) % Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT == 1 else False


        while word_index < len(self.binary):
            if word_index == image_checksum_offset:
                word_index += Win32BinaryOffsetsAndSizes.CHECKSUM_SIZE
            else:
                checksum += MultiByteHandler.get_word_given_offset(self.binary, word_index)
                checksum & GenericConstants.DWORD_MASK
                #checksum += (checksum >> Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT)
                word_index += Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT

        if has_odd_byte:
            checksum += self.binary[-1]

        checksum = (checksum >> Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT*GenericConstants.BITS_PER_BYTE) + (checksum & 0xFFFF)
        checksum += (checksum >> Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT*GenericConstants.BITS_PER_BYTE)
        checksum = (checksum & 0xFFFF)
        checksum += len(self.binary)
        MultiByteHandler.set_dword_given_offset(self.binary,image_checksum_offset,checksum)

    '''
        RVAs for sections must be SectionAligned. I need to determined what is going to be the delta for the sections coming after
        the shellcode section so i can adjust headers and stuff properly.
    '''
    def set_rva_delta_for_section_alignment(self, header_offset,  raw_offset_of_header_of_section_containing_entrypoint):

        rva_for_entrypoint_section = MultiByteHandler.get_dword_given_offset(self.binary, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)
        virtual_size_of_entrypoint_section = MultiByteHandler.get_dword_given_offset(self.binary, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER)
        minimum_rva_for_next_section = (rva_for_entrypoint_section + virtual_size_of_entrypoint_section + len(self.shell_code))

        # Next section RVA
        next_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.SIZE_OF_SECTION_HEADER + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RVA_WITHIN_SECTION_HEADER)

        if minimum_rva_for_next_section < next_section_rva:
            self.rva_delta = 0
            return

        virtual_rva_delta = self.compute_padding_size_for_section_alignment(header_offset, minimum_rva_for_next_section)

        # Only the RVA for the shellcode section is affected.
        if virtual_rva_delta != 0x0:
            self.rva_delta = (minimum_rva_for_next_section + virtual_rva_delta - next_section_rva)



    def file_align_shellcode(self, header_offset, raw_offset_of_header_of_section_containing_entrypoint, entrypoint_raw_section_size):

        """
        :param raw_offset_of_header_of_section_containing_entrypoint:
        :param entrypoint_raw_section_size:
        :return: Updates public shellcode to take into account the FileAlignment specification, i.e., raw sections must have a size that is multiple of the FileAlignment
        """

        default_shell_code = self.shell_code_generator.get_shell_code()
        raw_offset_of_entrypoint_section =  MultiByteHandler.get_dword_given_offset(self.binary, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER)
        minimum_raw_offset_for_next_section = raw_offset_of_entrypoint_section + entrypoint_raw_section_size + len(default_shell_code)
        padding_size = self.compute_padding_size_for_file_alignment(header_offset, minimum_raw_offset_for_next_section)
        padded_shell_code = self.shell_code_generator.get_padded_shell_code(padding_size)
        self.shell_code = padded_shell_code




    def modify_binary(self):

        header_offset = MultiByteHandler.get_dword_given_offset(self.binary, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        #We must get the offsets for the location where the shellcode will be inserted before inserting it and before changing the headers.
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA)
        raw_offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, header_offset, entrypoint_rva)[1]

        entrypoint_raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_OFFSET_WITHIN_SECTION_HEADER)
        entrypoint_raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary, raw_offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER)

        self.file_align_shellcode(header_offset, raw_offset_of_header_of_section_containing_entrypoint,entrypoint_raw_section_size)
        self.set_rva_delta_for_section_alignment(header_offset, raw_offset_of_header_of_section_containing_entrypoint,)

        self.adjust_data_directories(header_offset)
        self.adjust_section_headers(header_offset)
        self.adjust_standard_coff_fields(header_offset)
        self.adjust_windows_specific_headers(header_offset)
        self.inject_shell_code_at_offset(entrypoint_raw_section_offset + entrypoint_raw_section_size)
        self.update_checksum(header_offset)



    def get_result(self):
        return self.binary

    def set_binary(self, binary):
        self.binary = binary

        '''
            Sections must be aligned to SectionAlignment. As such, all the sections coming after the extended section must have their RVAs adjusted.
            This variable contains the adjustment.
        '''
        self.rva_delta = 0

    def set_shell_code_generator(self, shell_code_generator):
        self.shell_code_generator = shell_code_generator


    def __init__(self):
       pass



