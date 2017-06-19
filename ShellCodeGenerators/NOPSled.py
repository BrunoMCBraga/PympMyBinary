from Utils.GenericConstants import GenericConstants

class NOPSled:


    def get_base_shell_code(self, displacement):
        #Resetting to default
        self.shell_code = bytearray(self.original_shell_code_base)

        #Insert relative jump
        adjusted_displacement = displacement - len(self.shell_code) - 0x5 #Jmp relative is relative to next instruction
        word_displacement = adjusted_displacement & 0xFFFFFFFF
        jump_instruction_bytes = [0xE9,
                                  word_displacement & 0xFF,
                                  (word_displacement >> 1*GenericConstants.BITS_PER_BYTE) & 0xFF,
                                  (word_displacement >> 2 * GenericConstants.BITS_PER_BYTE) & 0xFF,
                                  (word_displacement >> 3 * GenericConstants.BITS_PER_BYTE) & 0xFF]
        self.shell_code.extend(jump_instruction_bytes)
        return self.shell_code

    #get_base_shell_code should be called first
    def get_padded_shell_code(self, padding_size):
        padding = bytearray([0x0 for x in range(0, padding_size)])
        unpadded_shell_code = bytearray(self.shell_code)
        unpadded_shell_code.extend(padding)
        return unpadded_shell_code

    def __init__(self):
        original_shell_code_base_temp = bytearray([0x90, 0x90, 0x90, 0x90])
        self.original_shell_code_base = bytearray(original_shell_code_base_temp)
        self.shell_code = bytearray(original_shell_code_base_temp)
