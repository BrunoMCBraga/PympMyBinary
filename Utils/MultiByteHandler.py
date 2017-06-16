from Utils.GenericConstants import GenericConstants

class MultiByteHandler:

    @staticmethod
    def get_dword_given_offset(binary_data, offset):
        return binary_data[offset] + \
               (binary_data[offset + 1] << GenericConstants.BITS_PER_BYTE) + \
               (binary_data[offset + 2] << 2 * GenericConstants.BITS_PER_BYTE) + \
               (binary_data[offset + 3] << 3 * GenericConstants.BITS_PER_BYTE)

    @staticmethod
    def set_dword_given_offset(binary_data, offset, dword):
        binary_data[offset] = (dword & 0xFF)
        binary_data[offset + 1] = ((dword >> GenericConstants.BITS_PER_BYTE) & 0xFF)
        binary_data[offset + 2] = ((dword >> 2 * GenericConstants.BITS_PER_BYTE) & 0xFF)
        binary_data[offset + 3] = ((dword >> 3 * GenericConstants.BITS_PER_BYTE) & 0xFF)

    @staticmethod
    def get_word_given_offset(binary_data, offset):
        return binary_data[offset] + (binary_data[offset + 1] << GenericConstants.BITS_PER_BYTE)

    @staticmethod
    def set_word_given_offset(binary_data, offset, word):
        binary_data[offset] = (word & 0xFF)
        binary_data[offset + 1] = ((word >> GenericConstants.BITS_PER_BYTE) & 0xFF)
