class Win32SectionCreator():


    def modify_binary(self):
        raise NotImplementedError

    def __init__(self, binary_data, shell_code_generator):
        self.binary_data = binary_data
        self.shell_code_generator = shell_code_generator
        self.shell_code = shell_code_generator.get_shell_code()
        # extended section must have their RVAs adjusted. This variable contains the adjustment.
