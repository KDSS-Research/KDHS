import random
import os
import pefile

# charset for analyse file (like: f-1-2_j-5-3)

charset = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm'
charset_output = 'qwertyuiopasdfghjklzxcvbnm'

# main kdhs class
class kdhs:
    # constructor for variables
    
    def __init__(self, file):
        self.file = file
        
    # get hash of file function
    
    def gethash(self):
        self.finalhash = ''
        self.kdhs_lines = []
        self.pe = pefile.PE(self.file)
        self.kdhs_is_exe = os.path.splitext(self.file)[1]
        try:
            while True: # while: file reading (lines)
        
                self.kdhs_line_f_append = self.fh.readline() # Line for append
            
                self.kdhs_lines.append(self.kdhs_line_f_append.strip()) # Append line to kdhs_lines list
            
                if not self.kdhs_line_f_append:
                    break
            self.kdhs_plug = None
            for i in range(0, len(self.kdhs_lines)):
                for i2 in range(0, len(charset)):
                    self.kdhs_lines_line = self.kdhs_lines[i]
                    self.kdhs_inline = self.kdhs_lines_line.find(charset[i2]) != -1 # in line?
                    if self.kdhs_inline == False:
                        self.kdhs_plug = None
                    else:
                        self.kdhs_finalhash_temp = str(charset[i2]) + '-' + str(i) + '-' + str(self.kdhs_lines_line.find(charset[i2])) + "_" # generate line hash
                        self.finalhash += self.kdhs_finalhash_temp # final method in while
            self.kdhs_finalhash_len = len(self.finalhash)
            return(self.finalhash[:self.kdhs_finalhash_len-1])
        except:
            self.kdhs_exe_bytes = os.path.getsize(self.file)
            self.kdhs_lines.append(str(self.pe.sections[0].get_data()[:self.kdhs_exe_bytes]))
            self.kdhs_plug = None
            for i in range(0, len(self.kdhs_lines)):
                for i2 in range(0, len(charset)):
                    self.kdhs_lines_line = self.kdhs_lines[i]
                    self.kdhs_inline = self.kdhs_lines_line.find(charset[i2]) != -1 # in line?
                    if self.kdhs_inline == False:
                        self.kdhs_plug = None
                    else:
                        self.kdhs_finalhash_temp = str(charset[i2]) + '-' + str(i) + '-' + str(self.kdhs_lines_line.find(charset[i2])) + "_" # generate line hash
                        self.finalhash += self.kdhs_finalhash_temp # final method in while
            self.kdhs_finalhash_len = len(self.finalhash)
            return(self.finalhash[:self.kdhs_finalhash_len-1])

