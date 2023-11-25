import os
import argparse
from Crypto.Cipher import ARC4
from Crypto.Hash import MD5

def print_bytes(by):
    for byte in by:
        print(hex(byte), end=",")
    print()

def bytes_to_int(by: bytes) -> int:
    result = bytearray()
    for byte in by:
        if byte != r'\x00' and byte != None:
            result.append(byte)    
    int.from_bytes(result, 'little')

def get_cipher():
    pswd = "bgfpha"
    key = MD5.new(bytes(pswd, 'ascii')).digest()
    RC4_Cipher = ARC4.new(key)
    return RC4_Cipher

class WdbFile:
    def __init__(self, filename_in) -> None:
        self.file_in = open(filename_in, 'rb')
        self.__decrypt_header()
        self.__decrypt_footer()
        self.__find_files()

    def __del__(self):
        self.file_in.close()
        
    def __decrypt_header(self):
        header_length = bytes_to_int(self.file_in.read(4))
        #print("Header length = " + hex(header_length) + "\n")
        header: bytes = self.file_in.read(header_length)
        #print("Original:")
        #print_bytes(header)
        #print("Decrypted:")
        header_decrypted = get_cipher().decrypt(header)
        #print_bytes(header_decrypted)

        # Checks if file is correct
        if(int(header_decrypted[2*4])+int(header_decrypted[3*4])+0x10 != int(header_decrypted[0])):
            raise Exception("Invalid file header") 

        header_filename_len = int(header_decrypted[2*4])
        header_sw_len = header_decrypted[3*4]

        self.wdb_file_name = header_decrypted[16:16+header_filename_len].decode('ascii')
        self.wdb_sw = header_decrypted[16+header_filename_len:16+header_filename_len+header_sw_len].decode('ascii')

        print("File name: %s" % self.wdb_file_name)
        print("SW: %s" % self.wdb_sw)
    
    def __decrypt_footer(self):
        self.file_in.seek(-4, 2) # от конца 4-ый байт
        ending_byte = int.from_bytes(self.file_in.read(1), 'little')
        #print(hex(ending_byte))

        self.file_in.seek(-ending_byte-4, 2)
        footer = self.file_in.read(ending_byte)
        #print_bytes(footer)

        footer_decrypted = get_cipher().decrypt(footer)
        #print("Footer ecrypted:")
        #print_bytes(footer_decrypted)

        #!
        self.num_of_files = int(footer_decrypted[0])
        print("Number of files: %d" % self.num_of_files)

        #self.files_offset = footer_decrypted[4]

        self.files_offset = []
        for i in range(0, self.num_of_files):
            #self.file_in.seek(-footer_decrypted[4] - i*4, 2)
            file_header_len = footer_decrypted[4+i*4:4+i*4+4]
            self.files_offset.append( int.from_bytes(file_header_len, 'little') )


    def __find_files(self):
        for i in range(0, self.num_of_files):
            print()
            self.file_in.seek(self.files_offset[i], 0)
            file_header_len = self.file_in.read(4)[0]
            print("File offset: %s" % hex(self.files_offset[i]))
            print("File header length: %s" % hex(file_header_len))

            some = self.file_in.read(4)
            print_bytes(some)
            file_header = self.file_in.read(file_header_len)
            file_header_decrypted = get_cipher().decrypt(file_header)
            #print_bytes(file_header_decrypted)

            header1byte = file_header_decrypted[0:4]
            len_of_filename = file_header_decrypted[4]
            header3byte = file_header_decrypted[8:12]
            header4byte = file_header_decrypted[12:16]

            print("header1byte: ", end="")
            print_bytes(header1byte)

            filename = file_header_decrypted[16:16+len_of_filename].decode('ascii')
            print("File name: %s" % filename)

            print("header3byte: ", end="")
            print_bytes(header3byte)            
            print("header4byte: ", end="")
            print_bytes(header4byte)

            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                        prog = 'wdb.py',
                        description = 'Extract WDB file for old LG phones')
    parser.add_argument('-d', help='Decrypt KDZ file', action='store_true')
    parser.add_argument('-e', help='Encrypt CAB file', action='store_true')
    parser.add_argument('-o', help='Output filename. By default the converted file is saved in the same folder.', type=str)
    parser.add_argument('filename', help='Path to the file', type=str)
    args = parser.parse_args()

    if os.path.isfile(args.filename) == False:
        print("File doesn't exist")
        exit()

    if args.d == True:
        WdbFile(args.filename)
