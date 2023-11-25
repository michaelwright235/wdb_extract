import os
import argparse
import zlib
from Crypto.Cipher import ARC4
from Crypto.Hash import MD5

DLL_FILE_SIZE = "163840" # size of Inf_WebDnld.dll file
SECRET = "113841" # found in dll
PASSWORD = ""

# The password is based on a size of Inf_WebDnld.dll file and
# a secret string. As far as I can tell, it doesn't change from phone to phone.
for i in range(0, len(DLL_FILE_SIZE)):
    PASSWORD += chr (ord(SECRET[i % 6]) + ord(DLL_FILE_SIZE[i]))

KEY = MD5.new(bytes(PASSWORD, 'ascii')).digest()

def print_bytes(by):
    for byte in by:
        print(hex(byte), end=",")
    print()

def get_cipher():
    RC4_Cipher = ARC4.new(KEY)
    return RC4_Cipher

class WdbFile:
    def __init__(self, filename_in, out_dir) -> None:
        self.file_in = open(filename_in, 'rb')
        self.out_dir = out_dir
        if self.out_dir == None:
            self.out_dir = os.path.dirname(filename_in)
        if os.path.isdir(self.out_dir) == False:
            raise Exception("'%s' is not a directory. Check if it exists." % self.out_dir)
        self.__decrypt_header()
        self.__decrypt_footer()
        self.__find_files()
        self.__extract()

    def __del__(self):
        self.file_in.close()
        
    def __decrypt_header(self):
        header_length = int.from_bytes(self.file_in.read(4), 'little')
        #print("Header length = " + hex(header_length) + "\n")
        header: bytes = self.file_in.read(header_length)
        #print("Original:")
        #print_bytes(header)
        #print("Decrypted:")
        header_decrypted = get_cipher().decrypt(header)
        #print_bytes(header_decrypted)

        # Checks if file is correct
        if(int(header_decrypted[2*4])+int(header_decrypted[3*4])+0x10 != int(header_decrypted[0])):
            raise Exception("Invalid WDB file header") 

        header_filename_len = int(header_decrypted[2*4])
        header_sw_len = header_decrypted[3*4]

        self.wdb_file_name = header_decrypted[16:16+header_filename_len].decode('ascii')
        self.wdb_sw = header_decrypted[16+header_filename_len:16+header_filename_len+header_sw_len].decode('ascii')

        print("File name: %s" % self.wdb_file_name)
        print("SW: %s" % self.wdb_sw)
    
    def __decrypt_footer(self):
        self.file_in.seek(-4, 2) # the 4th byte from the end
        ending_byte = int.from_bytes(self.file_in.read(1), 'little')
        #print(hex(ending_byte))

        self.file_in.seek(-ending_byte-4, 2)
        footer = self.file_in.read(ending_byte)
        #print_bytes(footer)

        footer_decrypted = get_cipher().decrypt(footer)
        #print("Footer ecrypted:")
        #print_bytes(footer_decrypted)

        self.num_of_files = int(footer_decrypted[0])
        print("Number of files: %d" % self.num_of_files)

        self.files_offset = []
        for i in range(0, self.num_of_files):
            file_header_len = footer_decrypted[4+i*4:4+i*4+4]
            self.files_offset.append( int.from_bytes(file_header_len, 'little') )


    def __find_files(self):
        self.files = []
        for i in range(0, self.num_of_files):
            self.file_in.seek(self.files_offset[i], 0)
            file_header_len = self.file_in.read(4)[0]
            #print("File offset: %s" % hex(self.files_offset[i]))
            #print("File header length: %s" % hex(file_header_len))

            some = self.file_in.read(4)
            #print_bytes(some)
            file_header = self.file_in.read(file_header_len)
            file_header_decrypted = get_cipher().decrypt(file_header)
            #print_bytes(file_header_decrypted)

            header1byte = file_header_decrypted[0:4]
            len_of_filename = file_header_decrypted[4]
            filesize = int.from_bytes(file_header_decrypted[8:12], 'little')
            header4byte = file_header_decrypted[12:16]

            #print("header1byte: ", end="")
            #print_bytes(header1byte)

            filename = file_header_decrypted[16:16+len_of_filename].decode('ascii')
            print("File #%d: '%s', size = %d (zlib compressed)" % (i, filename, filesize))      
            #print("header4byte: ", end="")
            #print_bytes(header4byte)
            self.files.append({
                'name': filename,
                'size': filesize,
                'offset': self.files_offset[i],
                'header_length': file_header_len
            })

    def __extract(self):
        for file in self.files:
            self.file_in.seek(file['offset']+file['header_length']+4+4, 0)
            file_out_name = self.out_dir + os.sep + file['name'].split('\\')[1]
            print("Extracting '%s'..." % file['name'].split('\\')[1])

            raw = self.file_in.read(file['size'])
            decrypted = get_cipher().decrypt(raw)

            f_out = open(file_out_name, "wb")
            decompressed = zlib.decompress(decrypted)
            f_out.write(decompressed)
            f_out.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                        prog = 'wdb.py',
                        description = 'Extract WDB files for old LG phones')
    parser.add_argument('-o', help='Output directory. By default files are extracted in the same folder', type=str)
    parser.add_argument('filename', help='Path to the file', type=str)
    args = parser.parse_args()

    if os.path.isfile(args.filename) == False:
        print("File doesn't exist")
        exit()

    WdbFile(args.filename, args.o)
