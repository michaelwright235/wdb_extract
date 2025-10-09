import os
import argparse
import zlib
from Crypto.Cipher import ARC4
from Crypto.Hash import MD5

# Size of Inf_WebDnld.dll file. May vary from model to model
DLL_FILE_SIZES = [
    "163840", # KP500, GS290, KS360, GC900, GD350, GD510, KM570, KM900, KS365
    "176128", # GT350
    "155648", # KP275
    "278528", # P970
]
SECRET = "113841" # found in dll

def print_bytes(by):
    for byte in by:
        print(hex(byte), end=",")
    print()

def get_keys():
    keys = []
    for size in DLL_FILE_SIZES:
        # The password is based on a size of Inf_WebDnld.dll file and
        # a secret string. As far as I can tell, the secret doesn't change from phone to phone.
        password = ""
        for i in range(0, len(size)):
            password += chr (ord(SECRET[i % 6]) + ord(size[i]))
        key = MD5.new(bytes(password, 'ascii')).digest()
        keys.append((key, size))
    return keys

def bruteforce_keys():
    keys = []
    for size1 in range(0, 900000):
        size = "%06d" % (size1)
        password = ""
        for i in range(0, len(size)):
            password += chr (ord(SECRET[i % 6]) + ord(size[i]))
        key = MD5.new(bytes(password, 'ascii')).digest()
        keys.append((key, size))
    return keys

class WdbFile:
    def __init__(self, filename_in, out_dir, bruteforce) -> None:
        self.file_in = open(filename_in, 'rb')
        self.out_dir = out_dir
        if self.out_dir == None:
            self.out_dir = os.path.dirname(os.path.realpath(__file__))
        if os.path.isdir(self.out_dir) == False:
            raise Exception("'%s' is not a directory. Check if it exists." % self.out_dir)

        if bruteforce == False:
            self.__find_key()
            self.__decrypt_header()
        else:
            keys = bruteforce_keys()
            for (key, dll_size) in keys:
                self.key = key
                try:
                    self.file_in.seek(0)
                    self.__decrypt_header()
                except (Exception, IndexError):
                    self.key = ""
                else:
                    print("Found a suitable key (dll size = %s)" % (dll_size))
            if self.key == "":
                print("Bruteforcing failed, couldn't find a suitable key. Please, report an issue on GitHub.")
                return

        self.__decrypt_footer()
        self.__find_files()
        self.__extract()

    def __del__(self):
        self.file_in.close()

    def __find_key(self):
        header_length = int.from_bytes(self.file_in.read(4), 'little')
        header: bytes = self.file_in.read(header_length)
        keys = get_keys()
        for (key, dll_size) in keys:
            cipher = ARC4.new(key)
            header_decrypted = cipher.decrypt(header)
            if(int(header_decrypted[2*4])+int(header_decrypted[3*4])+0x10 == int(header_decrypted[0])):
                print("Found a suitable decryption key (dll size = %s)" % (dll_size))
                self.key = key
        self.file_in.seek(0)
        if hasattr(self, "key") == False:
            raise Exception("Cannot find a suitable decryption key. You may try bruteforcing (-b flag).")

    def __get_cipher(self):
        return ARC4.new(self.key)

    def __decrypt_header(self):
        header_length = int.from_bytes(self.file_in.read(4), 'little')
        #print("Header length = " + hex(header_length) + "\n")
        header: bytes = self.file_in.read(header_length)
        #print("Original:")
        #print_bytes(header)
        #print("Decrypted:")
        header_decrypted = self.__get_cipher().decrypt(header)
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

        footer_decrypted = self.__get_cipher().decrypt(footer)
        #print("Footer encrypted:")
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
            file_header_decrypted = self.__get_cipher().decrypt(file_header)
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
            decrypted = self.__get_cipher().decrypt(raw)

            f_out = open(file_out_name, "wb")
            decompressed = zlib.decompress(decrypted)
            f_out.write(decompressed)
            f_out.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                        prog = 'wdb.py',
                        description = 'Extract WDB files for old LG phones')
    parser.add_argument('-o', help='Output directory. By default files are extracted in the same folder', type=str)
    parser.add_argument('-b', help='Try bruteforcing dll size to find a suitable key', action='store_true')
    parser.add_argument('filename', help='Path to the file', type=str)
    args = parser.parse_args()

    if os.path.isfile(args.filename) == False:
        print("File doesn't exist")
        exit()

    WdbFile(args.filename, args.o, args.b)
