
# WDB Extractor

After extracting a
[`KDZ` firmware file](https://github.com/michaelwright235/kdz_decrypt_encrypt)
you'll find a WDB file – a cointainer of necessary files for flashing an old
LG phone. This python script extracts those **old** WDB files. By old LG phones
I mean models, such as KP500, GS290, KS360, etc (models from around 2008-2010).

Since the decryption key is based on the size of `Inf_WebDnld.dll` file that
may vary from model to model, some of them may be yet unsupported. If there's
no matching dll size, you may try the `-b` flag to bruteforce it. If it fails,
please file an issue on GitHub.

Known supported models: KP500, GS290, KS360, GT350, KP275, GC900, P970, GD350,
GD510, KM570, KM900, KS365.

```text
usage: wdb.py [-h] [-o O] [-b] filename

Extract WDB files for old LG phones

positional arguments:
  filename    Path to the file

options:
  -h, --help  show this help message and exit
  -o O        Output directory. By default files are extracted in the same folder
  -b          Try bruteforcing dll size to find a suitable key
```

Before running the script install dependencies via
`pip install -r requirements.txt` command.

## What is a WDB file?

A WDB file is a proprietary encrypted acrhive of files. The header, footer and
inner files are encrypted with [RC4](https://en.wikipedia.org/wiki/RC4)
algorithm. The key is based on the size of `Inf_WebDnld.dll` (this dll is
responsible of extracting WDBs) and a secret string found in it, then it's
hashed with MD5 algorithm. The size parameter may vary, however the secret
key remains the same (as far as I can tell). Every file is compressed with
`zlib` and automatically gets decompressed (this is true for the original
library behaviour too).
