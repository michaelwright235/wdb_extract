
# WDB Extractor

After decrypting a
[`KDZ` firmware file](https://github.com/michaelwright235/kdz_decrypt_encrypt)
you'll find a WDB file – a cointainer of necessary files for flashing an old
LG phone. This python script extracts those **old** WDB files. By old LG phones
I mean models, such as KP500, GS290, KS360, etc (roughly models from 2008-2010).

## Supported (known) models

KP500, GS290, KS360, GT350, KP275, GC900, P970, GD350, GD510, KM570, KM900,
KS365, KH1000.

This list is not exhaustive. If you have a WDB from a different model that
fails to extract, please report it.

## Prerequisites

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```text
usage: wdb.py [-h] [-o O] [-b] filename

Extract WDB files for old LG phones

positional arguments:
  filename    Path to the file

options:
  -h, --help  show this help message and exit
  -o O        Output directory. By default, files are extracted into the same folder as the source file
  -b          Try bruteforcing the `Inf_WebDnld.dll` size to find a suitable decryption key
```

If the script cannot find a matching DLL size, try the `-b` flag.
If bruteforcing fails, please open an issue on GitHub and include the
problematic WDB and a phone model name.

## What is a WDB file?

A **WDB** file is a proprietary, encrypted archive containing files used for
LG phone updates. The header, footer and inner files are encrypted using the
[RC4](https://en.wikipedia.org/wiki/RC4) stream cipher. The decryption key is
derived from two things:

1. The size of the `Inf_WebDnld.dll` file (this may vary between models)
2. A secret string embedded in that DLL.

These values are combined and hashed (MD5) to produce the RC4 key.

Because the DLL size can differ between firmware releases and models, some
WDBs may not match the known sizes included in the script. The `-b`
option attempts to discover the correct size by trying a range of values.

After decryption, each inner file that is compressed with `zlib` is automatically
decompressed by the script (this mirrors the behavior of the original LG
library).
