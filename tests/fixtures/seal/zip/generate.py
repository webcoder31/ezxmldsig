"""Writes the ZIP archives of tests/fixtures/seal/zip/ with the zipfile
module of Python, a writer apart from the library: run from this directory,
`python3 -I generate.py`. The archives are committed; their content is
fixed, their dates too."""

import io
import zipfile

DATE = (2026, 10, 28, 12, 0, 0)


def entry(name, method):
    info = zipfile.ZipInfo(name, DATE)
    info.compress_type = method
    return info


class Unseekable(io.RawIOBase):
    """A stream zipfile cannot seek in: it then writes data descriptors."""

    def __init__(self):
        self.data = bytearray()

    def writable(self):
        return True

    def write(self, b):
        self.data += b
        return len(b)


# Stored and deflated entries, a UTF-8 name, a directory entry, a comment.
with zipfile.ZipFile('plain.zip', 'w') as archive:
    archive.writestr(entry('mimetype', zipfile.ZIP_STORED), b'application/vnd.etsi.asic-e+zip')
    archive.writestr(entry('docs/', zipfile.ZIP_STORED), b'')
    archive.writestr(entry('docs/résumé.txt', zipfile.ZIP_DEFLATED), 'Un résumé.\n'.encode() * 50)
    archive.writestr(entry('empty.bin', zipfile.ZIP_DEFLATED), b'')
    archive.comment = b'A comment of the archive.'

# Data descriptors (flag 0x08), with their signature.
stream = Unseekable()
with zipfile.ZipFile(stream, 'w') as archive:
    with archive.open(entry('streamed.txt', zipfile.ZIP_DEFLATED), 'w') as file:
        file.write(b'Written to a stream. ' * 100)
    with archive.open(entry('streamed-stored.txt', zipfile.ZIP_STORED), 'w') as file:
        file.write(b'Stored to a stream.')
with open('descriptor.zip', 'wb') as out:
    out.write(stream.data)
