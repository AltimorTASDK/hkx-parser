from . import bitutil
import struct
import sys

class HkxException(Exception):
    def __init__(*args, **kwargs):
        super.__init__(*args, **kwargs)

class FileBuffer():
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def eof(self):
        return self.offset >= len(self.data)

    def unpack(self, format, *, peek=False, offset=0):
        format = f">{format}"
        result = struct.unpack_from(format, self.data, self.offset + offset)
        if not peek:
            self.offset += struct.calcsize(format) + offset
        return result

    def read(self, count, *, peek=False, offset=0):
        result = self.data[self.offset+offset:self.offset+offset+count]
        if not peek:
            self.offset += count + offset
        return result

    def skip(self, count):
        self.offset += count

class IndentPrint():
    level = -1
    @staticmethod
    def print(*args, **kwargs):
        print("    " * max(IndentPrint.level, 0), end="")
        print(*args, **kwargs)

class SectionHandlers():
    @staticmethod
    def TAG0(file, header):
        read_sections(FileBuffer(file.read(header.data_size)), {
            'INDX': SectionHandlers.INDX,
            'SDKV': SectionHandlers.SDKV,
            'TYPE': SectionHandlers.TYPE,
        })

    @staticmethod
    def INDX(file, header):
        IndentPrint.print("INDX")
        read_sections(FileBuffer(file.read(header.data_size)), {})

    @staticmethod
    def SDKV(file, header):
        IndentPrint.print(f"SDKV: {file.read(header.data_size).decode()}")

    @staticmethod
    def TBDY(file, header):
        IndentPrint.print("TBDY")
        inner = FileBuffer(file.read(header.data_size))
        IndentPrint.level += 1
        while not inner.eof():
            read_type_body(inner)
            break
        IndentPrint.level -= 1

    @staticmethod
    def TYPE(file, header):
        IndentPrint.print("TYPE")
        read_sections(FileBuffer(file.read(header.data_size)), {
            'TBDY': SectionHandlers.TBDY
        })

class Section():
    def __init__(self, flags, size, tag):
        self.tag = tag
        self.flags = flags
        self.total_size = size
        self.data_size = size - 8

class HkField():
    def __init__(self, type, name):
        self.type = type
        self.name = name

def decode_varint(file):
    """Returns tuple of size and value"""
    value, = file.unpack("Q", peek=True)
    msb = bitutil.reverse_extract64(value, 0, 7)
    mode = msb >> 3

    if mode <= 15:
        return (1, msb)
    if mode <= 23:
        return (2, bitutil.reverse_extract64(value, 2, 16 - 1))
    if mode <= 27:
        return (3, bitutil.reverse_extract64(value, 3, 24 - 1))
    if mode == 28:
        return (4, bitutil.reverse_extract64(value, 5, 32 - 1))
    if mode == 29:
        return (5, bitutil.reverse_extract64(value, 5, 40 - 1))
    if mode == 30:
        return (8, bitutil.reverse_extract64(value, 5, 64 - 1))
    if mode == 31 and (msb & 7) == 0:
        return (6, bitutil.reverse_extract64(value, 8, 48 - 1))
    if mode == 31 and (msb & 7) == 1:
        return (9, file.unpack("Q", peek=True, offset=1)[0])

    raise HkxException(f"Bad varint encoding mode {msb:02X}")

def read_varint(file, max_bits=None):
    size, value = decode_varint(file)
    file.skip(size)
    if max_bits is not None and (value >> max_bits) != 0:
        raise HkxException(f"varint is too large: {value:X}, bits {max_bits}")
    return value

def read_varint_u16(file):
    return read_varint(file, 16)

def read_varint_s32(file):
    return read_varint(file, 31)

def read_varint_u32(file):
    return read_varint(file, 32)

class Opt():
    FORMAT     = 0x00000001
    SUBTYPE    = 0x00000002
    VERSION    = 0x00000010
    FIELDS     = 0x00020000
    SIZE_ALIGN = 0x00800000
    UNK24      = 0x01000000
    STRUCT     = 0x04000000
    ATTRIBUTES = 0x10000000

def read_type_body(file):
    id     = read_varint_s32(file)
    parent = read_varint_s32(file)
    opts   = read_varint_u32(file)

    fmt     = 0
    version = 0
    size    = 0
    align   = 0
    fields  = []

    if opts & Opt.FORMAT:
        fmt = read_varint_u32(file)

    if opts & Opt.SUBTYPE:
        if fmt == 0:
            raise HkxException("Invalid type with Opt::SUBTYPE optional but no "
                               "Opt::FORMAT.")
    else:
        if opts & Opt.VERSION:
            version = read_varint_s32(file)
        if opts & Opt.SIZE_ALIGN:
            size  = read_varint_u32(file)
            align = read_varint_u32(file)
        if opts & Opt.UNK24:
            unk24 = read_varint_u16(file)
        if opts & Opt.STRUCT:
            raise NotImplementedError
        else:
            if opts & Opt.FIELDS:
                field_count = read_varint_s32(file)
                for _ in range(field_count):
                    type = read_varint_s32(file)
                    name = read_varint_s32(file)
                    fields.append(HkField(type, name))

    IndentPrint.print(f"type body {id}")
    IndentPrint.level += 1
    IndentPrint.print(f"parent  {parent}")
    IndentPrint.print(f"opts    {opts:08X}")
    IndentPrint.print(f"format  {fmt}")
    IndentPrint.print(f"version {version}")
    IndentPrint.print(f"size    {size}")
    IndentPrint.print(f"align   {align}")
    IndentPrint.print("fields")
    IndentPrint.level += 1
    for field in fields:
        IndentPrint.print(f"{field.type} {field.name}")
    IndentPrint.level -= 1
    IndentPrint.level -= 1

def read_section(file):
    size_and_flags, tag = file.unpack("I4s")
    flags = size_and_flags >> 30
    size = size_and_flags & ((1 << 30) - 1)
    return Section(flags, size, tag.decode())

def read_sections(file, section_handlers):
    IndentPrint.level += 1

    while not file.eof():
        header = read_section(file)
        if header.tag in section_handlers:
            section_handlers[header.tag](file, header)
        else:
            IndentPrint.print(header.tag)
            file.skip(header.data_size)

    IndentPrint.level -= 1

def main():
    if len(sys.argv) < 2:
        print("Usage: hkx-parser.py <input.hkx>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    read_sections(FileBuffer(data), {'TAG0': SectionHandlers.TAG0})

if __name__ == "__main__":
    main()