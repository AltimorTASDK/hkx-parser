from . import bitutil
import struct
import sys

class HkxException(Exception):
    def __init__(*args, **kwargs):
        super.__init__(*args, **kwargs)

class BufferReader():
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def eof(self):
        return self.offset >= len(self.data)

    def unpack(self, format, *, peek=False, offset=0):
        format = f">{format}"

        start = self.offset + offset
        if start >= len(self.data):
            raise IndexError
        end = start + struct.calcsize(format)
        buffer = self.data[start:end].ljust(end - start, b'\x00')

        result = struct.unpack(format, buffer)
        if not peek:
            self.offset = end
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

class Section():
    def __init__(self, flags, size, tag):
        self.tag = tag
        self.flags = flags
        self.total_size = size
        self.data_size = size - 8

class Field():
    def __init__(self, type, name, flags=0):
        self.type = type
        self.name = name
        self.flags = flags

class TemplateParam():
    def __init__(self, name, value):
        self.name = name
        self.value = value

class TypeIdentity():
    def __init__(self, name, template):
        self.name = name
        self.template = template

def read_string(file):
    result = b""
    while not file.eof():
        c = file.read(1)
        if c == b'\x00':
            break
        result += c
    return result.decode()

def read_string_section(file):
    strings = []
    while not file.eof():
        strings.append(read_string(file))
    return strings

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
    INTERFACES = 0x00020000
    SIZE_ALIGN = 0x00800000
    UNK24      = 0x01000000
    FIELDS     = 0x04000000
    ATTRIBUTE  = 0x10000000

def read_opts(file):
    FLAGS = [
        Opt.FORMAT,
        Opt.SUBTYPE,
        Opt.VERSION,
        Opt.SIZE_ALIGN,
        Opt.UNK24,
        Opt.FIELDS,
        Opt.INTERFACES,
        Opt.ATTRIBUTE
    ]
    value = read_varint_u32(file)
    return sum(flag for i, flag in enumerate(FLAGS) if value & (1 << i))

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

class HkxParser():
    def __init__(self):
        self.tstr = None
        self.tna1 = None
        self.fstr = None

    def TAG0(self, file, header):
        read_sections(BufferReader(file.read(header.data_size)), {
            'INDX': self.INDX,
            'SDKV': self.SDKV,
            'TYPE': self.TYPE,
        })

    def INDX(self, file, header):
        IndentPrint.print("INDX")
        read_sections(BufferReader(file.read(header.data_size)), {})

    def SDKV(self, file, header):
        IndentPrint.print(f"SDKV: {file.read(header.data_size).decode()}")

    def TYPE(self, file, header):
        IndentPrint.print("TYPE")
        read_sections(BufferReader(file.read(header.data_size)), {
            'TSTR': self.TSTR,
            'TNA1': self.TNA1,
            'FSTR': self.FSTR,
            'TBDY': self.TBDY
        })

    def TSTR(self, file, header):
        IndentPrint.print("TSTR")
        if self.tstr is not None:
            raise HkxException("Found multiple TSTR sections")
        inner = BufferReader(file.read(header.data_size))
        self.tstr = read_string_section(inner)

    def TNA1(self, file, header):
        IndentPrint.print("TNA1")
        inner = BufferReader(file.read(header.data_size))
        count = read_varint_s32(inner)
        IndentPrint.level += 1
        self.tna1 = [None]
        self.tna1 += [self.read_type_identity(inner) for _ in range(1, count)]
        IndentPrint.level -= 1

    def FSTR(self, file, header):
        IndentPrint.print("FSTR")
        if self.fstr is not None:
            raise HkxException("Found multiple FSTR sections")
        inner = BufferReader(file.read(header.data_size))
        self.fstr = read_string_section(inner)

    def TBDY(self, file, header):
        IndentPrint.print("TBDY")
        inner = BufferReader(file.read(header.data_size))
        IndentPrint.level += 1
        while not inner.eof():
            self.read_type_body(inner)
        IndentPrint.level -= 1

    def get_type_name(self, id):
        identity = self.tna1[id]
        basename = self.tstr[identity.name]
        template = identity.template

        if len(template) == 0:
            return basename

        if basename == "T*":
            return f"{self.get_type_name(template[0].value)}*"
        if basename == "T[N]":
            return (f"{self.get_type_name(template[0].value)}"
                    f"[{template[1].value}]")

        params = []

        for param in template:
            name = self.tstr[param.name]
            if name[0] == 'v':
                params.append(f"{param.value}")
            elif name[0] == 't':
                params.append(self.get_type_name(param.value))
            else:
                raise NotImplementedError

        return f"{basename}<{', '.join(params)}>"

    def read_type_identity(self, file):
        name            = read_varint_s32(file)
        template_count  = read_varint_s32(file)
        template        = []

        for _ in range(template_count):
            param_name = read_varint_s32(file)
            param_value = read_varint_s32(file)
            template.append(TemplateParam(param_name, param_value))

        return TypeIdentity(name, template)

    def read_type_body(self, file):
        id = read_varint_s32(file)
        if id == 0:
            return

        parent = read_varint_s32(file)
        opts = read_opts(file)

        fmt        = 0
        subtype    = 0
        version    = None
        size       = None
        align      = None
        fields     = []
        interfaces = []
        attribute  = None

        if opts & Opt.FORMAT:
            fmt = read_varint_u32(file)
        if opts & Opt.SUBTYPE:
            if fmt == 0:
                raise HkxException("Invalid type with Opt::SUBTYPE optional "
                                   "but no Opt::FORMAT.")
            subtype = read_varint_s32(file)
        if opts & Opt.VERSION:
            version = read_varint_s32(file)
        if opts & Opt.SIZE_ALIGN:
            size  = read_varint_u32(file)
            align = read_varint_u32(file)
        if opts & Opt.UNK24:
            unk24 = read_varint_u16(file)
        if opts & Opt.FIELDS:
            field_count_pair  = read_varint_s32(file)
            field_count       = bitutil.extract(field_count_pair, 0, 15)
            placeholder_count = bitutil.extract(field_count_pair, 16, 31)
            for _ in range(field_count):
                field_name  = read_varint_u16(file)
                field_flags = read_varint_u16(file)
                field_unk   = read_varint_u16(file)
                field_type  = read_varint_s32(file)
                fields.append(Field(field_type, field_name, field_flags))
            for _ in range(placeholder_count):
                fields.append(Field(None, None))
        if opts & Opt.INTERFACES:
            interface_count = read_varint_s32(file)
            for _ in range(interface_count):
                interface_type = read_varint_s32(file)
                interface_name = read_varint_s32(file)
                interfaces.append(Field(interface_type, interface_name))
        if opts & Opt.ATTRIBUTE:
            attribute = read_varint_s32(file)

        IndentPrint.print(f"type body {self.get_type_name(id)}")
        IndentPrint.level += 1

        if parent != 0:
            IndentPrint.print(f"parent    {self.get_type_name(parent)}")
        IndentPrint.print(f"opts      {opts:08X}")
        if fmt != 0:
            IndentPrint.print(f"format    {fmt:08X} ({fmt & 0x1F})")
        if subtype != 0:
            IndentPrint.print(f"subtype   {self.get_type_name(subtype)}")
        if version is not None:
            IndentPrint.print(f"version   {version}")
        if size is not None:
            IndentPrint.print(f"size      {size}")
            IndentPrint.print(f"align     {align}")
        if attribute is not None:
            IndentPrint.print(f"attribute {attribute}")
        if len(fields) != 0:
            IndentPrint.print("fields")
            IndentPrint.level += 1
            for field in fields:
                if field.name is not None:
                    IndentPrint.print(f"{self.get_type_name(field.type)} "
                                      f"{self.fstr[field.name]}")
                else:
                    IndentPrint.print(f"$PLACEHOLDER$")
            IndentPrint.level -= 1
        if len(interfaces) != 0:
            IndentPrint.print("interfaces")
            IndentPrint.level += 1
            for field in interfaces:
                if field.name is not None:
                    IndentPrint.print(f"{self.get_type_name(field.type)} "
                                      f"{self.fstr[field.name]}")
                else:
                    IndentPrint.print(f"$PLACEHOLDER$")
            IndentPrint.level -= 1

        IndentPrint.level -= 1

def main():
    if len(sys.argv) < 2:
        print("Usage: hkx-parser.py <input.hkx>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    hkx = HkxParser()
    read_sections(BufferReader(data), {'TAG0': hkx.TAG0})

if __name__ == "__main__":
    main()