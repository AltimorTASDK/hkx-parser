from . import bitutil
import json
import struct
import sys
from itertools import chain

class HkxException(Exception):
    def __init__(*args, **kwargs):
        super.__init__(*args, **kwargs)

class BufferReader():
    def __init__(self, data, *, offset=0):
        self.data = data
        self.offset = offset

    def clone(self, *, offset=None):
        if offset is None:
            return BufferReader(self.data, offset=self.offset)
        else:
            return BufferReader(self.data, offset=offset)

    def eof(self):
        return self.offset >= len(self.data)

    def unpack(self, format, *, peek=False, offset=0):
        # Allow partial overread for varint decoding
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

    def tell(self):
        return self.offset

    def seek(self, offset):
        self.offset = offset

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
    def __init__(self, name, flags, offset, type):
        self.name = name
        self.flags = flags
        self.offset = offset
        self.type = type

class Interface():
    def __init__(self, type, name, flags=0):
        self.type = type
        self.name = name

class TemplateParam():
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def is_type(self):
        return self.name[0] == 't'

class Type():
    def __init__(self):
        self.name       = None
        self.template   = None
        self.parent     = None
        self.opts       = 0
        self.format     = None
        self.subtype    = None
        self.version    = None
        self.size       = None
        self.align      = None
        self.flags      = None
        self.fields     = []
        self.interfaces = []
        self.attribute  = None

    def hierarchy(self):
        typ = self
        types = []
        while typ is not None:
            types.append(typ)
            typ = typ.parent
        return reversed(types)

    def all_fields(self):
        return chain(*[t.fields for t in self.hierarchy()])

    def is_pointer(self):
        return self.name == "T*"

    def is_array(self):
        return self.name == "T[N]"

    def resolve(self):
        """Resolve type aliases like hkInt32"""
        typ = self
        while typ.format is None and typ.parent is not None:
            typ = typ.parent
        return typ

    def get_name(self):
        template = self.template

        if len(template) == 0:
            return self.name

        if self.is_pointer():
            return f"{template[0].value.get_name()}*"
        if self.is_array():
            return (f"{template[0].value.get_name()}"
                    f"[{template[1].value}]")

        params = []

        for param in template:
            if param.is_type():
                params.append(param.value.get_name())
            else:
                params.append(f"{param.value}")

        return f"{self.name}<{', '.join(params)}>"

    def get_format_type(self):
        return self.format & 31

class Item():
    def __init__(self, type, flags, offset, count):
        self.type = type
        self.flags = flags
        self.offset = offset
        self.count = count
        self.value = None

    def is_pointer(self):
        return (self.flags & ItemFlag.POINTER) != 0

    def is_array(self):
        return (self.flags & ItemFlag.ARRAY) != 0

def read_string(reader):
    result = b""
    while not reader.eof():
        c = reader.read(1)
        if c == b'\x00':
            break
        result += c
    return result.decode()

def read_string_section(reader):
    strings = []
    while not reader.eof():
        strings.append(read_string(reader))
    return strings

def decode_varint(reader):
    """Returns tuple of size and value"""
    value, = reader.unpack(">Q", peek=True)
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
        return (9, reader.unpack(">Q", peek=True, offset=1)[0])

    raise HkxException(f"Bad varint encoding mode {msb:02X}")

def read_varint(reader, max_bits=None):
    size, value = decode_varint(reader)
    reader.skip(size)
    if max_bits is not None and (value >> max_bits) != 0:
        raise HkxException(f"varint is too large: {value:X}, bits {max_bits}")
    return value

def read_varint_u16(reader):
    return read_varint(reader, 16)

def read_varint_s32(reader):
    return read_varint(reader, 31)

def read_varint_u32(reader):
    return read_varint(reader, 32)

class Opt():
    FORMAT     = 0x00000001
    SUBTYPE    = 0x00000002
    VERSION    = 0x00000010
    INTERFACES = 0x00020000
    SIZE_ALIGN = 0x00800000
    FLAGS      = 0x01000000
    FIELDS     = 0x04000000
    ATTRIBUTE  = 0x10000000

class FormatType():
    VOID    = 0
    OPAQUE  = 1
    BOOL    = 2
    STRING  = 3
    INT     = 4
    FLOAT   = 5
    POINTER = 6
    RECORD  = 7
    ARRAY   = 8

class FormatFlag():
    INLINE_ARRAY = 0x00000020
    SIGNED       = 0x00000200
    INT8         = 0x00002000
    INT16        = 0x00004000
    INT32        = 0x00008000
    INT64        = 0x00010000

class ItemFlag():
    POINTER = 0x10
    ARRAY   = 0x20

def read_opts(reader):
    FLAGS = [
        Opt.FORMAT,
        Opt.SUBTYPE,
        Opt.VERSION,
        Opt.SIZE_ALIGN,
        Opt.FLAGS,
        Opt.FIELDS,
        Opt.INTERFACES,
        Opt.ATTRIBUTE
    ]
    value = read_varint_u32(reader)
    return sum(flag for i, flag in enumerate(FLAGS) if value & (1 << i))

def read_section(reader):
    size_and_flags, tag = reader.unpack(">I4s")
    flags = size_and_flags >> 30
    size = size_and_flags & ((1 << 30) - 1)
    return Section(flags, size, tag.decode())

def read_sections(reader, section_handlers):
    IndentPrint.level += 1

    while not reader.eof():
        header = read_section(reader)
        if header.tag in section_handlers:
            section_handlers[header.tag](reader, header)
        else:
            IndentPrint.print(header.tag)
            reader.skip(header.data_size)

    IndentPrint.level -= 1

class HkxParser():
    def __init__(self):
        self.data = None
        self.tstr = None
        self.fstr = None
        self.types = None
        self.items = None

    def TAG0(self, reader, header):
        read_sections(BufferReader(reader.read(header.data_size)), {
            'DATA': self.DATA,
            'INDX': self.INDX,
            'SDKV': self.SDKV,
            'TYPE': self.TYPE,
        })

    def DATA(self, reader, header):
        IndentPrint.print("DATA")
        self.data = BufferReader(reader.read(header.data_size))

    def INDX(self, reader, header):
        IndentPrint.print("INDX")
        read_sections(BufferReader(reader.read(header.data_size)), {
            'ITEM': self.ITEM
        })

    def ITEM(self, reader, header):
        IndentPrint.print("ITEM")
        inner = BufferReader(reader.read(header.data_size))
        IndentPrint.level += 1
        self.items = []
        while not inner.eof():
            self.items.append(self.read_item(inner))
        IndentPrint.level -= 1

    def SDKV(self, reader, header):
        IndentPrint.print(f"SDKV: {reader.read(header.data_size).decode()}")

    def TYPE(self, reader, header):
        IndentPrint.print("TYPE")
        read_sections(BufferReader(reader.read(header.data_size)), {
            'TSTR': self.TSTR,
            'TNA1': self.TNA1,
            'FSTR': self.FSTR,
            'TBDY': self.TBDY
        })

    def TSTR(self, reader, header):
        IndentPrint.print("TSTR")
        if self.tstr is not None:
            raise HkxException("Found multiple TSTR sections")
        inner = BufferReader(reader.read(header.data_size))
        self.tstr = read_string_section(inner)

    def TNA1(self, reader, header):
        IndentPrint.print("TNA1")
        if self.types is not None:
            raise HkxException("Found multiple TNA1 sections")
        inner = BufferReader(reader.read(header.data_size))
        count = read_varint_s32(inner)
        IndentPrint.level += 1
        self.types = [None] + [Type() for _ in range(1, count)]
        for i in range(1, count):
            self.read_type_identity(inner, self.types[i])
        IndentPrint.level -= 1

    def FSTR(self, reader, header):
        IndentPrint.print("FSTR")
        if self.fstr is not None:
            raise HkxException("Found multiple FSTR sections")
        inner = BufferReader(reader.read(header.data_size))
        self.fstr = read_string_section(inner)

    def TBDY(self, reader, header):
        IndentPrint.print("TBDY")
        inner = BufferReader(reader.read(header.data_size))
        IndentPrint.level += 1
        while not inner.eof():
            self.read_type_body(inner)
        IndentPrint.level -= 1

    def read_type_identity(self, reader, typ):
        typ.name        = self.tstr[read_varint_s32(reader)]
        typ.template    = []
        for _ in range(read_varint_s32(reader)):
            param_name = self.tstr[read_varint_s32(reader)]
            if param_name[0] == 't':
                param_value = self.types[read_varint_s32(reader)]
            else:
                param_value = read_varint_s32(reader)
            typ.template.append(TemplateParam(param_name, param_value))

    def read_type_body(self, reader):
        id = read_varint_s32(reader)
        if id == 0:
            return

        typ = self.types[id]
        typ.parent = self.types[read_varint_s32(reader)]
        typ.opts = read_opts(reader)

        if typ.opts & Opt.FORMAT:
            typ.format = read_varint_u32(reader)
        if typ.opts & Opt.SUBTYPE:
            if typ.format == 0:
                raise HkxException("Invalid type with Opt::SUBTYPE optional "
                                   "but no Opt::FORMAT.")
            typ.subtype = self.types[read_varint_s32(reader)]
        if typ.opts & Opt.VERSION:
            typ.version = read_varint_s32(reader)
        if typ.opts & Opt.SIZE_ALIGN:
            typ.size  = read_varint_u32(reader)
            typ.align = read_varint_u32(reader)
        if typ.opts & Opt.FLAGS:
            typ.flags = read_varint_u16(reader)
        if typ.opts & Opt.FIELDS:
            field_count_pair  = read_varint_s32(reader)
            field_count       = bitutil.extract(field_count_pair, 0, 15)
            placeholder_count = bitutil.extract(field_count_pair, 16, 31)
            for _ in range(field_count):
                field_name   = self.fstr[read_varint_u16(reader)]
                field_flags  = read_varint_u16(reader)
                field_offset = read_varint_u16(reader)
                field_type   = self.types[read_varint_s32(reader)]
                typ.fields.append(Field(field_name, field_flags, field_offset,
                                        field_type))
        if typ.opts & Opt.INTERFACES:
            interface_count = read_varint_s32(reader)
            for _ in range(interface_count):
                interface_type = self.types[read_varint_s32(reader)]
                interface_name = self.fstr[read_varint_s32(reader)]
                typ.interfaces.append(Interface(interface_type, interface_name))
        if typ.opts & Opt.ATTRIBUTE:
            typ.attribute = read_varint_s32(reader)

        IndentPrint.print(f"type body {id}: {typ.get_name()}")
        IndentPrint.level += 1

        if typ.parent is not None:
            IndentPrint.print(f"parent    {typ.parent.get_name()}")
        IndentPrint.print(f"opts      {typ.opts:08X}")
        if typ.format is not None:
            IndentPrint.print(f"format    {typ.format:08X} "
                                       f"({typ.get_format_type()})")
        if typ.subtype is not None:
            IndentPrint.print(f"subtype   {typ.subtype.get_name()}")
        if typ.version is not None:
            IndentPrint.print(f"version   {typ.version}")
        if typ.flags is not None:
            IndentPrint.print(f"flags     {typ.flags:02X}")
        if typ.size is not None:
            IndentPrint.print(f"size      {typ.size}")
            IndentPrint.print(f"align     {typ.align}")
        if typ.attribute is not None:
            IndentPrint.print(f"attribute {typ.attribute}")
        if len(typ.fields) != 0:
            IndentPrint.print("fields")
            IndentPrint.level += 1
            for field in typ.fields:
                IndentPrint.print(f"{field.offset:02X}: "
                                  f"{field.type.get_name()} {field.name}")
            IndentPrint.level -= 1
        if len(typ.interfaces) != 0:
            IndentPrint.print("interfaces")
            IndentPrint.level += 1
            for iface in typ.interfaces:
                if iface.name is not None:
                    IndentPrint.print(f"{iface.type.get_name()} {iface.name}")
            IndentPrint.level -= 1

        IndentPrint.level -= 1

    def read_item(self, reader):
        type_and_flags, offset, count = reader.unpack("<III")
        type_id = bitutil.extract(type_and_flags, 0, 23)
        flags   = bitutil.extract(type_and_flags, 24, 31)
        if type_id == 0:
            return None
        typ = self.types[type_id]
        IndentPrint.print("item")
        IndentPrint.level += 1
        IndentPrint.print(f"type   {typ.get_name()}")
        IndentPrint.print(f"flags  {flags:02X}")
        IndentPrint.print(f"offset {offset:08X}")
        IndentPrint.print(f"count  {count}")
        IndentPrint.level -= 1
        return Item(typ, flags, offset, count)

    def read_pointer(self, reader):
        return self.items[reader.unpack("<Q")[0]]

    def deserialize_item(self, reader, item):
        if item is None:
            return None
        if item.value is None:
            item_reader = reader.clone(offset=item.offset)
            if item.is_array():
                item.value = [self.deserialize_object(item_reader, item.type)
                                                for _ in range(item.count)]
            else:
                item.value = self.deserialize_object(item_reader, item.type)
        # Return cached value
        return item.value

    def deserialize_string(self, reader, item):
        if item is None:
            return None
        if not item.is_array():
            raise HkxException("Unexpected non-array")
        return reader.clone(offset=item.offset).read(item.count - 1).decode()

    def deserialize_object_impl(self, reader, typ, name):
        fmt = typ.format
        fmt_type = typ.get_format_type()

        if fmt_type == FormatType.BOOL:
            return reader.unpack("?")[0]

        if fmt_type == FormatType.STRING:
            return self.deserialize_string(reader, self.read_pointer(reader))

        if fmt_type == FormatType.INT:
            if fmt & FormatFlag.INT8:
                if fmt & FormatFlag.SIGNED:
                    return reader.unpack("<b")[0]
                else:
                    return reader.unpack("<B")[0]
            if fmt & FormatFlag.INT16:
                if fmt & FormatFlag.SIGNED:
                    return reader.unpack("<h")[0]
                else:
                    return reader.unpack("<H")[0]
            if fmt & FormatFlag.INT32:
                if fmt & FormatFlag.SIGNED:
                    return reader.unpack("<i")[0]
                else:
                    return reader.unpack("<I")[0]
            if fmt & FormatFlag.INT64:
                if fmt & FormatFlag.SIGNED:
                    return reader.unpack("<q")[0]
                else:
                    return reader.unpack("<Q")[0]
            raise NotImplementedError

        if fmt_type == FormatType.FLOAT:
            return reader.unpack("<f")[0]

        if fmt_type == FormatType.ARRAY and fmt & FormatFlag.INLINE_ARRAY:
            offset = reader.tell()
            result = []
            while reader.tell() < offset + typ.size:
                result.append(self.deserialize_object(reader, typ.subtype))
            return result

        if fmt_type in [FormatType.POINTER, FormatType.ARRAY]:
            item = self.read_pointer(reader)
            if item is not None and typ.subtype not in item.type.hierarchy():
                if typ.subtype.get_format_type() != FormatType.OPAQUE:
                    raise HkxException("Unexpected pointer type")
            return self.deserialize_item(reader, item)

        if fmt_type == FormatType.RECORD:
            offset = reader.tell()
            result = {}
            for f in typ.all_fields():
                reader.seek(offset + f.offset)
                result[f.name] = self.deserialize_object(reader, f.type, f.name)
            return result

        print(f"Unimplemented format type {fmt_type}")
        raise NotImplementedError

    def deserialize_object(self, reader, typ, name=None):
        real_typ = typ.resolve()
        offset = reader.tell()
        if real_typ.align is not None:
            offset = (offset + real_typ.align - 1) & ~(real_typ.align - 1)
            reader.seek(offset)
        value = self.deserialize_object_impl(reader, real_typ, name)
        if real_typ.size is not None:
            reader.seek(offset + real_typ.size)
        return value

def main():
    if len(sys.argv) < 2:
        print("Usage: hkx-parser.py <input.hkx>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    hkx = HkxParser()
    read_sections(BufferReader(data), {'TAG0': hkx.TAG0})
    value = hkx.deserialize_item(hkx.data, hkx.items[1])

    with open("output.xml", "w") as f:
        print(json.dump(value, f, indent=4))

if __name__ == "__main__":
    main()