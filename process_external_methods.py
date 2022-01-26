#
# scripts/process_external_methods.py
# Brandon Azad
#
# Parse a list of IOExternalMethod or IOExternalMethodDispatch structs and print metainformation
# about the selectors in the format:
#   { selector, input_scalars_count, input_structure_size, output_scalars_count, output_structure_size }
#

import idc
import idautils
import idaapi

WORD_SIZE = 0
"""The size of a word on the current platform."""

class objectview(object):
    """A class to present an object-like view of a struct."""
    # https://goodcode.io/articles/python-dict-object/
    def __init__(self, fields, addr, size):
        self.__dict__ = fields
        self.__addr   = addr
        self.__size   = size
    def __int__(self):
        return self.__addr
    def __len__(self):
        return self.__size

def read_word(ea, wordsize=WORD_SIZE):
    """Get the word at the given address.
    Words are read using Byte(), Word(), Dword(), or Qword(), as appropriate. Addresses are checked
    using is_mapped(). If the address isn't mapped, then None is returned.
    """
    if not is_mapped(ea, wordsize):
        return None
    if wordsize == 1:
        return idc.get_wide_byte(ea)
    if wordsize == 2:
        return idc.get_wide_word(ea)
    if wordsize == 4:
        return idc.get_wide_dword(ea)
    if wordsize == 8:
        return idc.get_qword(ea)
    raise ValueError('Invalid argument: wordsize={}'.format(wordsize))

def _read_struct_member_once(ea, flags, size, member_sid, member_size, asobject):
    """Read part of a struct member for _read_struct_member."""
    if idc.is_byte(flags):
        return read_word(ea, 1), 1
    elif idc.is_word(flags):
        return read_word(ea, 2), 2
    elif idc.is_dword(flags):
        return read_word(ea, 4), 4
    elif idc.is_qword(flags):
        return read_word(ea, 8), 8
    elif idc.is_oword(flags):
        return read_word(ea, 16), 16
    elif idc.is_strlit(flags):
        return idc.GetManyBytes(ea, size), size
    elif idc.is_float(flags):
        return idc.Float(ea), 4
    elif idc.is_double(flags):
        return idc.Double(ea), 8
    elif idc.is_struct(flags):
        value = read_struct(ea, sid=member_sid, asobject=asobject)
        return value, member_size
    return None, size

def _read_struct_member(struct, sid, union, ea, offset, name, size, asobject):
    """Read a member into a struct for read_struct."""
    flags = idc.get_member_flag(sid, offset)
    assert flags != -1
    # Extra information for parsing a struct.
    member_sid, member_ssize = None, None
    if idc.is_struct(flags):
        member_sid = idc.get_member_strid(sid, offset)
        member_ssize = idc.get_struc_size(member_sid)
    # Get the address of the start of the member.
    member = ea
    if not union:
        member += offset
    # Now parse out the value.
    array = []
    processed = 0
    while processed < size:
        value, read = _read_struct_member_once(member + processed, flags, size, member_sid,
                member_ssize, asobject)
        assert size % read == 0
        array.append(value)
        processed += read
    if len(array) == 1:
        value = array[0]
    else:
        value = array
    struct[name] = value

def read_struct(ea, struct=None, sid=None, members=None, asobject=False):
    """Read a structure from the given address.
    This function reads the structure at the given address and converts it into a dictionary or
    accessor object.
    Arguments:
        ea: The linear address of the start of the structure.
    Options:
        sid: The structure ID of the structure type to read.
        struct: The name of the structure type to read.
        members: A list of the names of the member fields to read. If members is None, then all
            members are read. Default is None.
        asobject: If True, then the struct is returned as a Python object rather than a dict.
    One of sid and struct must be specified.
    """
    # Handle sid/struct.
    if struct is not None:
        sid2 = idc.get_struc_id(struct)
        if sid2 == idc.BADADDR:
            raise ValueError('Invalid struc name {}'.format(struct))
        if sid is not None and sid2 != sid:
            raise ValueError('Invalid arguments: sid={}, struct={}'.format(sid, struct))
        sid = sid2
    else:
        if sid is None:
            raise ValueError('Invalid arguments: sid={}, struct={}'.format(sid, struct))
        if idc.get_struc_name(sid) is None:
            raise ValueError('Invalid struc id {}'.format(sid))
    # Iterate through the members and add them to the struct.
    union = idc.is_union(sid)
    struct = {}
    for offset, name, size in idautils.StructMembers(sid):
        if members is not None and name not in members:
            continue
        _read_struct_member(struct, sid, union, ea, offset, name, size, asobject)
    if asobject:
        struct = objectview(struct, ea, idc.get_struc_size(sid))
    return struct

def is_mapped(ea, size=1, value=True):
    """Check if the given address is mapped.
    Specify a size greater than 1 to check if an address range is mapped.
    Arguments:
        ea: The linear address to check.
    Options:
        size: The number of bytes at ea to check. Default is 1.
        value: Only consider an address mapped if it has a value. For example, the contents of a
            bss section exist but don't have a static value. If value is False, consider such
            addresses as mapped. Default is True.
    Notes:
        This function is currently a hack: It only checks the first and last byte.
    """
    if size < 1:
        raise ValueError('Invalid argument: size={}'.format(size))
    # HACK: We only check the first and last byte, not all the bytes in between.
    if value:
        return idc.is_loaded(ea) and (size == 1 or idc.is_loaded(ea + size - 1))
    else:
        return idaapi.getseg(ea) and (size == 1 or idaapi.getseg(ea + size - 1))

def kernelcache_process_external_methods(ea=None, struct_type=None, count=None):
    kIOUCVariableStructureSize = 0xffffffff

    kIOUCTypeMask = 0xf
    kIOUCScalarIScalarO = 0
    kIOUCScalarIStructO = 2
    kIOUCStructIStructO = 3
    kIOUCScalarIStructI = 4

    kIOUCFlags = 0xff

    IOExternalMethod_types = (kIOUCScalarIScalarO, kIOUCScalarIStructO, kIOUCStructIStructO,
            kIOUCScalarIStructI)

    IOExternalMethod_count0_scalar = (kIOUCScalarIScalarO, kIOUCScalarIStructO,
            kIOUCScalarIStructI)

    IOExternalMethod_count1_scalar = (kIOUCScalarIScalarO,)

    def check_scalar(scalar_count):
        return (0 <= scalar_count <= 400)

    def check_structure(structure_size):
        return (0 <= structure_size <= 0x100000 or structure_size == kIOUCVariableStructureSize)

    def is_IOExternalMethodDispatch(obj):
        return (is_mapped(obj.function)
                and check_scalar(obj.checkScalarInputCount)
                and check_structure(obj.checkStructureInputSize)
                and check_scalar(obj.checkScalarOutputCount)
                and check_structure(obj.checkStructureOutputSize))

    def process_IOExternalMethodDispatch(obj):
        return (obj.checkScalarInputCount, obj.checkStructureInputSize,
                obj.checkScalarOutputCount, obj.checkStructureOutputSize)

    def is_IOExternalMethod(obj):
        method_type = obj.flags & kIOUCTypeMask
        check_count0 = check_scalar if method_type in IOExternalMethod_count0_scalar else check_structure
        check_count1 = check_scalar if method_type in IOExternalMethod_count1_scalar else check_structure
        return ((obj.object == 0 or is_mapped(obj.object))
                and (obj.flags & kIOUCFlags == obj.flags)
                and is_mapped(obj.func)
                and method_type in IOExternalMethod_types
                and check_count0(obj.count0)
                and check_count1(obj.count1))

    def process_IOExternalMethod(obj):
        isc, iss, osc, oss = 0, 0, 0, 0
        method_type = obj.flags & kIOUCTypeMask
        if method_type == kIOUCScalarIScalarO:
            isc, osc = obj.count0, obj.count1
        elif method_type == kIOUCScalarIStructO:
            isc, oss = obj.count0, obj.count1
        elif method_type == kIOUCStructIStructO:
            iss, oss = obj.count0, obj.count1
        elif method_type == kIOUCScalarIStructI:
            isc, iss = obj.count0, obj.count1
        else:
            assert False
        return (isc, iss, osc, oss)

    TYPE_MAP = {
            'IOExternalMethodDispatch':
                (is_IOExternalMethodDispatch, process_IOExternalMethodDispatch),
            'IOExternalMethod': (is_IOExternalMethod, process_IOExternalMethod),
    }

    # Get the EA.
    if ea is None:
        ea = idc.get_screen_ea()

    # Get the struct_type and the check and process functions.
    if struct_type is None:
        for stype in TYPE_MAP:
            struct_type = stype
            check, process = TYPE_MAP[struct_type]
            obj = read_struct(ea, struct=struct_type, asobject=True)
            if check(obj):
                break
        else:
            print('Address {:#x} does not look like any known external method struct'.format(ea))
            return False
    else:
        if struct_type not in TYPE_MAP:
            print('Unknown external method struct type {}'.format(struct_type))
            return False
        check, process = TYPE_MAP[struct_type]
        obj = read_struct(ea, struct=struct_type, asobject=True)
        if not check(obj):
            print('Address {:#x} does not look like {}'.format(ea, struct_type))

    # Process the external methods.
    selector = 0;
	#count or 0 to get around NoneType errors in Python3
    while (count is None and check(obj)) or (selector < int(count or 0)):
        isc, iss, osc, oss = process(obj)
        print('{{ {:3}, {:5}, {:#10x}, {:5}, {:#10x} }}'.format(selector, isc, iss, osc, oss))
        selector += 1
        ea += len(obj)
        obj = read_struct(ea, struct=struct_type, asobject=True)

    return True

kernelcache_process_external_methods()
