def mask(value, start_bit, end_bit):
    return value & (((1 << (end_bit - start_bit + 1)) - 1) << start_bit)

def extract(value, start_bit, end_bit):
    """Mask and shift so first bit of mask is the new LSB"""
    return mask(value, start_bit, end_bit) >> start_bit

def reverse_mask64(value, start_bit, end_bit):
    """PowerPC style bit mask"""
    return mask(value, 63 - end_bit, 63 - start_bit)

def reverse_extract64(value, start_bit, end_bit):
    """PowerPC style bit mask (and shift so first bit of mask is the new LSB)"""
    return extract(value, 63 - end_bit, 63 - start_bit)