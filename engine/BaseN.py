import string
digs = string.digits + string.ascii_lowercase

def int2base(x, base):
    if base == 16:
        return hex(x)[2:]
    elif base == 10:
        return str(x)
    else:
        return None


def base2int(x):
    if x[0:2] == '0x' or x[0:2] == '0X':
        return int(x, 16)
    else:
        return int(x)