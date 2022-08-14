import math


def sum_bytes(bytes1, bytes2, overflow=False):
    if len(bytes2) > len(bytes1):
        tmp = bytes1
        bytes1 = bytes2
        bytes2 = tmp
    l1 = len(bytes1) - 1
    l2 = len(bytes2) - 1

    res = bytearray()
    carry = 0
    for i in range(len(bytes2)):
        s = bytes1[l1 - i] + bytes2[l2 - i] + carry
        if s > 255:
            s -= 256
            carry = 1
        else:
            carry = 0
        res.append(s)

    for i in range(len(bytes2), len(bytes1)):
        s = bytes1[l1 - i] + carry
        if s > 255:
            s -= 256
            carry = 1
        else:
            carry = 0
        res.append(s)

    if not overflow and carry > 0:
        res.append(carry)
    res.reverse()

    return bytes(res)


def sum_bytes_multi(bytes_array, overflow=False):
    if len(bytes_array) < 1:
        return None

    longest_word_ind = 0
    for i in range(1, len(bytes_array)):
        if bytes_array[longest_word_ind] < bytes_array[i]:
            longest_word_ind = i

    if longest_word_ind != 0:
        tmp = bytes_array[0]
        bytes_array[0] = bytes_array[longest_word_ind]
        bytes_array[longest_word_ind] = tmp

    res = bytes_array[0]
    for i in range(1, len(bytes_array)):
        res = sum_bytes(res, bytes_array[i], overflow)

    return res


def bytes_equal(bytes1, bytes2):
    if len(bytes1) != len(bytes2):
        return False

    for b1, b2 in zip(bytes1, bytes2):
        if b1 != b2:
            return False

    return True


def leftmost(bytes_in, no_of_bits):
    bytes_out = bytearray()
    bytes_count = 0

    while bytes_count < len(bytes_in) and (bytes_count + 1)*8 <= no_of_bits:
        bytes_out.append(bytes_in[bytes_count])
        bytes_count += 1

    if bytes_count < len(bytes_in) and bytes_count*8 < no_of_bits:
        bits_diff = no_of_bits - bytes_count*8
        byte_in = bytes_in[bytes_count]
        byte_out = 0
        for i in range(bits_diff):
            if byte_in >= 2**(7-i):
                byte_out += 2**(7-i)
                byte_in -= 2**(7-i)

        bytes_out.append(byte_out)

    return bytes(bytes_out)


def int_to_bytes(int_in, no_of_bytes):
    res = bytearray()
    for i in range(no_of_bytes):
        res.append(int_in % 256)
        int_in = math.floor(int_in / 256)

    res.reverse()
    return bytes(res)


def bytes_to_string(bytes_in):
    return "b\'" + "".join(["\\x%02x" % b for b in bytes_in]) + "\'"
