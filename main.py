import re
import time
from Crypto.Hash import SHA512, HMAC

from implementations.HashDRBG import HashDRBG
from implementations.KleptoHashDRBG import KHashDRBG1, KHashDRBG2
from helpers.DRBG_status import DRBGStatus, DRBG_status_to_string
from helpers.general_helpers import bytes_to_string
from kat.kat_create_db import create_hash_kat


def generate_sample_outputs_hash(total_bits_per_hash):
    bits_per_generate = 1024
    for hash_fun in ["SHA-224", "SHA-512/224", "SHA3-224", "SHA-256", "SHA-512/256", "SHA3-256",
                     "SHA-384", "SHA3-384", "SHA-512", "SHA3-512"]:

        HashPRNG = KHashDRBG1(hash_fun)
        status, state_handle = HashPRNG.instantiate()
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            exit(1)

        f = open("outputs/K1" + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + ".bin", "wb")
        total_bits_written = 0
        while total_bits_written < total_bits_per_hash:

            status, bits = HashPRNG.generate(state_handle, bits_per_generate)
            if status != DRBGStatus.SUCCESS:
                print(DRBG_status_to_string(status))
                break

            f.write(bits)
            total_bits_written += bits_per_generate

        f.close()


def test_attack():
    hash_fun = "SHA-512"
    hash_implementation = SHA512
    seedlen = 888
    pkey = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])

    KHashPRNG = KHashDRBG1(hash_fun, pkey)
    status, state_handle = KHashPRNG.instantiate()
    if status != DRBGStatus.SUCCESS:
        print(DRBG_status_to_string(status))
        exit(1)
    else:  # generated constant in bits
        secret = format(int.from_bytes(KHashPRNG._DRBG__states[state_handle].get_C(), "big"), "b").zfill(seedlen)
        print(secret)

    constant = [[0, 0] for i in range(seedlen)]  # observations for 0s and 1s

    for i in range(seedlen):
        status, bits = KHashPRNG.generate(state_handle, 32, prediction_resistance_request=False)
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            break

        decoded = HMAC.new(pkey, msg=bits, digestmod=SHA512).digest()

        for b in range(4):
            block = format(int.from_bytes(decoded[b * 11:(b + 1) * 11], "big"), "b").zfill(88)
            for d in range(8):
                d_loc = (int(block[d * 10:(d + 1) * 10], 2) % seedlen) + 1
                d_value = int(block[80 + d])

                constant[-d_loc][d_value] += 1

    constant_string = ""
    for c in constant:
        if c[0] > c[1]:
            constant_string += "0"
        elif c[1] > c[0]:
            constant_string += "1"
        else:
            constant_string += "x"

    print(constant_string)

    equal = 0
    different = 0
    unknown = 0
    for c, s in zip(constant_string, secret):
        if c == 'x':
            unknown += 1
        elif c == s:
            equal += 1
        else:
            different += 1

    print("%d correct, %d incorrect, %d unknown" % (equal, different, unknown))


def test_speed():
    hash_fun = "SHA-512"
    iters = 10000

    HashPRNG = HashDRBG(hash_fun)
    status, state_handle = HashPRNG.instantiate()
    if status != DRBGStatus.SUCCESS:
        print(DRBG_status_to_string(status))
        exit(1)

    start = time.perf_counter()
    for i in range(iters):
        status, bits = HashPRNG.generate(state_handle, 512, prediction_resistance_request=False)
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            break
    end = time.perf_counter()
    print("Hash %d gens in %0.4f seconds" % (iters, end - start))

    KHashPRNG = KHashDRBG1(hash_fun)
    status, state_handle = KHashPRNG.instantiate()
    if status != DRBGStatus.SUCCESS:
        print(DRBG_status_to_string(status))
        exit(1)

    start = time.perf_counter()
    for i in range(iters):
        status, bits = KHashPRNG.generate(state_handle, 512, prediction_resistance_request=False)
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            break
    end = time.perf_counter()
    print("KHash1 %d gens in %0.4f seconds" % (iters, end - start))

    KHashPRNG = KHashDRBG2(hash_fun)
    status, state_handle = KHashPRNG.instantiate()
    if status != DRBGStatus.SUCCESS:
        print(DRBG_status_to_string(status))
        exit(1)

    start = time.perf_counter()
    for i in range(iters):
        status, bits = KHashPRNG.generate(state_handle, 512, prediction_resistance_request=False)
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            break
    end = time.perf_counter()
    print("KHash2 %d gens in %0.4f seconds" % (iters, end - start))


if __name__ == "__main__":
    test_speed()
