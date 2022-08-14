import re
from Crypto.Hash import SHA1, HMAC

from implementations.HashDRBG import HashDRBG
from implementations.KleptoHashDRBG import KHashDRBG1, KHashDRBG2
from helpers.DRBG_status import DRBGStatus, DRBG_status_to_string
from helpers.general_helpers import bytes_to_string


def generate_sample_outputs_hash(total_bits_per_hash):
    bits_per_generate = 1024
    for hash_fun in ["SHA-224", "SHA-512/224", "SHA3-224", "SHA-256", "SHA-512/256", "SHA3-256",
                     "SHA-384", "SHA3-384", "SHA-512", "SHA3-512"]:

        HashPRNG = HashDRBG(hash_fun)
        status, state_handle = HashPRNG.instantiate()
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            exit(1)

        f = open("outputs/" + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + ".bin", "wb")
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
    seedlen = 888

    KHashPRNG = KHashDRBG1(hash_fun)
    status, state_handle = KHashPRNG.instantiate()
    if status != DRBGStatus.SUCCESS:
        print(DRBG_status_to_string(status))
        exit(1)
    else:  # generated constant in bits
        print(format(int.from_bytes(KHashPRNG._DRBG__states[state_handle].get_C(), "big"), "b").zfill(seedlen))

    constant = list("x" * seedlen)
    pkey = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])

    for i in range(2*seedlen):
        status, bits = KHashPRNG.generate(state_handle, 32, prediction_resistance_request=False)
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            break

        decoded = HMAC.new(pkey, msg=bits, digestmod=SHA1).digest()
        d_loc = (int.from_bytes(decoded[:2], "big") % seedlen) + 1
        d_value = decoded[2] % 2

        constant[-d_loc] = str(d_value)

    print("".join(constant))


if __name__ == "__main__":
    print(1e6)
    generate_sample_outputs_hash(1e6)
