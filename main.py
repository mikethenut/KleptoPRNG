import re

from implementations.HashDRBG import HashDRBG
from implementations.KleptoHashDRBG import KHashDRBG1, KHashDRBG2
from helpers.DRBG_status import DRBGStatus, DRBG_status_to_string
from helpers.general_helpers import bytes_to_string
from testing.subversion_test import test_throughput, test_speed, plot_efficiency


def generate_sample_outputs_hash(HashDRBGImpl, total_bits_per_hash):
    bits_per_generate = 1024
    for hash_fun in ["SHA-224", "SHA-512/224", "SHA3-224", "SHA-256", "SHA-512/256", "SHA3-256",
                     "SHA-384", "SHA3-384", "SHA-512", "SHA3-512"]:

        HashPRNG = HashDRBGImpl(hash_fun)
        status, state_handle = HashPRNG.instantiate()
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            exit(1)

        f = open("outputs/K2" + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + ".bin", "wb")
        total_bits_written = 0
        while total_bits_written < total_bits_per_hash:

            status, bits = HashPRNG.generate(state_handle, bits_per_generate)
            if status != DRBGStatus.SUCCESS:
                print(DRBG_status_to_string(status))
                break

            f.write(bits)
            total_bits_written += bits_per_generate

        f.close()


if __name__ == "__main__":
    generate_sample_outputs_hash(HashDRBG, 1000000)
