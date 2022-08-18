import math
import time
import random

from Crypto.Hash import SHA512, HMAC
import matplotlib.pyplot as plt

from implementations.HashDRBG import HashDRBG
from helpers.DRBG_status import DRBGStatus, DRBG_status_to_string


def test_throughput(KHashDRBGImpl, instantiations=100, requests_per_instantiation=100,
                    max_leaked_bits=8, max_extra_attempts=10):
    hash_fun = "SHA-512"
    hash_implementation = SHA512
    seedlen = 888

    pkey = bytes([random.randrange(256) for r in range(32)])
    fig, axes = plt.subplots(figsize=(12, 8))
    f = open("testing/tmp_info.txt", "w")

    for leaked_bits in range(1, max_leaked_bits + 1):
        leaked_info = []

        for extra_attempts in range(max_extra_attempts + 1):
            KHashPRNG = KHashDRBGImpl(hash_fun, pkey, extra_attempts, leaked_bits)
            lbatch_count = math.ceil(leaked_bits / 8)
            final_lbatch_size = leaked_bits - (lbatch_count - 1) * 8
            correct_leaks = 0
            incorrect_leaks = 0

            for a in range(instantiations):
                status, state_handle = KHashPRNG.instantiate()
                if status != DRBGStatus.SUCCESS:
                    print(DRBG_status_to_string(status))
                    exit(1)
                else:  # generated constant in bits
                    secret = format(int.from_bytes(KHashPRNG._DRBG__states[state_handle].get_C(),
                                                   "big"), "b").zfill(seedlen)

                for b in range(requests_per_instantiation):
                    status, bits = KHashPRNG.generate(state_handle, 512, prediction_resistance_request=False)
                    if status != DRBGStatus.SUCCESS:
                        print(DRBG_status_to_string(status))
                        break

                    decoded = HMAC.new(pkey, msg=bits, digestmod=SHA512).digest()

                    for b in range(lbatch_count):
                        lbatch = format(int.from_bytes(decoded[b * 11:(b + 1) * 11], "big"), "b").zfill(88)
                        if b < lbatch_count - 1:
                            lbatch_size = 8
                        else:
                            lbatch_size = final_lbatch_size

                        for d in range(lbatch_size):
                            d_loc = (int(lbatch[d * 10:(d + 1) * 10], 2) % seedlen) + 1
                            d_value = lbatch[80 + d]

                            if secret[-d_loc] == d_value:
                                correct_leaks += 1
                            else:
                                incorrect_leaks += 1

            accuracy = correct_leaks / (correct_leaks + incorrect_leaks)
            if accuracy <= 0.9999:
                missing_information = - accuracy * math.log2(accuracy) - (1 - accuracy) * math.log2(1 - accuracy)
            else:
                missing_information = 0.

            gained_info = leaked_bits * (1. - missing_information)
            print("%d bits, %d attempts: %d correct, %d incorrect, %0.4f accuracy, %0.4f information" %
                  (leaked_bits, extra_attempts, correct_leaks, incorrect_leaks,
                   accuracy, gained_info))
            leaked_info.append(gained_info)
            f.write("%d, %d, %f\n" % (leaked_bits, extra_attempts, gained_info))

        axes.plot(list(range(max_extra_attempts + 1)), leaked_info, label=str(leaked_bits) + "BIT")

    f.close()
    plt.legend(loc="lower right")
    plt.show()
    fig.savefig("testing/information.png")
    plt.close()


def test_speed(KHashDRBGImpl, generate_requests=10000, max_leaked_bits=8, max_extra_attempts=10):
    hash_fun = "SHA-512"
    hash_implementation = SHA512

    HashPRNG = HashDRBG(hash_fun)
    status, state_handle = HashPRNG.instantiate()
    if status != DRBGStatus.SUCCESS:
        print(DRBG_status_to_string(status))
        exit(1)

    start = time.process_time()
    for b in range(generate_requests):
        status, bits = HashPRNG.generate(state_handle, 512, prediction_resistance_request=False)
        if status != DRBGStatus.SUCCESS:
            print(DRBG_status_to_string(status))
            break
    end = time.process_time()
    print("Original: %0.4f seconds" % (end - start))
    original = end - start

    pkey = bytes([random.randrange(256) for r in range(32)])
    fig, axes = plt.subplots(figsize=(12, 8))
    f = open("testing/tmp_speed.txt", "w")

    for leaked_bits in range(1, max_leaked_bits + 1):
        slowing = []

        for extra_attempts in range(max_extra_attempts + 1):
            KHashPRNG = KHashDRBGImpl(hash_fun, pkey, extra_attempts, leaked_bits)
            status, state_handle = KHashPRNG.instantiate()
            if status != DRBGStatus.SUCCESS:
                print(DRBG_status_to_string(status))
                exit(1)

            start = time.process_time()
            for b in range(generate_requests):
                status, bits = KHashPRNG.generate(state_handle, 512, prediction_resistance_request=False)
                if status != DRBGStatus.SUCCESS:
                    print(DRBG_status_to_string(status))
                    break
            end = time.process_time()

            slowdown = (end - start) / original - 1.
            print("%d bits, %d attempts: %0.4f seconds, %0.4f slower" % (leaked_bits, extra_attempts,
                                                                         end - start, slowdown))
            slowing.append(slowdown)
            f.write("%d, %d, %f\n" % (leaked_bits, extra_attempts, slowdown))

        axes.plot(list(range(max_extra_attempts + 1)), slowing, label=str(leaked_bits) + "BIT")

    f.close()
    plt.legend(loc="lower right")
    plt.show()
    fig.savefig("testing/speed.png")
    plt.close()


def plot_efficiency():
    """WARNING: Should only be called after both tests are completed"""
    info = dict()
    speed = dict()

    with open("testing/tmp_info.txt", encoding="utf-8") as f:
        for line in f:
            values = line.split(",")
            leaked_bits = int(values[0].strip())
            extra_attempts = int(values[1].strip())
            gained_info = float(values[2].strip())

            if leaked_bits not in info.keys():
                info[leaked_bits] = dict()
            info[leaked_bits][extra_attempts] = gained_info

    with open("testing/tmp_speed.txt", encoding="utf-8") as f:
        for line in f:
            values = line.split(",")
            leaked_bits = int(values[0].strip())
            extra_attempts = int(values[1].strip())
            slowdown = float(values[2].strip())

            if leaked_bits not in speed.keys():
                speed[leaked_bits] = dict()
            speed[leaked_bits][extra_attempts] = slowdown

    fig, axes = plt.subplots(figsize=(12, 8))

    for leaked_bits in [lb for lb in info.keys() if lb in speed.keys()]:
        ea_values = sorted([ea for ea in info[leaked_bits].keys() if ea in speed[leaked_bits].keys()])
        efficiencies = []
        for ea in ea_values:
            if speed[leaked_bits][ea] > 0:
                efficiencies.append(info[leaked_bits][ea] / speed[leaked_bits][ea])
            else:
                efficiencies.append(0.)

        axes.plot(ea_values, efficiencies, label=str(leaked_bits) + "BIT")

    plt.legend(loc="lower right")
    plt.show()
    fig.savefig("testing/efficiency.png")
    plt.close()
