from Crypto.Hash import HMAC, SHA512
import math
import re
import sqlite3

from implementations.HashDRBG import HashDRBG
from helpers.DRBG_status import DRBGStatus
from helpers.DRBG_states import HashDRBGState
from helpers.general_helpers import sum_bytes, bytes_equal, sum_bytes_multi, leftmost


class KHashDRBG1(HashDRBG):
    def __init__(self, hash_function, pkey=bytes([0, 1, 2, 3, 4])):
        """Initializes a hash-based DRBG.

        Parameters
        ----------
        hash_function : str
            The name of the hash function to use. Supports SHA-224, SHA-512/224, SHA3-224, SHA-256, SHA-512/256,
            SHA3-256, SHA-384, SHA3-384, SHA-512, SHA3-512. SHA-1 can be initialized, but will refuse to generate.
        """

        self.__max_attempts = 8
        self.__pkey = pkey

        super().__init__(hash_function)

    def _generate_algorithm(self, working_state, requested_number_of_bits, additional_input):
        """The generate algorithm for the hash DRBG. Generates a requested number of pseudo-random bits using
                    an instantiated state and additional input."""

        hash_fun = self._HashDRBG__hash
        const_binary = format(int.from_bytes(working_state.get_C(), "big"), "b").zfill(8*len(working_state.get_C()))
        m = math.ceil(requested_number_of_bits / (2 * self.get_highest_supported_security_state()))
        coins = additional_input
        attempts = 0

        best_t = -1
        best_block = None
        new_state = None

        while attempts < self.__max_attempts:
            if working_state.reseed_counter > self._reseed_interval:
                working_state.reseed_counter = 1

            if coins is not None and len(coins) > 0:
                w = hash_fun(b''.join([bytes([2]), working_state.get_value(), coins]))
                V = sum_bytes(working_state.get_value(), w, True)
            else:
                V = working_state.get_value()

            data = V
            W = bytearray()
            for i in range(m):
                w = hash_fun(data)
                W += bytearray(w)
                data = sum_bytes(data, bytes([1]), True)

            returned_bits = leftmost(bytes(W), requested_number_of_bits)
            decoded = HMAC.new(self.__pkey, msg=returned_bits, digestmod=SHA512).digest()

            t = 0
            for b in range(4):
                block = format(int.from_bytes(decoded[b*11:(b+1)*11], "big"), "b").zfill(88)
                for d in range(8):
                    d_loc = (int(block[d*10:(d+1)*10], 2) % (8*len(working_state.get_C()))) + 1
                    d_value = int(block[80+d])

                    if int(const_binary[-d_loc]) == d_value:
                        t += 1

            if t > best_t:
                best_block = returned_bits
                best_t = t
                H = hash_fun(b''.join([bytes([3]), V]))
                new_value = sum_bytes_multi([V, H, working_state.get_C(), working_state.reseed_counter.
                                            to_bytes(int(math.log2(self._reseed_interval) + 1), 'big')], True)
                new_state = HashDRBGState(new_value, working_state.get_C(), working_state.reseed_counter + 1,
                                          working_state.security_strength, working_state.prediction_resistance_flag)

            attempts += 1
            coins = sum_bytes(coins, bytes([1]))

        return DRBGStatus.SUCCESS, best_block, new_state

    def test_generate(self):
        """Performs known-answer testing on the generate algorithm implementation for the hash DRBG."""

        conn = sqlite3.connect('kat/kat_hash_generate.db')
        cursor = conn.execute("SELECT ID,ADDIN,VAL,CONST,SESTR,REQBITS,RESEED,BITS,NEWVAL,NEWCONST from " +
                              re.sub(r'[^a-zA-Z0-9]', '', self._hash_function))
        prediction_resistance_flag = True

        for row in cursor:
            additional_input = row[1]
            V_in = row[2]
            C_in = row[3]
            security_strength = row[4]
            requested_number_of_bits = row[5]
            reseed_counter = row[6]
            generated_bits = row[7]
            V = row[8]
            C = row[9]

            working_state = HashDRBGState(V_in, C_in, reseed_counter, security_strength,
                                          prediction_resistance_flag)

            status, returned_bits, new_state = super()._generate_algorithm(working_state, requested_number_of_bits,
                                                                           additional_input)
            if status != DRBGStatus.SUCCESS:
                return status

            if not bytes_equal(returned_bits, generated_bits) or not bytes_equal(new_state.get_value(), V) or \
                    not bytes_equal(new_state.get_C(), C) or new_state.reseed_counter != reseed_counter + 1 or \
                    new_state.security_strength != security_strength or \
                    new_state.prediction_resistance_flag is not True:

                self.trigger_catastrophic_error()
                return DRBGStatus.CATASTROPHIC_ERROR_FLAG

        conn.close()
        return DRBGStatus.SUCCESS


class KHashDRBG2(HashDRBG):
    def __init__(self, hash_function, pkey=bytes([0, 1, 2, 3, 4])):
        """Initializes a hash-based DRBG.

        Parameters
        ----------
        hash_function : str
            The name of the hash function to use. Supports SHA-224, SHA-512/224, SHA3-224, SHA-256, SHA-512/256,
            SHA3-256, SHA-384, SHA3-384, SHA-512, SHA3-512. SHA-1 can be initialized, but will refuse to generate.
        """

        self.__max_attempts = 8
        self.__pkey = pkey

        super().__init__(hash_function)

    def generate(self, state_handle, requested_number_of_bits, requested_security_strength=None,
                 prediction_resistance_request=None, additional_input=None):
        """Generates pseudo-random bits using an instantiation.

        Parameters
        ----------
        state_handle : int
            A handle for the instantiated state used for bit generation.
        requested_number_of_bits : int
            The number of pseudo-random bits to generate.
        requested_security_strength : int
            The requested security strength for the bit generation..
        prediction_resistance_request: bool
            A flag used to request prediction resistance.
        additional_input : bytes, optional
            Optional bitstring used to personalize the bit generation.

        Returns
        -------
        status : DRBGStatus
            One of the defined DRBG status flags.
        pseudorandom_bits : bytes
            Generated pseudo-random bits. Might be None.
        """

        if self.has_catastrophic_error():
            return DRBGStatus.CATASTROPHIC_ERROR_FLAG, None

        working_state = self._DRBG__load_state(state_handle)
        if working_state is None:
            return DRBGStatus.ERROR_FLAG, None

        if requested_number_of_bits > self._max_number_of_bits_per_request:
            return DRBGStatus.ERROR_FLAG, None

        if requested_security_strength is None:
            requested_security_strength = working_state.security_strength
        elif requested_security_strength > working_state.security_strength:
            return DRBGStatus.ERROR_FLAG, None

        if additional_input is None:
            additional_input = bytes(0)
        elif len(additional_input) * 8 > self._max_additional_input_length:
            return DRBGStatus.ERROR_FLAG, None

        if prediction_resistance_request is None:
            prediction_resistance_request = working_state.prediction_resistance_flag
        elif prediction_resistance_request and not working_state.prediction_resistance_flag:
            return DRBGStatus.ERROR_FLAG, None

        reseed_required_flag = False
        while True:
            if reseed_required_flag or prediction_resistance_request:
                status = self.reseed(state_handle, prediction_resistance_request, additional_input)
                if status != DRBGStatus.SUCCESS:
                    return status, None

                additional_input = bytes(0)
                reseed_required_flag = False
                working_state = HashDRBGState(working_state.get_value(), working_state.get_C(), 1,
                                              working_state.security_strength, working_state.prediction_resistance_flag)

            const_binary = format(int.from_bytes(working_state.get_C(), "big"), "b").zfill(8*len(working_state.get_C()))
            coins = additional_input
            attempts = 0

            best_t = -1
            best_block = None
            new_state = None

            while attempts < self.__max_attempts:
                status, bits, next_state = super()._generate_algorithm(working_state, requested_number_of_bits, coins)
                if status == DRBGStatus.RESEED_REQUIRED:
                    reseed_required_flag = True
                    prediction_resistance_flag = working_state.prediction_resistance_flag
                    if prediction_resistance_flag:
                        prediction_resistance_request = True
                    break
                elif status != DRBGStatus.SUCCESS:
                    return status, None

                decoded = HMAC.new(self.__pkey, msg=bits, digestmod=SHA512).digest()
                t = 0
                for b in range(4):
                    block = format(int.from_bytes(decoded[b * 11:(b + 1) * 11], "big"), "b").zfill(88)
                    for d in range(8):
                        d_loc = (int(block[d * 10:(d + 1) * 10], 2) % (8*len(working_state.get_C()))) + 1
                        d_value = int(block[80 + d])

                        if int(const_binary[-d_loc]) == d_value:
                            t += 1

                if t > best_t:
                    best_block = bits
                    best_t = t
                    new_state = next_state

                attempts += 1
                coins = sum_bytes(coins, bytes([1]))

            if attempts == self.__max_attempts:
                break

        self._DRBG__save_state(new_state, state_handle)
        self._DRBG__health_state.increment_generate_counter()
        return DRBGStatus.SUCCESS, best_block
