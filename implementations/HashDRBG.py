import math
import random
import re
import sqlite3
from Crypto.Hash import SHA1, SHA224, SHA512, SHA3_224, SHA256, SHA3_256, SHA384, SHA3_384, SHA3_512

from helpers.general_helpers import sum_bytes, sum_bytes_multi, int_to_bytes, leftmost, bytes_equal
from helpers.DRBG_status import DRBGStatus
from helpers.DRBG_states import HashDRBGState
from DRBG import DRBG


class HashDRBG(DRBG):
    def __init__(self, hash_function):
        """Initializes a hash-based DRBG.

        Parameters
        ----------
        hash_function : str
            The name of the hash function to use. Supports SHA-224, SHA-512/224, SHA3-224, SHA-256, SHA-512/256,
            SHA3-256, SHA-384, SHA3-384, SHA-512, SHA3-512. SHA-1 can be initialized, but will refuse to generate.
        """

        self._hash_function = hash_function.upper()
        self.__hash_implementation = None

        if self._hash_function == "SHA-1":
            highest_supported_security_strength = 80
            self.__outlen = 160
            self.__seedlen = 440
            self.__hash_implementation = SHA1

        elif self._hash_function in ["SHA-224", "SHA-512/224", "SHA3-224"]:
            highest_supported_security_strength = 112
            self.__outlen = 224
            self.__seedlen = 440
            if self._hash_function == "SHA-224":
                self.__hash_implementation = SHA224
            elif self._hash_function == "SHA-512/224":
                self.__hash_implementation = SHA512
            else:
                self.__hash_implementation = SHA3_224

        elif self._hash_function in ["SHA-256", "SHA-512/256", "SHA3-256"]:
            highest_supported_security_strength = 128
            self.__outlen = 256
            self.__seedlen = 440
            if self._hash_function == "SHA-256":
                self.__hash_implementation = SHA256
            elif self._hash_function == "SHA-512/256":
                self.__hash_implementation = SHA512
            else:
                self.__hash_implementation = SHA3_256

        elif self._hash_function in ["SHA-384", "SHA3-384"]:
            highest_supported_security_strength = 192
            self.__outlen = 384
            self.__seedlen = 888
            if self._hash_function == "SHA-384":
                self.__hash_implementation = SHA384
            else:
                self.__hash_implementation = SHA3_384

        elif self._hash_function in ["SHA-512", "SHA3-512"]:
            highest_supported_security_strength = 256
            self.__outlen = 512
            self.__seedlen = 888
            if self._hash_function == "SHA-512":
                self.__hash_implementation = SHA512
            else:
                self.__hash_implementation = SHA3_512

        else:
            self.__health_state.set_catastrophic_error()
            print("Hash function " + self._hash_function + " is not supported.")
            return

        self._reseed_interval = 2**48
        max_personalization_string_length = 2**35
        max_additional_input_length = 2**35
        max_number_of_bits_per_request = 2**19
        max_length = 2**35

        super().__init__("HASHDRBG", highest_supported_security_strength, max_personalization_string_length,
                         max_additional_input_length, max_number_of_bits_per_request, 112, max_length)

    def get_hash_function(self):
        """Returns the name of the hash function used by this hash DRBG."""

        return self._hash_function

    def _instantiate_algorithm(self, entropy_input, nonce, personalization_string, security_strength,
                               prediction_resistance_flag):
        """The instantiate algorithm for the hash DRBG. Instantiates a hash DRBG state with requested security strength
            and optional prediction resistance using the entropy input, nonce and personalization string.

        Parameters
        ----------
        entropy_input : bytes
            The entropy input used for this instantiation.
        nonce : bytes
            The nonce used for this instantiation.
        personalization_string : bytes
            The personalization string used to personalize this instantiation.
        security_strength : int
            The requested security strength for this instantiation.
        prediction_resistance_flag : bool
            A flag used to request prediction resistance for this instantiation.

        Returns
        -------
        status : DRBGStatus
            One of the defined DRBG status flags.
        state : HashDRBGState
            The newly instantiated state.
        """

        seed_material = b''.join([entropy_input, nonce, personalization_string])
        seed = self.__hash_df(seed_material, self.__seedlen)
        constant = self.__hash_df(b''.join([bytes(1), seed]), self.__seedlen)
        state = HashDRBGState(seed, constant, 1, security_strength, prediction_resistance_flag)
        return DRBGStatus.SUCCESS, state

    def _reseed_algorithm(self, working_state, entropy_input, additional_input):
        """The reseed algorithm for the hash DRBG. Reseeds the given hash DRBG state using the entropy input
            and the additional input.

        Parameters
        ----------
        working_state : HashDRBGState
            The instantiated state to reseed.
        entropy_input: bytes
            The entropy input used to reseed the state.
        additional_input: bytes
            The additional input used to personalize the reseed.

        Returns
        -------
        status : DRBGStatus
            One of the defined DRBG status flags.
        state : HashDRBGState
            The reseeded state.
        """

        seed_material = b''.join([bytes([1]), working_state.get_value(), bytes(entropy_input), bytes(additional_input)])
        seed = self.__hash_df(seed_material, self.__seedlen)
        constant = self.__hash_df(b''.join([bytes(1), seed]), self.__seedlen)
        state = HashDRBGState(seed, constant, 1, working_state.security_strength,
                              working_state.prediction_resistance_flag)
        return DRBGStatus.SUCCESS, state

    def _generate_algorithm(self, working_state, requested_number_of_bits, additional_input):
        """The generate algorithm for the hash DRBG. Generates a requested number of pseudo-random bits using
            an instantiated state and additional input.

        Parameters
        ----------
        working_state : HashDRBGState
            The instantiated state to use for bit generation.
        requested_number_of_bits: int
            The number of pseudo-random bits to generate.
        additional_input: bytes
            The additional input used to personalize the bit generation.

        Returns
        -------
        status : DRBGStatus
            One of the defined DRBG status flags.
        pseudorandom_bits : bytes
            Generated pseudo-random bits. Might be None.
        state : HashDRBGState
            The new state to transition into after the bit generation. Might be None.
        """

        if working_state.reseed_counter > self._reseed_interval:
            return DRBGStatus.RESEED_REQUIRED, None, None

        if additional_input is not None and len(additional_input) > 0:
            w = self.__hash(b''.join([bytes([2]), working_state.get_value(), additional_input]))
            V = sum_bytes(working_state.get_value(), w, True)
        else:
            V = working_state.get_value()

        returned_bits = self.__hashgen(requested_number_of_bits, V)
        H = self.__hash(b''.join([bytes([3]), V]))
        new_value = sum_bytes_multi([V, H, working_state.get_C(), working_state.reseed_counter.
                                    to_bytes(int(math.log2(self._reseed_interval) + 1), 'big')], True)
        new_state = HashDRBGState(new_value, working_state.get_C(), working_state.reseed_counter + 1,
                                  working_state.security_strength, working_state.prediction_resistance_flag)

        return DRBGStatus.SUCCESS, returned_bits, new_state

    def __hash(self, input_string):
        """Returns the digest of the input string digest using the selected hash function."""

        if self._hash_function == "SHA-512/224":
            hash_object = self.__hash_implementation.new(truncate="224")
        elif self._hash_function == "SHA-512/256":
            hash_object = self.__hash_implementation.new(truncate="256")
        else:
            hash_object = self.__hash_implementation.new()

        hash_object.update(input_string)
        return hash_object.digest()

    def __hash_df(self, input_string, no_of_bits_to_return):
        """Hash-based derivation function used to hash an input string and return the requested number of bits."""

        temp = bytearray()
        length = math.ceil(no_of_bits_to_return / self.__outlen)
        counter = 1
        no_of_bits_as_bytes = int_to_bytes(no_of_bits_to_return, 4)
        for i in range(length):
            hash_input = b''.join([bytes([counter]), no_of_bits_as_bytes, input_string])
            temp += bytearray(self.__hash(hash_input))
            counter += 1

        requested_bits = leftmost(bytes(temp), no_of_bits_to_return)
        return requested_bits

    def __hashgen(self, requested_number_of_bits, value):
        """Auxiliary function used to generate the requested number of bits using a value"""

        m = math.ceil(requested_number_of_bits/self.__outlen)
        data = value
        W = bytearray()
        for i in range(m):
            w = self.__hash(data)
            W += bytearray(w)
            data = sum_bytes(data, bytes([1]), True)

        returned_bits = leftmost(bytes(W), requested_number_of_bits)
        return returned_bits

    def test_instantiate(self):
        """Performs known-answer testing on the instantiate algorithm implementation for the hash DRBG."""

        conn = sqlite3.connect('kat/kat_hash_instantiate.db')
        cursor = conn.execute("SELECT ID,ENTROPY,NONCE,PESTR,SESTR,VAL,CONST from " +
                              re.sub(r'[^a-zA-Z0-9]', '', self._hash_function))
        prediction_resistance_flag = True

        for row in cursor:
            entropy = row[1]
            nonce = row[2]
            personalization_string = row[3]
            security_strength = row[4]
            V = row[5]
            C = row[6]

            status, state = self._instantiate_algorithm(entropy, nonce, personalization_string, security_strength,
                                                        prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            if not bytes_equal(state.get_value(), V) or not bytes_equal(state.get_C(), C) or state.reseed_counter != 1 \
                    or state.security_strength != security_strength or state.prediction_resistance_flag is not True:
                self.trigger_catastrophic_error()
                return DRBGStatus.CATASTROPHIC_ERROR_FLAG

        conn.close()
        return DRBGStatus.SUCCESS

    def test_reseed(self):
        """Performs known-answer testing on the reseed algorithm implementation for the hash DRBG."""

        conn = sqlite3.connect('kat/kat_hash_reseed.db')
        cursor = conn.execute("SELECT ID,ENTROPY,ADDIN,VAL,CONST,SESTR,NEWVAL,NEWCONST from " +
                              re.sub(r'[^a-zA-Z0-9]', '', self._hash_function))
        prediction_resistance_flag = True

        for row in cursor:
            entropy = row[1]
            additional_input = row[2]
            V_in = row[3]
            C_in = row[4]
            security_strength = row[5]
            V = row[6]
            C = row[7]

            working_state = HashDRBGState(V_in, C_in, random.choice(range(512)), security_strength,
                                          prediction_resistance_flag)
            status, new_state = self._reseed_algorithm(working_state, entropy, additional_input)
            if status != DRBGStatus.SUCCESS:
                return status

            if not bytes_equal(new_state.get_value(), V) or not bytes_equal(new_state.get_C(), C) or \
                    new_state.reseed_counter != 1 or new_state.security_strength != security_strength or \
                    new_state.prediction_resistance_flag is not True:
                self.trigger_catastrophic_error()
                return DRBGStatus.CATASTROPHIC_ERROR_FLAG

        conn.close()
        return DRBGStatus.SUCCESS

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

            status, returned_bits, new_state = self._generate_algorithm(working_state, requested_number_of_bits,
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
