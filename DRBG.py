import sys

from helpers.DRBG_status import DRBGStatus
from helpers.DRBG_states import DRBGHealthState

from helpers.entropy_source import get_entropy_input, get_nonce


class DRBG:
    """General DRBG class inherited by specific implementations. Not intended to be initialized directly."""

    __supported_prediction_resistance = True
    __states = dict()

    def __init__(self, DRBG_type, highest_supported_security_strength, max_personalization_string_length,
                 max_additional_input_length, max_number_of_bits_per_request, min_length, max_length):
        """Initializes the DRBG. Only intended to be invoked by inherited classes.

        Parameters
        ----------
        DRBG_type : str
            The name of this DRBG type.
        highest_supported_security_strength : int
            Highest supported security strength of this DRBG.
        max_personalization_string_length : int
            Maximum length of personalization_string used by instantiate method.
        max_additional_input_length : int
            Maximum length of additional_input used by reseed and generate method.
        max_number_of_bits_per_request : int
            Upper limit of requested_number_of_bits used by generate method.
        min_length : int
            Minimum number of entropy bits requested by instantiate and reseed methods.
        max_length : int
            Maximum number of entropy bits requested by instantiate and reseed methods.
        """

        self._DRBG_type = DRBG_type.upper()
        self._highest_supported_security_strength = highest_supported_security_strength
        self._max_personalization_string_length = max_personalization_string_length
        self._max_additional_input_length = max_additional_input_length
        self._max_number_of_bits_per_request = max_number_of_bits_per_request
        self._min_length = min_length
        self._max_length = max_length
        self.__health_state = DRBGHealthState(self)
        self.health_test()

    def get_type(self):
        """Returns the name of this DRBG type."""

        return self._DRBG_type

    def get_highest_supported_security_state(self):
        """Returns the highest supported security strength of this DRBG initialization."""

        return self._highest_supported_security_strength

    def instantiate(self, requested_instantiation_security_strength=None, prediction_resistance_flag=None,
                    personalization_string=None):
        """Instantiates a state of this DRBG.

        Parameters
        ----------
        requested_instantiation_security_strength : int
            The requested security strength for this instantiation.
        prediction_resistance_flag : bool
            A flag used to request prediction resistance for this instantiation.
        personalization_string : bytes, optional
            Optional bitstring used to personalize this instantiation.

        Returns
        -------
        status : DRBGStatus
            One of the defined DRBG status flags.
        state_handle : int
            A handle for the newly instantiated state. Might be None.
        """

        if self.has_catastrophic_error():
            return DRBGStatus.CATASTROPHIC_ERROR_FLAG, None

        if requested_instantiation_security_strength is None:
            requested_instantiation_security_strength = self._highest_supported_security_strength
        elif requested_instantiation_security_strength > self._highest_supported_security_strength:
            return DRBGStatus.ERROR_FLAG, None

        if prediction_resistance_flag is None:
            prediction_resistance_flag = self.__supported_prediction_resistance
        elif prediction_resistance_flag and not self.__supported_prediction_resistance:
            return DRBGStatus.ERROR_FLAG, None

        if personalization_string is None:
            personalization_string = bytes(0)
        elif len(personalization_string) * 8 > self._max_personalization_string_length:
            return DRBGStatus.ERROR_FLAG, None

        security_strength = requested_instantiation_security_strength
        for ss in [112, 128, 192, 256]:
            if ss >= requested_instantiation_security_strength:
                security_strength = ss
                break

        status, entropy_input = get_entropy_input(security_strength, self._min_length, self._max_length,
                                                  prediction_resistance_flag)

        if status != DRBGStatus.SUCCESS:
            return status, None

        nonce = get_nonce(security_strength)

        status, state = self._instantiate_algorithm(entropy_input, nonce, personalization_string, security_strength,
                                                    prediction_resistance_flag)

        if status != DRBGStatus.SUCCESS:
            return status, None
        state_handle = self.__save_state(state)

        if state_handle is None:
            return DRBGStatus.ERROR_FLAG, None
        return DRBGStatus.SUCCESS, state_handle

    def reseed(self, state_handle, prediction_resistance_request=None, additional_input=None):
        """Reseeds a given instantiated state of this DRBG.

        Parameters
        ----------
        state_handle : int
            A handle for the instantiated state to reseed.
        prediction_resistance_request : bool
            A flag used to request prediction resistance for the reseed.
        additional_input : bytes, optional
            Optional bitstring used to personalize the reseed.

        Returns
        -------
        status : DRBGStatus
            One of the defined DRBG status flags.
        """

        if self.has_catastrophic_error():
            return DRBGStatus.CATASTROPHIC_ERROR_FLAG

        working_state = self.__load_state(state_handle)
        if working_state is None:
            return DRBGStatus.ERROR_FLAG

        if prediction_resistance_request is None:
            prediction_resistance_request = working_state.prediction_resistance_flag
        elif prediction_resistance_request and not working_state.prediction_resistance_flag:
            return DRBGStatus.ERROR_FLAG

        if additional_input is None:
            additional_input = bytes(0)
        elif len(additional_input) * 8 > self._max_additional_input_length:
            return DRBGStatus.ERROR_FLAG

        status, entropy_input = get_entropy_input(working_state.security_strength, self._min_length,
                                                  self._max_length, prediction_resistance_request)

        if status != DRBGStatus.SUCCESS:
            return status

        status, new_working_state = self._reseed_algorithm(working_state, entropy_input, additional_input)
        if status != DRBGStatus.SUCCESS:
            return status

        self.__save_state(new_working_state, state_handle)
        return DRBGStatus.SUCCESS

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

        working_state = self.__load_state(state_handle)
        if working_state is None:
            return DRBGStatus.ERROR_FLAG, None

        if requested_number_of_bits > self._max_number_of_bits_per_request or requested_number_of_bits <= 0:
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

                working_state = self.__load_state(state_handle)
                if working_state is None:
                    return DRBGStatus.ERROR_FLAG, None

                additional_input = bytes(0)
                reseed_required_flag = False

            status, pseudorandom_bits, new_working_state = \
                self._generate_algorithm(working_state, requested_number_of_bits, additional_input)

            if status == DRBGStatus.RESEED_REQUIRED:
                reseed_required_flag = True
                prediction_resistance_flag = working_state.prediction_resistance_flag
                if prediction_resistance_flag:
                    prediction_resistance_request = True
            elif status != DRBGStatus.SUCCESS:
                return status, None
            else:
                break

        self.__save_state(new_working_state, state_handle)
        self.__health_state.increment_generate_counter()
        return DRBGStatus.SUCCESS, pseudorandom_bits

    def uninstantiate(self, state_handle):
        """Removes an instantiation of this DRBG.

        Parameters
        ----------
        state_handle : int
            A handle for the instantiation to remove.

        Returns
        -------
        status : DRBGStatus
            One of the defined DRBG status flags.
        """

        if state_handle not in self.__states.keys():
            return DRBGStatus.ERROR_FLAG
        del self.__states[state_handle]
        return DRBGStatus.SUCCESS

    def __save_state(self, state, state_handle=None):
        """Saves an instantiation of this DRBG and returns its handle. The handle will be generated if not provided."""

        if state_handle is None:
            for i in range(sys.maxsize):
                if i not in self.__states.keys():
                    self.__states[i] = state
                    return i
        else:
            self.__states[state_handle] = state
            return state_handle

    def __load_state(self, state_handle):
        """Loads an instantiation of this DRBG."""

        if state_handle not in self.__states.keys():
            return None
        else:
            return self.__states[state_handle]

    def health_test(self):
        """Performs known-answer testing on the instantiate, reseed and generate algorithm implementations."""

        status = self.test_instantiate()
        if status == DRBGStatus.CATASTROPHIC_ERROR_FLAG:
            print("Instantiate algorithm is invalid.")
        elif status != DRBGStatus.SUCCESS:
            print("Error encountered during testing of instantiate algorithm.")

        status = self.test_reseed()
        if status == DRBGStatus.CATASTROPHIC_ERROR_FLAG:
            print("Reseed algorithm is invalid.")
        elif status != DRBGStatus.SUCCESS:
            print("Error encountered during testing of reseed algorithm.")

        status = self.test_generate()
        if status == DRBGStatus.CATASTROPHIC_ERROR_FLAG:
            print("Generate algorithm is invalid.")
        elif status != DRBGStatus.SUCCESS:
            print("Error encountered during testing of generate algorithm.")

    def has_catastrophic_error(self):
        """Returns bool value indicating whether the DRBG is in a catastrophic error state."""

        return self.__health_state.is_catastrophic_error()

    def trigger_catastrophic_error(self):
        """Used to trigger a catastrophic error and prevent further operations by the DRBG."""

        self.__health_state.set_catastrophic_error()

    def _instantiate_algorithm(self, entropy_input, nonce, personalization_string, security_strength,
                               prediction_resistance_flag):
        """Dummy implementation for the instantiate algorithm. Inherited classes must override this method."""

        self.trigger_catastrophic_error()
        print("Instantiate algorithm for " + self._DRBG_type + " is not implemented.")
        return DRBGStatus.CATASTROPHIC_ERROR_FLAG, None

    def _reseed_algorithm(self, working_state, entropy_input, additional_input):
        """Dummy implementation for the reseed algorithm. Inherited classes must override this method."""

        self.trigger_catastrophic_error()
        print("Reseed algorithm for " + self._DRBG_type + " is not implemented.")
        return DRBGStatus.CATASTROPHIC_ERROR_FLAG, None

    def _generate_algorithm(self, working_state, requested_number_of_bits, additional_input):
        """Dummy implementation for the generate algorithm. Inherited classes must override this method."""

        self.trigger_catastrophic_error()
        print("Generate algorithm for " + self._DRBG_type + " is not implemented.")
        return DRBGStatus.CATASTROPHIC_ERROR_FLAG, None, None

    def test_instantiate(self):
        """Dummy implementation for instantiate algorithm health-test. Inherited classes must override this method."""

        self.trigger_catastrophic_error()
        return DRBGStatus.CATASTROPHIC_ERROR_FLAG

    def test_reseed(self):
        """Dummy implementation for reseed algorithm health-test. Inherited classes must override this method."""

        self.trigger_catastrophic_error()
        return DRBGStatus.CATASTROPHIC_ERROR_FLAG

    def test_generate(self):
        """Dummy implementation for generate algorithm health-test. Inherited classes must override this method."""

        self.trigger_catastrophic_error()
        return DRBGStatus.CATASTROPHIC_ERROR_FLAG
