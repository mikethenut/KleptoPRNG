from helpers.DRBG_status import DRBGStatus


class DRBGHealthState:
    def __init__(self, drbg_instance):
        self.__catastrophic_error = False
        self.__generate_counter = 0
        self.__generate_test_interval = 50
        self.__drbg = drbg_instance

    def set_catastrophic_error(self):
        self.__catastrophic_error = True

    def is_catastrophic_error(self):
        return self.__catastrophic_error

    def increment_generate_counter(self):
        self.__generate_counter += 1
        if self.__generate_counter >= self.__generate_test_interval:
            status = self.__drbg.test_generate()
            if status == DRBGStatus.CATASTROPHIC_ERROR_FLAG:
                print("Generate algorithm is invalid.")
            elif status != DRBGStatus.SUCCESS:
                print("Error encountered during testing of generate algorithm.")
            else:
                self.__generate_counter = 0


class DRBGState:
    def __init__(self, value, reseed_counter, security_strength, prediction_resistance_flag):
        self.__V = value
        self.reseed_counter = reseed_counter
        self.security_strength = security_strength
        self.prediction_resistance_flag = prediction_resistance_flag

    def get_value(self):
        return self.__V


class HashDRBGState(DRBGState):
    def __init__(self, value, constant, reseed_counter, security_strength, prediction_resistance_flag):
        super().__init__(value, reseed_counter, security_strength, prediction_resistance_flag)
        self.__C = constant

    def get_C(self):
        return self.__C


class HMACDRBGState(DRBGState):
    def __init__(self, value, key, reseed_counter, security_strength, prediction_resistance_flag):
        super().__init__(value, reseed_counter, security_strength, prediction_resistance_flag)
        self.__Key = key

    def get_Key(self):
        return self.__Key


class CTRDRBGState(DRBGState):
    def __init__(self, value, key, reseed_counter, security_strength, prediction_resistance_flag):
        super().__init__(value, reseed_counter, security_strength, prediction_resistance_flag)
        self.__Key = key

    def get_Key(self):
        return self.__Key
