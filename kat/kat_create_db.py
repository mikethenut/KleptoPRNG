import random
import re
import sqlite3

from helpers.entropy_source import get_entropy_input, get_nonce
from helpers.DRBG_status import DRBGStatus
from implementations.HashDRBG import HashDRBG
from implementations.KleptoHashDRBG import KHashDRBG1


def create_hash_kat(no_of_tests):
    status = create_hash_instantiate_kat(no_of_tests)
    if status != DRBGStatus.SUCCESS:
        print("Error encountered while creating hash instantiate KAT.")

    status = create_hash_reseed_kat(no_of_tests)
    if status != DRBGStatus.SUCCESS:
        print("Error encountered while creating hash reseed KAT.")

    status = create_hash_generate_kat(no_of_tests)
    if status != DRBGStatus.SUCCESS:
        print("Error encountered while creating hash generate KAT.")


def create_hash_instantiate_kat(no_of_tests, db_name='kat/kat_hash_instantiate.db'):
    conn = sqlite3.connect(db_name)

    for hash_fun in ["SHA-224", "SHA-512/224", "SHA3-224", "SHA-256", "SHA-512/256", "SHA3-256",
                     "SHA-384", "SHA3-384", "SHA-512", "SHA3-512"]:

        HashPRNG = HashDRBG(hash_fun)
        conn.execute("DROP TABLE IF EXISTS " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + ";")
        conn.execute("CREATE TABLE " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + "\n" +
                     "(ID       INT PRIMARY KEY NOT NULL,\n" +
                     "ENTROPY  BLOB            NOT NULL,\n" +
                     "NONCE    BLOB            NOT NULL,\n" +
                     "PESTR    BLOB            NOT NULL,\n" +
                     "SESTR    INT             NOT NULL,\n" +
                     "VAL      BLOB            NOT NULL,\n" +
                     "CONST    BLOB            NOT NULL);")

        prediction_resistance_flag = True
        supported_security_strengths = []
        for ss in [112, 128, 192, 256]:
            if ss <= HashPRNG._highest_supported_security_strength:
                supported_security_strengths.append(ss)

        for i in range(no_of_tests):
            ss = random.choice(supported_security_strengths)
            status, entropy = get_entropy_input(ss, HashPRNG._min_length, HashPRNG._max_length,
                                                prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            nonce = get_nonce(ss)
            personalization_string = get_nonce(random.choice([0, ss, ss * 2]))

            status, state = HashPRNG._instantiate_algorithm(entropy, nonce, personalization_string, ss,
                                                            prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            insert_query = "INSERT INTO " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + \
                           " (ID,ENTROPY,NONCE,PESTR,SESTR,VAL,CONST) VALUES (?, ?, ?, ?, ?, ?, ?);"
            insert_data = (i, entropy, nonce, personalization_string, ss, state.get_value(), state.get_C())
            conn.execute(insert_query, insert_data)
            conn.commit()

    conn.close()
    return DRBGStatus.SUCCESS


def create_hash_reseed_kat(no_of_tests, db_name='kat/kat_hash_reseed.db'):
    conn = sqlite3.connect(db_name)

    for hash_fun in ["SHA-224", "SHA-512/224", "SHA3-224", "SHA-256", "SHA-512/256", "SHA3-256",
                     "SHA-384", "SHA3-384", "SHA-512", "SHA3-512"]:

        HashPRNG = HashDRBG(hash_fun)
        conn.execute("DROP TABLE IF EXISTS " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + ";")
        conn.execute("CREATE TABLE " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + "\n" +
                     "(ID       INT PRIMARY KEY NOT NULL,\n" +
                     "ENTROPY  BLOB            NOT NULL,\n" +
                     "ADDIN    BLOB            NOT NULL,\n" +
                     "VAL      BLOB            NOT NULL,\n" +
                     "CONST    BLOB            NOT NULL,\n" +
                     "SESTR    INT             NOT NULL,\n" +
                     "NEWVAL   BLOB            NOT NULL,\n" +
                     "NEWCONST BLOB            NOT NULL);")

        prediction_resistance_flag = True
        supported_security_strengths = []
        for ss in [112, 128, 192, 256]:
            if ss <= HashPRNG._highest_supported_security_strength:
                supported_security_strengths.append(ss)

        for i in range(no_of_tests):
            ss = random.choice(supported_security_strengths)
            status, entropy = get_entropy_input(ss, HashPRNG._min_length, HashPRNG._max_length,
                                                prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            nonce = get_nonce(ss)
            personalization_string = get_nonce(random.choice([0, ss, ss * 2]))

            status, working_state = HashPRNG._instantiate_algorithm(entropy, nonce, personalization_string, ss,
                                                                    prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            status, entropy = get_entropy_input(ss, HashPRNG._min_length, HashPRNG._max_length,
                                                prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            additional_input = get_nonce(random.choice([0, ss, ss * 2]))
            status, new_state = HashPRNG._reseed_algorithm(working_state, entropy, additional_input)
            if status != DRBGStatus.SUCCESS:
                return status

            insert_query = "INSERT INTO " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + \
                           " (ID,ENTROPY,ADDIN,VAL,CONST,SESTR,NEWVAL,NEWCONST) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
            insert_data = (i, entropy, additional_input, working_state.get_value(), working_state.get_C(), ss,
                           new_state.get_value(), new_state.get_C())
            conn.execute(insert_query, insert_data)
            conn.commit()

    conn.close()
    return DRBGStatus.SUCCESS


def create_hash_generate_kat(no_of_tests, db_name='kat/kat_hash_generate.db'):
    conn = sqlite3.connect(db_name)

    for hash_fun in ["SHA-224", "SHA-512/224", "SHA3-224", "SHA-256", "SHA-512/256", "SHA3-256",
                     "SHA-384", "SHA3-384", "SHA-512", "SHA3-512"]:

        HashPRNG = HashDRBG(hash_fun)
        conn.execute("DROP TABLE IF EXISTS " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + ";")
        conn.execute("CREATE TABLE " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + "\n" +
                     "(ID       INT PRIMARY KEY NOT NULL,\n" +
                     "ADDIN    BLOB            NOT NULL,\n" +
                     "VAL      BLOB            NOT NULL,\n" +
                     "CONST    BLOB            NOT NULL,\n" +
                     "SESTR    INT             NOT NULL,\n" +
                     "REQBITS  INT             NOT NULL,\n" +
                     "RESEED   INT             NOT NULL,\n" +
                     "BITS     BLOB            NOT NULL,\n" +
                     "NEWVAL   BLOB            NOT NULL,\n" +
                     "NEWCONST BLOB            NOT NULL);")

        prediction_resistance_flag = True
        supported_security_strengths = []
        for ss in [112, 128, 192, 256]:
            if ss <= HashPRNG._highest_supported_security_strength:
                supported_security_strengths.append(ss)

        for i in range(no_of_tests):
            ss = random.choice(supported_security_strengths)
            status, entropy = get_entropy_input(ss, HashPRNG._min_length, HashPRNG._max_length,
                                                prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            nonce = get_nonce(ss)
            personalization_string = get_nonce(random.choice([0, ss, ss * 2]))

            status, working_state = HashPRNG._instantiate_algorithm(entropy, nonce, personalization_string, ss,
                                                                    prediction_resistance_flag)
            if status != DRBGStatus.SUCCESS:
                return status

            requested_number_of_bits = random.choice([32, 128, 512])
            additional_input = get_nonce(random.choice([0, ss, ss * 2]))
            working_state.reseed_counter = random.choice(range(HashPRNG._reseed_interval))

            status, returned_bits, new_state = HashPRNG._generate_algorithm(working_state, requested_number_of_bits,
                                                                            additional_input)
            if status != DRBGStatus.SUCCESS:
                return status

            insert_query = "INSERT INTO " + re.sub(r'[^a-zA-Z0-9]', '', hash_fun) + \
                           " (ID,ADDIN,VAL,CONST,SESTR,REQBITS,RESEED,BITS,NEWVAL,NEWCONST) " + \
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
            insert_data = (i, additional_input, working_state.get_value(), working_state.get_C(), ss,
                           requested_number_of_bits, working_state.reseed_counter, returned_bits,
                           new_state.get_value(), new_state.get_C())
            conn.execute(insert_query, insert_data)
            conn.commit()

    conn.close()
    return DRBGStatus.SUCCESS
