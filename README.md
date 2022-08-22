# Subverting the NIST Hash PRNG

This repository contains a Python implementation of the NIST Hash PRNG as well as its kleptographic subversion. It was coded as a class project during the [Cryptography and Computer Security](https://github.com/jaanos/kirv) course in 2021/2022, under prof. dr. Aleksandar Jurišić, mag. Klemen Klanjšček and dr. Janoš Vidali, as part of the Master's degree programme at FRI, UL.

A thorough description of the theoretical background and implementation details can be found in the accompanying 'Subverting the NIST Hash PRNG' pdf report. Most code contains docstrings for easier navigation. The HashDRBG class could potentially be used as a legitimate PRNG, but is inherently unsafe due to the lack of private variables in Python.

## Repository Structure

The 'DRBG.py' file contains the functional model of a NIST PRNG, and should not be initialized directly. The 'HashPRNG.py' under 'implementations' contains the Hash PRNG implementation, and the 'KleptoHashDRBG.py' contains two variants of a kleptographic subversion. 

The 'kat' folder contains a script for generating known-answer tests as well as databases with sample tests. The testing folder contains a script and some plots regarding the efficiency of the subversion. The 'helpers' folder contains some useful functions for working with bytes.

The 'main.py' script contains an example of how to initialize and instantiate a Hash PRNG, use it to generate output, and store it in a binary file. All implementations use 'os.urandom' calls as an entropy source. All main resources used for the project can be found at the end of the pdf report, and some additional ones can be provided upon request.


## Dependencies

- **pycryptodome 3.15.0** was used for hash function implementations
- **matplotlib 3.5.3** was used to generate plots during testing
