import os
import math
from helpers.DRBG_status import DRBGStatus


def get_entropy_input(min_entropy, min_len, max_len, prediction_resistance):
    """Uses simple call to os.urandom, not compliant with documentation.

    Parameters
    ----------
    min_entropy : int
        Minimum entropy in bits to return.
    min_len : int
        Minimum number of bits to return.
    max_len : int
        Maximum number of bits to return.
    prediction_resistance: bool
        A flag used to request prediction resistance.

    Returns
    -------
    status : DRBGStatus
        One of the defined DRBG status flags.
    returned_bits : bytes
        The returned entropy bits.
    """

    if min_entropy > min_len:
        min_len = min_entropy
    returned_bits = os.urandom(math.ceil(min_len / 8))
    return DRBGStatus.SUCCESS, returned_bits


def get_nonce(security_strength):
    """Uses simple call to os.urandom to get security_strength/2 pseudo-random bits."""

    nonce = os.urandom(math.ceil(security_strength/16))
    return nonce
