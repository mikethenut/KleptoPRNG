from enum import Enum


class DRBGStatus(Enum):
    SUCCESS = 0
    ERROR_FLAG = 1
    CATASTROPHIC_ERROR_FLAG = 2
    RESEED_REQUIRED = 3


def DRBG_status_to_string(DRBG_status):
    if DRBG_status == DRBGStatus.SUCCESS:
        return "SUCCESS"
    elif DRBG_status == DRBGStatus.ERROR_FLAG:
        return "ERROR FLAG"
    elif DRBG_status == DRBGStatus.CATASTROPHIC_ERROR_FLAG:
        return "CATASTROPHIC ERROR FLAG"
    elif DRBG_status == DRBGStatus.RESEED_REQUIRED:
        return "RESEED REQUIRED"
    else:
        return "STATUS UNKNOWN"
