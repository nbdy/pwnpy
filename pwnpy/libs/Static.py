from os import geteuid
from os.path import isfile


class ExitCode:
    NON_FATAL = 0
    FATAL = 1


def is_root():
    return geteuid() == 0


def is_rpi():
    return isfile("/sys/firmware/devicetree/base/model")
