#!/usr/bin/python3
from sys import argv
from os.path import isfile
from libs.Manager import Manager


if __name__ == '__main__':
    m = None
    if len(argv) == 3 and argv[1] in ["-c", "--config", "--configuration"] and isfile(argv[2]):
        m = Manager(argv[1])
    for config in ["config.json", "/etc/pwnpy/config.json"]:
        if isfile(config):
            m = Manager(config)
            break
    if m is not None:
        m.start()
        try:
            m.join()
        except KeyboardInterrupt:
            m.stop()
        except RuntimeError:
            pass
