#!/usr/bin/python3
from sys import argv
from os.path import isfile
from libs.Manager import Manager


if __name__ == '__main__':
    m = None
    if len(argv) == 3 and argv[1] in ["-c", "--config", "--configuration"] and isfile(argv[2]):
        m = Manager(argv[1])
    for l in ["config.json", "/etc/pwnpy/config.json"]:
        if isfile(l):
            m = Manager(l)
            break
    if m is not None:
        m.start()
        try:
            m.join()
        except KeyboardInterrupt:
            m.stop()
        except RuntimeError:
            pass
