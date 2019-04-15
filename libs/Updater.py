from os import execv, system
from sys import executable, argv


class Updater(object):
    url = "https://github.com/trig0n/pwnpi"

    @staticmethod
    def update():
        system("git pull")
        execv(executable, ['python'] + argv)
        exit()
