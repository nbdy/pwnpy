from sys import argv

from libs.Manager import Manager


if __name__ == '__main__':
    if len(argv) == 1:
        print "please supply config file"
        exit()
    m = Manager(argv[1])
    m.start()
    m.join()
