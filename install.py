#!/usr/bin/python3
from os import system, geteuid, getcwd
from sys import argv


class Setup(object):
    AUTOSTART_PATH = "/etc/rc.local"

    @staticmethod
    def setup_postgresql_database():
        system("sudo service postgresql start")

    @staticmethod
    def dependencies():
        system("sudo apt install libssl-dev libbluetooth-dev python python-dev python-pip tshark reaver aircrack-ng git"
               " gpsd gpsd-clients libcurl4-openssl-dev libpcap-dev libglib2.0-dev -y")
        system("cd /tmp/;"
               "git clone https://github.com/secdev/scapy;"
               "cd scapy;"
               "sudo python setup.py install;"
               "cd /tmp/;"
               "rm -rf scapy")
        system("cd /tmp/;"
               "wget http://www.willhackforsushi.com/code/cowpatty/4.6/cowpatty-4.6.tgz;"
               "tar xf cowpatty-4.6.tgz;"
               "rm cowpatty-4.6.tgz;"
               "cd cowpatty-4.6;"
               "make;"
               "sudo make install;"
               "cd /tmp/;"
               "rm -rf cowpatty-4.6")
        system("cd /tmp/;"
               "git clone https://github.com/JPaulMora/Pyrit;"
               "cd Pyrit;"
               "sudo python setup.py install;"
               "cd /tmp;"
               "rm -rf Pyrit")
        system("cd /tmp/;"
               "git clone https://github.com/ZerBea/hcxtools;"
               "cd hcxtools;"
               "make;"
               "sudo make install;"
               "cd /tmp/;"
               "rm -rf hcxtools")
        system("cd /tmp/;"
               "git clone https://github.com/derv82/wifite2;"
               "cd wifite2;"
               "sudo python setup.py install;"
               "cd /tmp/;"
               "rm -rf wifite2")
        system("sudo pip install -r requirements.txt")
        return True

    @staticmethod
    def read_autostart_file():
        return open(Setup.AUTOSTART_PATH).read()

    @staticmethod
    def already_autostart_installed():
        for line in Setup.read_autostart_file():
            if line.startswith("python pwn.py"):
                return True
        return False

    @staticmethod
    def install_autostart():
        lines = []
        for line in Setup.read_autostart_file().split('\n'):
            if "exit 0" not in line:
                lines.append(line)
        with open(Setup.AUTOSTART_PATH, 'w') as o:
            for line in lines:
                o.write(line + '\n')
            o.write("/usr/bin/python " + getcwd() + "/pwn.py " + getcwd() + "/config.json &\n")
            o.write("exit 0")
        return True

    @staticmethod
    def uninstall_autostart():
        _o = Setup.read_autostart_file()
        with open(Setup.AUTOSTART_PATH, 'w') as o:
            for line in _o.split("\n"):
                if "pwn.py" not in line:
                    o.write(line + "\n")


def should_be_root():
    if geteuid() != 0:
        print("need root; rerun with sudo or as root")
        exit()


def _help():
    print("usage: " + __file__ + " {arguments}")
    print("{arguments}:")
    print("\t-ia\t--install-autostart")
    print("\t-ua\t--uninstall-autostart")
    print("\t-d\t--dependencies")
    print("\t-db\t--database")
    print("\t--help")
    exit()


if __name__ == '__main__':
    i = 0
    if len(argv) == 1:
        _help()
    while i < len(argv):
        if argv[i] in ["-ia", "--install-autostart"]:
            should_be_root()
            Setup.install_autostart()
        elif argv[i] in ["-ua", "--uninstall-autostart"]:
            should_be_root()
            Setup.uninstall_autostart()
        elif argv[i] in ["-d", "--dependencies"]:
            should_be_root()
            Setup.dependencies()
        elif argv[i] in ["-db", "--database"]:
            Setup.setup_postgresql_database()
        elif argv[i] in ["--help"]:
            _help()
        i += 1
