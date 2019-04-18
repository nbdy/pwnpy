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
               " gpsd gpsd-clients libcurl4-openssl-dev -y")
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
        system("sudo apt install postgresql -y")
        system("pip3 install psycopg2")
        return True

    @staticmethod
    def read_autostart_file():
        return open(Setup.AUTOSTART_PATH).read()

    @staticmethod
    def already_autostart_installed():
        for l in Setup.read_autostart_file():
            if l.startswith("python pwn.py"):
                return True
        return False

    @staticmethod
    def install_autostart():
        with open(Setup.AUTOSTART_PATH, 'a') as o:
            o.write("/usr/bin/python " + getcwd() + "/pwn.py " + getcwd() + "/config.json")
        return True

    @staticmethod
    def uninstall_autostart():
        _o = Setup.read_autostart_file()
        with open(Setup.AUTOSTART_PATH, 'w') as o:
            for l in _o.split("\n"):
                if "pwn.py" not in l:
                    o.write(l + "\n")


def should_be_root():
    if geteuid() != 0:
        print("need root for apt calls")
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
