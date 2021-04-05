from argparse import ArgumentParser
from json import load
from os.path import isfile, abspath, dirname, join
from loguru import logger as log

from pwnpy import Manager, NoConfigurationSuppliedException


def main():
    ap = ArgumentParser()
    ap.add_argument("-c", "-cfg", "--config", "--configuration", help="path to configuration file",
                    default="config.json")
    ap.add_argument("-bd", "--bluetooth-device", help="which bluetooth device should be used", default="hci0")
    ap.add_argument("-wd", "--wifi-device", help="which wifi device should be used", default="wlan0")
    ap.add_argument("-db", "--database", help="name of database file", default="pwnpy.db")
    ap.add_argument("-m", "--module", help="specify modules to use", nargs="*", default=["UI", "GPS"])
    ap.add_argument("-mp", "--module-path", help="where do the modules live",
                    default=join(abspath(join(dirname(__file__))), "modules"))
    ap.add_argument("-l", "--lipo", help="watch for lipo state", action="store_true")
    a = ap.parse_args()

    cfg = None

    if "configuration" in a:
        cf = a.configuration
        if isfile(cf):
            cfg = load(cf)
        else:
            log.error("Configuration file '{}' does not exist.", cf)
            exit(1)
    else:
        a.module_path = abspath(a.module_path)
        cfg = {
            "bt-device": a.bluetooth_device, "w-device": a.wifi_device,
            "modules": a.module, "module-path": a.module_path,
            "lipo": a.lipo, "db": a.database
        }
    try:
        mgr = Manager(cfg)
        try:
            mgr.start()
        except KeyboardInterrupt:
            mgr.stop()
    except NoConfigurationSuppliedException:
        log.error("No configuration parameters supplied.")


if __name__ == '__main__':
    main()
