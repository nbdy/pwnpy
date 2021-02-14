from argparse import ArgumentParser
from json import load
from os.path import isfile, abspath, dirname
from loguru import logger as log

import pwnpy
from pwnpy import Manager, NoConfigurationSuppliedException


def main():
    ap = ArgumentParser()
    ap.add_argument("-c", "-cfg", "--config", "--configuration", help="path to configuration file",
                    default="config.json")
    ap.add_argument("-b", "--bluetooth", help="enable bluetooth modules", action="store_true")
    ap.add_argument("-bd", "--bluetooth-device", help="which bluetooth device should be used", default="hci0")
    ap.add_argument("-w", "--wifi", help="enable wifi modules", action="store_true")
    ap.add_argument("-wd", "--wifi-device", help="which wifi device should be used", default="wlan0")
    ap.add_argument("-db", "--database", help="name of database file", default="pwnpy")
    ap.add_argument("-m", "--module", help="specify modules to use", nargs="*", default=["GPS", "WiFi", "BT"])
    ap.add_argument("-mp", "--module-path", help="where do the modules live",
                    default=abspath(dirname(pwnpy.__file__)) + "/modules/")
    ap.add_argument("-l", "--lipo", help="watch for lipo state", action="store_true")
    a = ap.parse_args()

    cf = a.configuration
    cfg = None

    if cf:
        if isfile(cf):
            cfg = load(cf)
        else:
            log.error("Configuration file '{}' does not exist.", cf)
            exit(1)
    else:
        cfg = {
            "bt": a.bluetooth, "bt-device": a.bluetooth_device,
            "w": a.wifi, "w-device": a.wifi_device,
            "db": a.database, "modules": a.module,
            "lipo": a.lipo
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
