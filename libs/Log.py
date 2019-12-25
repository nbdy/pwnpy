from loguru import logger
from os import makedirs
from os.path import isdir


class Log(object):
    cfg = None
    format = None

    def __init__(self, cfg, fmt="[{__module__}]: {__message__}"):
        self.cfg = cfg
        self.format = fmt
        path = self.cfg["path"]
        if not path.endswith("/"):
            path += "/"
        if not isdir(path):
            makedirs(path)
        logger.add(path + "log_{time}.log",
                   rotation="500 MB",
                   compression="bz2",
                   enqueue=True,
                   backtrace=True,
                   diagnose=True)

    def d(self, module, message):
        logger.debug(self.format, __module__=module, __message__=message)

    def i(self, module, message):
        logger.info(self.format, __module__=module, __message__=message)

    def e(self, module, message):
        logger.error(self.format, __module__=module, __message__=message)
