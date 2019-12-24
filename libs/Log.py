from loguru import logger

logger.add("log_{time}.log", rotation="500 MB", compression="bz2", enqueue=True, backtrace=True, diagnose=True)


class Log(object):
    FMT = "[{module}]: {message}"

    @staticmethod
    def d(module, message):
        logger.debug(Log.FMT, module, message)

    @staticmethod
    def i(module, message):
        logger.info(Log.FMT, module, message)

    @staticmethod
    def e(module, message):
        logger.error(Log.FMT, module, message)

