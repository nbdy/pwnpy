# https://github.com/soonuse/epd-library-python/tree/master/2.13inch_e-paper_b/raspberrypi

from libs import IThread
from .epaper import epd2in13b
from PIL import ImageFont
from time import sleep

COLORED = 1
UNCOLORED = 0


class EPaper(IThread):
    fbb = None
    fbr = None
    dp = None
    font = None

    def _on_run(self):
        self.font = ImageFont.truetype(self.cfg["font"], self.cfg["fontSize"])
        self.dp = epd2in13b.EPD()
        self.dp.init()
        self.fbb = [0xFF] * (self.dp.width * self.dp.height / 8)
        self.fbr = [0xFF] * (self.dp.width * self.dp.height / 8)

    def header(self):
        self.dp.draw_string_at(self.fbb, 4, 30, self.cfg["header"], self.font, COLORED)

    def _work(self):
        self.header()

        self.dp.display_frame(self.fbb, self.fbr)
        sleep(self.cfg["sleepTime"])

