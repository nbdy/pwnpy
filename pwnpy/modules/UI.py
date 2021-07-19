import time
from os.path import join, abspath, dirname, isfile
import spidev
from loguru import logger as log

from PIL import Image, ImageDraw, ImageFont

from pwnpy import Module, Manager, is_rpi
from pwnpy.libs import ExitCode, ModuleType

if not is_rpi():
    log.error("The UI module only works with raspberry pies.")
    exit()
import RPi.GPIO


class Display(object):
    RST_PIN = 17
    DC_PIN = 25
    CS_PIN = 8
    BUSY_PIN = 24

    width = 122
    height = 250

    def __init__(self):
        self.GPIO = RPi.GPIO
        self.SPI = spidev.SpiDev(0, 0)

    def digital_write(self, pin, value):
        self.GPIO.output(pin, value)

    def digital_read(self, pin):
        return self.GPIO.input(pin)

    @staticmethod
    def delay_ms(delay):
        time.sleep(delay / 1000.0)

    def spi_writebyte(self, data):
        self.SPI.writebytes(data)

    def spi_writebyte2(self, data):
        self.SPI.writebytes2(data)

    def module_init(self):
        self.GPIO.setmode(self.GPIO.BCM)
        self.GPIO.setwarnings(False)
        self.GPIO.setup(self.RST_PIN, self.GPIO.OUT)
        self.GPIO.setup(self.DC_PIN, self.GPIO.OUT)
        self.GPIO.setup(self.CS_PIN, self.GPIO.OUT)
        self.GPIO.setup(self.BUSY_PIN, self.GPIO.IN)
        self.SPI.max_speed_hz = 4000000
        self.SPI.mode = 0b00
        return 0

    def module_exit(self):
        self.SPI.close()
        self.GPIO.output(self.RST_PIN, 0)
        self.GPIO.output(self.DC_PIN, 0)

        self.GPIO.cleanup()

    FULL_UPDATE = 0
    PART_UPDATE = 1
    lut_full_update = [
        0x80, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00,  # LUT0: BB:     VS 0 ~7
        0x10, 0x60, 0x20, 0x00, 0x00, 0x00, 0x00,  # LUT1: BW:     VS 0 ~7
        0x80, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00,  # LUT2: WB:     VS 0 ~7
        0x10, 0x60, 0x20, 0x00, 0x00, 0x00, 0x00,  # LUT3: WW:     VS 0 ~7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # LUT4: VCOM:   VS 0 ~7

        0x03, 0x03, 0x00, 0x00, 0x02,  # TP0 A~D RP0
        0x09, 0x09, 0x00, 0x00, 0x02,  # TP1 A~D RP1
        0x03, 0x03, 0x00, 0x00, 0x02,  # TP2 A~D RP2
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP3 A~D RP3
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP4 A~D RP4
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP5 A~D RP5
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP6 A~D RP6

        0x15, 0x41, 0xA8, 0x32, 0x30, 0x0A,
    ]

    lut_partial_update = [  # 20 bytes
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # LUT0: BB:     VS 0 ~7
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # LUT1: BW:     VS 0 ~7
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # LUT2: WB:     VS 0 ~7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # LUT3: WW:     VS 0 ~7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # LUT4: VCOM:   VS 0 ~7

        0x0A, 0x00, 0x00, 0x00, 0x00,  # TP0 A~D RP0
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP1 A~D RP1
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP2 A~D RP2
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP3 A~D RP3
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP4 A~D RP4
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP5 A~D RP5
        0x00, 0x00, 0x00, 0x00, 0x00,  # TP6 A~D RP6

        0x15, 0x41, 0xA8, 0x32, 0x30, 0x0A,
    ]

    # Hardware reset
    def reset(self):
        self.digital_write(self.RST_PIN, 1)
        self.delay_ms(200)
        self.digital_write(self.RST_PIN, 0)
        self.delay_ms(5)
        self.digital_write(self.RST_PIN, 1)
        self.delay_ms(200)

    def send_command(self, command):
        self.digital_write(self.DC_PIN, 0)
        self.digital_write(self.CS_PIN, 0)
        self.spi_writebyte([command])
        self.digital_write(self.CS_PIN, 1)

    def send_data(self, data):
        self.digital_write(self.DC_PIN, 1)
        self.digital_write(self.CS_PIN, 0)
        self.spi_writebyte([data])
        self.digital_write(self.CS_PIN, 1)

    def read_busy(self):
        while self.digital_read(self.BUSY_PIN) == 1:  # 0: idle, 1: busy
            self.delay_ms(100)

    def turn_on_display(self):
        self.send_command(0x22)
        self.send_data(0xC7)
        self.send_command(0x20)
        self.read_busy()

    def turn_on_display_part(self):
        self.send_command(0x22)
        self.send_data(0x0c)
        self.send_command(0x20)
        self.read_busy()

    def init(self, update):
        if self.module_init() != 0:
            return -1
        # EPD hardware init start
        self.reset()
        if update == self.FULL_UPDATE:
            self.read_busy()
            self.send_command(0x12)  # soft reset
            self.read_busy()

            self.send_command(0x74)  # set analog block control
            self.send_data(0x54)
            self.send_command(0x7E)  # set digital block control
            self.send_data(0x3B)

            self.send_command(0x01)  # Driver output control
            self.send_data(0xF9)
            self.send_data(0x00)
            self.send_data(0x00)

            self.send_command(0x11)  # data entry mode
            self.send_data(0x01)

            self.send_command(0x44)  # set Ram-X address start/end position
            self.send_data(0x00)
            self.send_data(0x0F)  # 0x0C-->(15+1)*8=128

            self.send_command(0x45)  # set Ram-Y address start/end position
            self.send_data(0xF9)  # 0xF9-->(249+1)=250
            self.send_data(0x00)
            self.send_data(0x00)
            self.send_data(0x00)

            self.send_command(0x3C)  # BorderWavefrom
            self.send_data(0x03)

            self.send_command(0x2C)  # VCOM Voltage
            self.send_data(0x55)  #

            self.send_command(0x03)
            self.send_data(self.lut_full_update[70])

            self.send_command(0x04)  #
            self.send_data(self.lut_full_update[71])
            self.send_data(self.lut_full_update[72])
            self.send_data(self.lut_full_update[73])

            self.send_command(0x3A)  # Dummy Line
            self.send_data(self.lut_full_update[74])
            self.send_command(0x3B)  # Gate time
            self.send_data(self.lut_full_update[75])

            self.send_command(0x32)
            for count in range(70):
                self.send_data(self.lut_full_update[count])

            self.send_command(0x4E)  # set RAM x address count to 0
            self.send_data(0x00)
            self.send_command(0x4F)  # set RAM y address count to 0X127
            self.send_data(0xF9)
            self.send_data(0x00)
            self.read_busy()
        else:
            self.send_command(0x2C)  # VCOM Voltage
            self.send_data(0x26)

            self.read_busy()

            self.send_command(0x32)
            for count in range(70):
                self.send_data(self.lut_partial_update[count])

            self.send_command(0x37)
            self.send_data(0x00)
            self.send_data(0x00)
            self.send_data(0x00)
            self.send_data(0x00)
            self.send_data(0x40)
            self.send_data(0x00)
            self.send_data(0x00)

            self.send_command(0x22)
            self.send_data(0xC0)
            self.send_command(0x20)
            self.read_busy()

            self.send_command(0x3C)  # BorderWavefrom
            self.send_data(0x01)
        return 0

    def get_buffer(self, image):
        line_width = self.get_line_width()

        buf = [0xFF] * (line_width * self.height)
        image_monocolor = image.convert('1')
        imwidth, imheight = image_monocolor.size
        pixels = image_monocolor.load()

        if imwidth == self.width and imheight == self.height:
            for y in range(imheight):
                for x in range(imwidth):
                    if pixels[x, y] == 0:
                        x = imwidth - x
                        buf[int(x / 8) + y * line_width] &= ~(0x80 >> (x % 8))
        elif imwidth == self.height and imheight == self.width:
            for y in range(imheight):
                for x in range(imwidth):
                    newx = y
                    newy = self.height - x - 1
                    if pixels[x, y] == 0:
                        newy = imwidth - newy - 1
                        buf[int(newx / 8) + newy * line_width] &= ~(0x80 >> (y % 8))
        return buf

    def get_line_width(self):
        if self.width % 8 == 0:
            return int(self.width / 8)
        else:
            return int(self.width / 8) + 1

    def display(self, image):
        line_width = self.get_line_width()
        self.send_command(0x24)
        for j in range(0, self.height):
            for i in range(0, line_width):
                self.send_data(image[i + j * line_width])
        self.turn_on_display()

    def send_image(self, image):
        line_width = self.get_line_width()
        self.send_command(0x24)
        for j in range(0, self.height):
            for i in range(0, line_width):
                self.send_data(image[i + j * line_width])

        self.send_command(0x26)
        for j in range(0, self.height):
            for i in range(0, line_width):
                self.send_data(~image[i + j * line_width])

    def display_partial(self, image):
        self.send_image(image)
        self.turn_on_display_part()

    def display_part_base_image(self, image):
        self.send_image(image)
        self.turn_on_display()

    def clear(self, color=None):
        line_width = self.get_line_width()
        self.send_command(0x24)
        for j in range(0, self.height):
            for i in range(0, line_width):
                self.send_data(color)
        self.turn_on_display()

    def sleep(self):
        self.send_command(0x10)  # enter deep sleep
        self.send_data(0x03)
        self.delay_ms(100)

    def dev_exit(self):
        self.module_exit()


class UI(Module):
    c = None
    shared_data = None
    type = ModuleType.UI

    font = None

    ignored = {
        "GPS": ["tme", "_uuid"],
    }

    def __init__(self, mgr: Manager, font_file=join(abspath(dirname(__file__)), 'Font.ttc'), **kwargs):
        Module.__init__(self, "UI", mgr)
        self.font_size = kwargs.get("font_size") or 10
        self.refresh_rate = kwargs.get("refresh_rate") or 10
        self.font_file = font_file

        if "censor" in kwargs.keys():
            if kwargs["censor"]:
                self.ignored["GPS"] += ["lng", "lat"]

    def on_start(self):
        if isfile(self.font_file):
            self.font = ImageFont.truetype(self.font_file, self.font_size)
            log.debug("Loaded font file '{}'.".format(self.font_file))
            self.c = Display()
            self.c.init(0)
            self.c.clear(0xFF)
            time.sleep(1)
        else:
            self.error(ExitCode.FATAL, "I could not load the font file '{}'".format(self.font_file))

    def on_stop(self):
        self.c.clear(0xFF)

    def draw_line(self, ib, coordinates, text: str):
        ib.text(coordinates, text, 0, self.font)

    def work(self):
        data = self.mgr.shared_data
        bi = Image.new('1', (self.c.height, self.c.width), 255)
        db = ImageDraw.Draw(bi)
        x = 2
        y = 2
        kl = len(data.keys())
        i = 0
        for key in data.keys():
            i += 1
            ll = 0
            self.draw_line(db, (x, y), "{}: ".format(key))
            y += 12

            sks = []
            for sk in data[key]["data"].keys():
                if key not in self.ignored.keys() or sk not in self.ignored[key]:
                    sks.append(sk)

            if "exit_reason" in sks:
                self.draw_line(db, (x, y), "err:")
                self.draw_line(db, (x, y + 12), "{}".format(data[key]["exit_reason"]))
            else:
                for sk in sks:
                    line = "{}: {}".format(sk, data[key]["data"][sk])
                    _ll = db.textlength(line, self.font)
                    if _ll > ll:
                        ll = _ll
                    self.draw_line(db, (x, y), line)
                    y += 12
            x += ll
            if i < kl:
                for _ in range(0, 100, 12):
                    self.draw_line(db, (x, _), "|")
            x += 8
            y = 2

        self.c.display(self.c.get_buffer(bi))
        self.sleep(self.refresh_rate)
