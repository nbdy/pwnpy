import os
os.environ["RAYLIB_BIN_PATH"] = "libs/"

import raylibpy
from . import IThread


class UI(IThread):
    touch_position = None

    def _on_run(self):
        raylibpy.set_config_flags(raylibpy.FLAG_WINDOW_UNDECORATED)
        raylibpy.init_window(self.cfg["width"], self.cfg["height"], "pwnpy")
        raylibpy.set_target_fps(self.cfg["fps"])

    def _draw_button(self, text, x, y, width, height, outline=True, outline_thickness=4, color=raylibpy.GREEN, font_size=16):
        if outline:
            raylibpy.draw_rectangle(x, y, width, height, color)
            raylibpy.draw_rectangle(x + outline_thickness, y + outline_thickness,
                           width - outline_thickness*2, height - outline_thickness*2, raylibpy.BLACK)
            raylibpy.draw_text(text, x + width/2, y + height/2, font_size, color)
        else:
            raylibpy.draw_rectangle(x, y, width, height, color)
            raylibpy.draw_text(text, x + width/2, y + height/2, font_size, color)
        return self.touch_position.x >= x and self.touch_position.y >= y and \
               self.touch_position.x <= (x + width) and self.touch_position.y <= (y + height)

    def _draw_wifi(self):
        pass

    def _draw_bt(self):
        pass

    def _draw_main(self):
        if self._draw_button("wifi", 4, 4, 200, 100):
            self._draw_wifi()
        if self._draw_button("bt", 4, 4, 200, 100):
            self._draw_bt()

    def _work(self):
        while not raylibpy.window_should_close() and self.do_run:
            raylibpy.begin_drawing()
            self.touch_position = raylibpy.get_touch_position(0)
            raylibpy.clear_background(raylibpy.BLACK)
            raylibpy.end_drawing()

    def _on_end(self):
        self._log("ended")
