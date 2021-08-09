from os.path import join, abspath
from os import getcwd

from pwnpy.libs import Module, log

from flask import Flask, render_template, send_from_directory


class WebUI(Module):
    def __init__(self, mgr, **kwargs):
        Module.__init__(self, "WebUI", mgr)

        kk = kwargs.keys()
        if "host" in kk:
            self.host = kwargs.get("host")
        else:
            self.host = "0.0.0.0"

        if "port" in kk:
            self.port = kwargs.get("port")
        else:
            self.port = 41337

        if "debug" in kk:
            self.debug = kwargs.get("debug")
        else:
            self.debug = False

        app = Flask(__name__)
        app.template_folder = join(abspath(getcwd()), "pwnpy", "templates")
        log.debug(app.template_folder)

        @app.route("/")
        def ui_root():
            return render_template("dashboard.html")

        @app.route("/css/<path:path>")
        def static_css(path):
            return send_from_directory("static/css", path)

        self.app = app

    def run(self) -> None:
        self.app.run(self.host, self.port, self.debug)
