from sanic import Sanic
from sanic.response import json_dumps as dumps
from jinja2 import Template
from os import getcwd
from libs import IThread

# todo authentication


class Server(IThread):
    app = None

    @staticmethod
    def parse_parameters(data):
        r = {}
        s = data.split('&')
        for i in s:
            t = i.split('=')
            r[t[0]] = t[1]
        return r

    def _on_run(self):
        self.app = Sanic(self.name)
        tpl_dir = getcwd() + "/" + self.cfg["data"]
        if not tpl_dir.endswith("/"):
            tpl_dir += "/"

        def dashboard():
            p = self.db.get()
            if p is None:
                p = self.cfg["defaultPosition"]
            else:
                p = [p[1], p[0]]
            tpl = Template(tpl_dir + "dashboard.html")
            return tpl.render(counts={
                "bluetoothClassic": self.db.count("bluetoothClassic"),
                "bluetoothLE": self.db.count("bluetoothLE"),
                "wifi": self.db.count("wifi"),
                "gps": self.db.count("gps")
            }, currentPosition=p)

        @self.app.route("/")
        async def root(req):
            return dashboard()

        @self.app.route("/*")
        async def catchall(req):
            return dashboard()

        @self.app.route("/api/columns/<path:path>")
        async def api_column_names(req, path):
            print(path)
            return "column names"

        @self.app.route("/api/positions/<path:path>")
        async def api_positions(path):
            return "positions"

        @self.app.route("/api/search", methods=["POST"])
        def api_search(req):
            return "search"

    def run(self):
        if not self.do_run:
            return
        self._on_run()
        self.log_info("listening on: '%s:%i'" % (self.cfg["host"], self.cfg["port"]))
        self.app.run(self.cfg["host"],
                     self.cfg["port"],
                     threaded=self.cfg["threaded"],
                     use_reloader=False,
                     debug=True)  # sanic or flacon
