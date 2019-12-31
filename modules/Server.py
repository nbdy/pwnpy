from sanic import Sanic, response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from os import getcwd
from libs import IThread

# todo authentication


class Server(IThread):
    app = None
    env = None

    @staticmethod
    def parse_parameters(data):
        r = {}
        s = data.split('&')
        for i in s:
            t = i.split('=')
            r[t[0]] = t[1]
        return r

    @staticmethod
    def endswith_append(s, c):
        if not s.endswith(c):
            s += c
        return s

    def _on_run(self):
        tpl_dir = getcwd() + "/" + self.cfg["templates"]
        tpl_dir = self.endswith_append(tpl_dir, "/")
        self.env = Environment(
            loader=FileSystemLoader(tpl_dir),
            autoescape=select_autoescape(["html"])
        )

        self.app = Sanic(self.name)
        static_dir = getcwd() + "/" + self.cfg["static"]
        static_dir = self.endswith_append(static_dir, "/")

        self.app.static('static', static_dir)

        def dashboard():
            p = self.db.current_position()
            if p is None:
                p = self.cfg["defaultPosition"]
            else:
                p = [p[1], p[0]]
            r = {
                "counts": self.db.counts(),
                "currentPosition": p
            }
            print(r)
            return response.html(self.env.get_template("dashboard.html").render(r))

        @self.app.route("/")
        async def root(req):
            return dashboard()

        @self.app.route("/api/columns/<path:path>")
        async def api_column_names(req, path):
            return response.json(self.db.get_columns(path))

        @self.app.route("/api/positions/<path:path>")
        async def api_positions(path):
            return "positions"

        @self.app.route("/api/search", methods=["POST"])
        def api_search(req):
            print(req.query_string)
            return response.json({"yuh": "skrrt"})  # todo

        @self.app.websocket("/api/counts")
        async def api_counts(req, ws):
            lc = None
            while True:
                nc = self.db.counts()
                if nc != lc:
                    await ws.send(nc)
                    lc = nc

    def run(self):
        if not self.do_run:
            return
        self._on_run()
        self.log_info("listening on: '%s:%i'" % (self.cfg["host"], self.cfg["port"]))
        self.app.run(self.cfg["host"],
                     self.cfg["port"],
                     threaded=self.cfg["threaded"],
                     use_reloader=False,
                     debug=True,
                     distributed=True)
