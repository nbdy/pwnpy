from flask import Flask, request
from jinja2 import Environment, FileSystemLoader, select_autoescape
from os import getcwd
from libs import IThread

# todo authentication


class Server(IThread):
    app = None
    env = None

    dir_tpl = None
    dir_static = None

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
        self.dir_tpl = getcwd() + "/" + self.cfg["templates"]
        self.dir_tpl = self.endswith_append(self.dir_tpl, "/")

        self.env = Environment(
            loader=FileSystemLoader(self.dir_tpl),
            autoescape=select_autoescape(["html"])
        )

        self.dir_static = getcwd() + "/" + self.cfg["static"]
        self.dir_static = self.endswith_append(self.dir_static, "/")

        self.app = Flask(self.name)

        @self.app.route("/")
        def root():
            return self.dashboard()

        @self.app.route("/dashboard")
        def dashboard():
            return self.dashboard()

    def dashboard(self):
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
        return self.env.get_template("dashboard.html").render(r)

    '''
    def api_column_names(self, req, path):
        return "skrt"

    async def api_positions(self, path):
        return "positions"

    def api_search(self, req):
        print(req.query_string)
        return "yuh"

    async def api_counts(self, req, ws):
        lc = None
        while True:
            nc = self.db.counts()
            if nc != lc:
                await ws.send(nc)
                lc = nc
    '''

    # https://stackoverflow.com/questions/15562446/how-to-stop-flask-application-without-using-ctrl-c
    @staticmethod
    def shutdown_server():
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('no werkzeug server running')
        func()

    def _on_stop(self):
        self.shutdown_server()
        self.do_run = False

    def run(self):
        if not self.do_run:
            return
        self._on_run()
        self.app.run(
            self.cfg["host"],
            self.cfg["port"],
            threaded=self.cfg["threaded"]
        )
