from flask import render_template, Flask, make_response, request

from libs import IThread
from json import dumps

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
        if not self.do_run:
            return
        self.app = Flask(__name__, static_folder='./server-data/static', template_folder='./server-data/templates')

        def dashboard():
            p = self.db.get_newest_position()
            if p is None:
                p = self.cfg["defaultPosition"]
            else:
                p = [p[1], p[0]]
            return render_template("dashboard.html",
                                   counts={
                                       "bluetooth_classic": self.db.get_count("bluetooth_classic"),
                                       "bluetooth_le": self.db.get_count("bluetooth_le"),
                                       "positions": self.db.get_count("positions"),
                                       "wifi": self.db.get_count("wifi")
                                   },
                                   currentPosition=p)

        @self.app.route("/")
        def root():
            return dashboard()

        @self.app.route("/*")
        def catchall():
            return dashboard()

        @self.app.route("/api/columns/<path:path>")
        def api_column_names(path):
            return make_response(dumps(self.db.get_column_names(path)))

        @self.app.route("/api/positions/<path:path>")
        def api_positions(path):
            return make_response(dumps(self.db.get_position(path)))

        @self.app.route("/api/search", methods=["POST"])
        def api_search():
            data = self.parse_parameters(request.get_data())
            return make_response(dumps(self.db.search(data)))

    def _work(self):
        self.app.run(self.cfg["host"], self.cfg["port"], False, threaded=self.cfg["threaded"])
