from flask import render_template, Flask, make_response

from libs import IThread
from json import dumps

# todo authentication


class Server(IThread):
    def _on_run(self):
        if not self.do_run:
            return
        app = Flask(__name__, static_folder='./server-data/static', template_folder='./server-data/templates')

        def dashboard():
            return render_template("dashboard.html",
                                   counts={
                                       "bluetooth_classic": self.db.get_count("bluetooth_classic"),
                                       "bluetooth_le": self.db.get_count("bluetooth_le"),
                                       "positions": self.db.get_count("positions"),
                                       "wifi": self.db.get_count("wifi")
                                   })

        @app.route("/")
        def root():
            return dashboard()

        @app.route("/*")
        def catchall():
            return dashboard()

        @app.route("/api/columns/<path:path>")
        def api_column_names(path):
            return make_response(dumps(self.db.get_column_names(path)))

        app.run(self.cfg["host"], self.cfg["port"], False, threaded=self.cfg["threaded"])
