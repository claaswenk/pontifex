import os
import logging

from flask import Flask

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

@app.route("/")
def index():
    return "DB-API is online!"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 13110))
    log.info("Starting Pontifex backend on HTTPS port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
