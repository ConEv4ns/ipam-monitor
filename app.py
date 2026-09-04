from flask import Flask, jsonify, render_template

from database import get_devices, initialise_database, save_scan
from scanner import scan_range


app = Flask(__name__)
NETWORK_RANGE = "192.168.1.0/24"

initialise_database()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/devices")
def devices():
    return jsonify(get_devices())


@app.route("/scan")
def scan():
    discovered_devices = scan_range(NETWORK_RANGE)

    # Save the scan before returning stored records
    save_scan(discovered_devices)

    return jsonify(get_devices())


if __name__ == "__main__":
    app.run(debug=True)