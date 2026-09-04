from flask import Flask, jsonify

from scanner import scan_range


app = Flask(__name__)


@app.route("/scan")
def scan():
    # Return discovered devices as JSON
    devices = scan_range("192.168.1.0/24")
    return jsonify(devices)


if __name__ == "__main__":
    app.run(debug=True)
