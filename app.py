from flask import Flask, jsonify, render_template

from scanner import scan_range


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    # Return discovered devices as JSON
    devices = scan_range("192.168.1.0/24")
    return jsonify(devices)


if __name__ == "__main__":
    app.run(debug=True)