from flask import Flask, jsonify, render_template, request

from database import (
    get_device,
    get_devices,
    initialise_database,
    save_scan,
    update_device
)
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


@app.route("/devices/<int:device_id>", methods=["PATCH"])
def edit_device(device_id):
    # Reject missing or invalid JSON
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    try:
        updated = update_device(
            device_id=device_id,
            name=data.get("name", ""),
            device_type=data.get("device_type", ""),
            notes=data.get("notes", ""),
            trust_status=data.get("trust_status", "unknown")
        )
    except (AttributeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

    if not updated:
        return jsonify({"error": "Device not found."}), 404

    return jsonify(get_device(device_id))


@app.route("/scan")
def scan():
    discovered_devices = scan_range(NETWORK_RANGE)

    # Save replies before returning stored records
    save_scan(discovered_devices)

    return jsonify(get_devices())


if __name__ == "__main__":
    app.run(debug=True)