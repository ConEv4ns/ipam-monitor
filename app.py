import csv
from io import StringIO

from flask import Flask, Response, jsonify, render_template, request

from database import (
    current_time,
    get_device,
    get_devices,
    get_scan_history,
    initialise_database,
    save_failed_scan,
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


@app.route("/history")
def history():
    return render_template("history.html")


@app.route("/devices")
def devices():
    return jsonify(get_devices())


@app.route("/api/scans")
def scan_history():
    try:
        limit = int(request.args.get("limit", 50))
    except ValueError:
        return jsonify({"error": "Limit must be a number."}), 400

    return jsonify(get_scan_history(limit))


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
    started_at = current_time()

    try:
        discovered_devices = scan_range(NETWORK_RANGE)

        # Save replies before returning stored records
        save_scan(discovered_devices)

        return jsonify(get_devices())
    except Exception:
        # Record failures without exposing internal errors
        save_failed_scan(started_at)
        return jsonify({"error": "Network scan failed."}), 500


@app.route("/export/devices.csv")
def export_devices():
    devices = get_devices()
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "IP Address",
        "MAC Address",
        "Device Name",
        "Device Type",
        "Trust Status",
        "Online Status",
        "First Seen",
        "Last Seen",
        "Notes"
    ])

    for device in devices:
        writer.writerow([
            device["ip_address"],
            device["mac_address"],
            safe_csv_value(device["name"]),
            safe_csv_value(device["device_type"]),
            device["trust_status"],
            "Online" if device["online"] else "Offline",
            device["first_seen"],
            device["last_seen"],
            safe_csv_value(device["notes"])
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=ipam_devices.csv"
        }
    )


def safe_csv_value(value):
    value = value or ""

    # Prevent spreadsheet formula injection
    if value.startswith(("=", "+", "-", "@")):
        return f"'{value}"

    return value


if __name__ == "__main__":
    app.run(debug=True)