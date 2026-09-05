import csv
from io import StringIO
from ipaddress import ip_network

from flask import Flask, Response, jsonify, render_template, request

from database import (
    current_time,
    get_device,
    get_devices,
    get_scan_history,
    get_settings,
    initialise_database,
    save_failed_scan,
    save_scan,
    update_device,
    update_settings
)
from scanner import scan_range


app = Flask(__name__)

initialise_database()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/history")
def history():
    return render_template("history.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


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


@app.route("/api/settings")
def settings():
    return jsonify(get_settings())


@app.route("/api/settings", methods=["PATCH"])
def save_settings():
    # Reject missing or invalid JSON
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    network_range = str(data.get("network_range", "")).strip()

    try:
        scan_timeout = int(data.get("scan_timeout", 3))
        network = ip_network(network_range, strict=False)
    except (TypeError, ValueError):
        return jsonify({
            "error": "Enter a valid IPv4 network range and timeout."
        }), 400

    # Limit scanning to private IPv4 networks
    if network.version != 4 or not network.is_private:
        return jsonify({
            "error": "The network range must be a private IPv4 network."
        }), 400

    if network.prefixlen < 24:
        return jsonify({
            "error": "Network ranges larger than /24 are not allowed."
        }), 400

    if not 1 <= scan_timeout <= 10:
        return jsonify({
            "error": "Scan timeout must be between 1 and 10 seconds."
        }), 400

    saved_settings = update_settings(
        str(network),
        scan_timeout
    )

    return jsonify(saved_settings)


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
    saved_settings = get_settings()

    try:
        discovered_devices = scan_range(
            saved_settings["network_range"],
            timeout=saved_settings["scan_timeout"]
        )

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