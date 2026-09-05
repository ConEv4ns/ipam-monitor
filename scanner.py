from scapy.all import ARP, Ether, srp


def scan_range(ip_range, timeout=3):
    """Scan a local IP range for active devices."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the request and collect replies
    replies = srp(
        packet,
        timeout=timeout,
        verbose=0
    )[0]

    devices = []

    for _, received in replies:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


if __name__ == "__main__":
    found_devices = scan_range(
        "192.168.1.0/24",
        timeout=3
    )

    for device in found_devices:
        print(device)