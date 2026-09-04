from scapy.all import ARP, Ether, srp


def scan_range(ip_range):
    """Scan a local IP range for active devices."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the ARP broadcast and collect replies
    replies = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for _, received in replies:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


if __name__ == "__main__":
    found = scan_range("192.168.1.0/24")  # Change to your network range

    for device in found:
        print(device)