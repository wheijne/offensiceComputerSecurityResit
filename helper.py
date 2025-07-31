from scapy.all import *

def get_mac_address(ip, iface):
    """
    Get the mac address of some IP
    """
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        resp, unans = srp(packet, timeout=2, verbose=False, iface=iface)
        if resp:
            return resp[0][1].hwsrc
    except Exception as e:
        print("Error getting MAC address for %s: %s" % (ip, e))
    return None
    
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
