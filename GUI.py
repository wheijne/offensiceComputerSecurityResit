import Tkinter as tk
from arp import *
from dns import *
from sslstrip import *
from page import *
import threading

class GUI:
    def __init__(self):
        root = tk.Tk()
        root.title("ARP and DNS spoofer and SSL stripper")
        root.geometry("800x400")
        root.resizable(False, False)
        
        self.frames = {}
        
        self.createGUI(root)
        
        root.mainloop()
        
    def createGUI(self, root):
    
        container = tk.Frame(root)
        container.pack(side="left", fill="both", expand=True)
        
        menu = Menu(container, self)
        menu.pack(side="top", fill="x")
                
        page_container = tk.Frame(container)
        page_container.pack(side="top", fill="both", expand=True)
        page_container.grid_rowconfigure(0, weight=1)
        page_container.grid_columnconfigure(0, weight=1)
        
        
        
        front = FrontPage(page_container)
        self.frames["Front"] = front
        front.grid(row=0, column=0, sticky="nsew")
    
        arp = ARPFrame(page_container)
        self.frames["ARP"] = arp
        arp.grid(row=0, column=0, sticky="nsew")
        
        dns = DNSFrame(page_container)
        self.frames["DNS"] = dns
        dns.grid(row=0, column=0, sticky="nsew")
        
        ssl = SSLFrame(page_container)
        self.frames["SSL"] = ssl
        ssl.grid(row=0, column=0, sticky="nsew")

        self.showFrame("Front")
        
    def showFrame(self, frame):
        frame = self.frames[frame]
        frame.tkraise()
        
class Menu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        
        to_arp = tk.Button(self, text="ARP poisoning", command=lambda: controller.showFrame("ARP"))
        to_arp.pack(side="left", expand=True)
        
        to_dns = tk.Button(self, text="DNS poisoning", command=lambda: controller.showFrame("DNS"))
        to_dns.pack(side="left", expand=True)
        
        to_ssl = tk.Button(self, text="SSL stripping", command=lambda: controller.showFrame("SSL"))
        to_ssl.pack(side="left", expand=True)
        
class FrontPage(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        
        tk.Label(self, text="Welcome to the spoofing tool").pack(expand=True)
        tk.Label(self, text="Click on any of the buttons above to go to one of the tools").pack(expand=True)
        tk.Label(self, text="Created by Wout Heijne, 1712675, for course 2IC80").pack(expand=True)
        

class ARPFrame(page):
    def __init__(self, parent):
        page.__init__(self, parent, "ARP spoofing", arp())
        self.start_text = "Starting ARP spoof on %s as %s every %d seconds on interface %s"
    
    def add_info_labels(self):
        label(self, "Spoof a target in one of two modes:")
        label(self, "Continuous: send spoofing packets at an interval")
        label(self, "Silent: only send spoofing packets when an ARP request occurs")
        label(self, "Enter an interval for continuous, leave interval empty for silent")
        
    def add_entries(self):
        page.add_entries(self)
        self.spoofed_ip = text_and_input(self, "Spoof as IP:")
        self.spoofed_ip.config(validate="key", validatecommand=self.vcmd_ip)
        self.interval = text_and_input(self, "Interval:")
        self.interval.config(validate="key", validatecommand=self.vcmd_number)
    
    def get_and_validate_inputs(self):
        target_ip = self.target_ip.get()
        spoofed_ip = self.spoofed_ip.get()
        interface = self.interface.get()
        interval = self.interval.get()
        if interval == '':
            interval = "0"
                
        if not len(target_ip.split('.')) == 4 or target_ip.split('.')[3] == '' \
           or not len(spoofed_ip.split('.')) == 4 or target_ip.split('.')[3] == '' \
           or interface == '':
            return
        
        return (target_ip, spoofed_ip, int(interval), interface)

class DNSFrame(page):
    def __init__(self, parent):
        page.__init__(self, parent, "DNS spoofing", dns())
        self.start_text = "Started DNS spoof on interface %s and %s, sending %s to %s"
        
    def add_info_labels(self):
        label(self, "Spoof the domain to the spoofed IP, for the target IP")
        
    def add_entries(self):
        page.add_entries(self)
        self.spoofed_ip = text_and_input(self, "Spoofed IP:")
        self.spoofed_ip.config(validate="key", validatecommand=self.vcmd_ip)
        self.domain = text_and_input(self, "Domain:")
        
    def get_and_validate_inputs(self):
        target_ip = self.target_ip.get()
        spoofed_ip = self.spoofed_ip.get()
        interface = self.interface.get()
        domain = self.domain.get()
        
        if not len(target_ip.split('.')) == 4 or target_ip.split('.')[3] == '' \
           or not len(spoofed_ip.split('.')) == 4 or target_ip.split('.')[3] == '' \
           or interface == '' or domain == '':
            return
        
        return (interface, domain, target_ip, spoofed_ip)
 
 
class SSLFrame(page):
    def __init__(self, parent):
        page.__init__(self, parent, "SSL stripping", sslstrip())
        self.start_text = "Started SSL stripping for %s on interface %s"
        
    def add_info_labels(self):
        label(self, "Start an SSL stripping attack at the victim")
        label(self, "Requests are saved in \"%s/request\"" % os.getcwd())
        label(self, "Responses are saved in \"%s/response\"" % os.getcwd())
        
    def add_entries(self):
        page.add_entries(self)
        
    def get_and_validate_inputs(self):
        target_ip = self.target_ip.get()
        interface = self.interface.get()
        
        print("target_ip='%s', interface='%s'" % (target_ip, interface))
        
        if not len(target_ip.split('.')) == 4 or target_ip.split('.')[3] == '' or interface == '':
            return
        
        return (target_ip, interface)


