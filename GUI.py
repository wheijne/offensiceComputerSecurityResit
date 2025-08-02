import Tkinter as tk
from arp import *
from dns import *
import threading

class GUI:
    def __init__(self):
        root = tk.Tk()
        root.title("ARP and DNS spoofer and SSL stripper")
        root.geometry("600x400")
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
        
        
        
class ARPFrame(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        self.thread = None
        
        tk.Label(self, text="ARP spoofing", font=("Helvetica", 14, "bold")).pack()
        label(self, "Spoof a target in one of two modes:")
        label(self, "Continuous: send spoofing packets at an interval")
        label(self, "Silent: only send spoofing packets when an ARP request occurs")
        label(self, "Enter an interval for continuous, leave interval empty for silent")
        self.interface = text_and_input(self, "Interface:")
        vcmd_ip = (self.register(validate_ip), '%P')
        self.target_ip = text_and_input(self, "Target IP:")
        self.target_ip.config(validate="key", validatecommand=vcmd_ip)
        self.spoofed_ip = text_and_input(self, "Spoof as IP:")
        self.spoofed_ip.config(validate="key", validatecommand=vcmd_ip)
        self.interval = text_and_input(self, "Interval:")
        vcmd_number = (self.register(validate_number), '%P')
        self.interval.config(validate="key", validatecommand=vcmd_number)
        self.start_button = button(self, "Start", self.handle_start)
        self.stop_button = button(self, "Stop", self.handle_stop)
        self.stop_button.config(state="disabled")
        self.info_label = label(self, "")
    
    def handle_start(self):
        target_ip = self.target_ip.get()
        spoofed_ip = self.spoofed_ip.get()
        interface = self.interface.get()
        interval = self.interval.get()
        
        if target_ip == '' or spoofed_ip == '' or interface == '':
            self.info_label.config(text="Please set the inputs for interface and target and spoof IP")
            return
        
        if self.thread and self.thread.is_alive():
            self.info_label.config(text="An ARP spoof is already running, please stop it first")
            
        self.start_button.config(state="disabled")
        self.arp1 = arp()
        
        if not interval == "":
            self.info_label.config(text="ARP spoof of %s to %s every %s seconds started" % (spoofed_ip, target_ip, interval))
            self.thread = threading.Thread(target=self.arp1.continuous_arp_spoof, args=(str(target_ip), str(spoofed_ip), float(interval), str(interface)))
            self.thread.start()
        else:
            self.info_label.config(text="Silent ARP spoof of %s to %s started" % (spoofed_ip, target_ip))
            self.thread = threading.Thread(target=self.arp1.silent_arp_spoof, args=(target_ip, spoofed_ip, interface))
            self.thread.start()
        
        self.stop_button.config(state="normal")
            
    def handle_stop(self):
        self.stop_button.config(state="disabled")
        self.arp1.stop_spoof()
        self.thread.join()
        self.info_label.config(text="ARP spoof stopped")
        self.start_button.config(state="normal")
       

class DNSFrame(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        self.config(bg="#FFE4E1")
        
        vcmd = (self.register(validate_ip), '%P')
        
        tk.Label(self, text="ARP spoofing", font=("Helvetica", 14, "bold")).pack()
        label(self, "Spoof the domain to the spoofed IP, for the target IP")
        self.interface = text_and_input(self, "Interface:")
        self.target_ip = text_and_input(self, "Target IP:")
        self.target_ip.config(validate="key", validatecommand=vcmd)
        self.spoofed_ip = text_and_input(self, "Spoofed IP:")
        self.spoofed_ip.config(validate="key", validatecommand=vcmd)
        self.domain = text_and_input(self, "Domain:")
        self.start_button = button(self, "Start", self.handle_start)
        self.stop_button = button(self, "Stop", self.handle_stop)
        self.stop_button.config(state="disabled")
        self.info_label = label(self, "")
        
    def handle_start(self):
        target_ip = self.target_ip.get()
        spoofed_ip = self.spoofed_ip.get()
        interface = self.interface.get()
        domain = self.domain.get()
        
        if not len(target_ip.split('.')) == 4 or target_ip.split('.')[3] == '' \
           or not len(spoofed_ip.split('.')) == 4 or target_ip.split('.')[3] == '' \
           or interface == '' or domain == '':
            self.info_label.config(text="Please check you inputs")
            
        self.start_button.config(state="disabled")
        
        self.dns1 = dns()
        self.info_label.config(text="Started DNS spoof pretending %s is at %s for %s" % (domain, spoofed_ip, target_ip))
        self.thread = threading.Thread(target=self.dns1.spoof, args=(interface, domain, target_ip, spoofed_ip))
        self.thread.start()
        self.stop_button.config(state="normal")
        
    
    def handle_stop(self):
        self.stop_button.config(state="disabled")
        self.dns1.stop_spoof()
        self.thread.join()
        self.start_button.config(state="disabled")
        self.info_label.config(text="DNS spoof stopped")
        
class SSLFrame(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        self.config(bg="#E0FFFF")
        
def label(parent, text):
    lbl = tk.Label(parent, text=text)
    lbl.pack(fill="x")    
    return lbl
    
def text_and_input(parent, text):
    container = tk.Frame(parent)
    tk.Label(container, text=text, width=20).pack(side="left")
    entry = tk.Entry(container, width=20)
    entry.pack(side="left")
    container.pack()
    return entry

def button(parent, text, handler):
    btn = tk.Button(parent, text=text, command=handler)
    btn.pack()
    return btn
    
def validate_number(text):
    if text == "":
        return True
    decimal_count = text.count(".")
    if decimal_count > 1:
        return False
    if text.replace('.', '', 1).isdigit():
        return True
    return False
    
def validate_ip(text):
    if text == "":
        return True
    splitted = text.split(".")
    if len(splitted) > 4:
        return False
    for i, t in enumerate(splitted):
        if t == '' and i == len(splitted) - 1:
            break
        if not t.isdigit():
            return False
        n = int(t)
        if n > 255 or n < 0:
            return False
    return True
