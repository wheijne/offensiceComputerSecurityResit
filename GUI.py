import Tkinter as tk
import arp
import dns

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
    
        self.config(bg="#FFFACD")
        
        tk.Label(self, text="ARP spoofing", font=("Helvetica", 14, "bold")).pack()
        label(self, "Spoof a target in one of two modes:")
        label(self, "Continuous: send spoofing packets at an interval")
        label(self, "Silent: only send spoofing packets when an ARP request occurs")
        label(self, "Enter an interval for continuous, leave interval empty for silent")
        self.interface = text_and_input(self, "Interface:")
        self.target_ip = text_and_input(self, "Target IP:")
        self.spoofed_ip = text_and_input(self, "Spoof as IP:")
        self.interval = text_and_input(self, "Interval:")
        start_button = button(self, "Start")
        self.filled_label = label(self, "")
    
    def handle_start(self):
        target_ip = self.target_ip.get()
        spoofed_ip = self.spoofed_ip.get()
        interface = self.interface.get()
        interval = self.interval.get()
        
        if target_ip == '' or spoofed_ip == '' or interface == '':
            self.filled_label.config(text="Please set the inputs for interface and target and spoof IP")
        
        if 

class DNSFrame(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        self.config(bg="#FFE4E1")
        
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

def button(parent, text):
    btn = tk.Button(parent, text=text, command=lambda: parent.handle_start())
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
