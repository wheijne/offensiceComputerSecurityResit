import Tkinter as tk
import threading

class page(tk.Frame):
    
    def __init__(self, parent, title, attack_module):
        tk.Frame.__init__(self, parent)
        
        self.parent = parent
        self.attack_module = attack_module
        self.start_text = ""
        
        self.thread = None
        
        self.vcmd_ip = (self.register(validate_ip), '%P')
        self.vcmd_number = (self.register(validate_number), '%P')
        
        tk.Label(self, text=title, font=("Helvetica", 14, "bold")).pack()
        
        self.add_info_labels()
        self.add_entries()
        
        self.start_button = button(self, "Start", self.handle_start)
        self.stop_button = button(self, "Stop", self.handle_stop)
        self.stop_button.config(state="disabled")
        self.info_label = label(self, "")
    
    def add_info_labels(self):
        pass
    
    def add_entries(self):
        self.interface = text_and_input(self, "Interface:")
        self.target_ip = text_and_input(self, "Target IP:")
        self.target_ip.config(validate="key", validatecommand=self.vcmd_ip)
    
    def handle_start(self):
        args = self.get_and_validate_inputs()
        if not args:
            self.info_label.config(text="Please check you inputs")
            return
        self.start_button.config(state="disabled")
        self.thread = threading.Thread(target=self.attack_module.start, args=args)
        self.thread.start()
        self.info_label.config(text=self.start_text % args)
        self.stop_button.config(state="normal")
        
    def get_and_validate_inputs(self):
        pass
        
    def handle_stop(self):
        self.stop_button.config(state="disabled")
        self.attack_module.stop()
        self.thread.join()
        self.info_label.config(text="Attack stopped")
        self.start_button.config(state="normal")
        

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
